"""信封加密服务：组合密钥管理与加密原语，对外提供加解密、轮换、退役与批量重加密。

并发约定：encrypt / retire / reencrypt 全程持有 KeyRing 的同一把锁，
与 rotate/deactivate 互斥，因此：
- 不会出现"用正在停用的版本加密新数据"，也不会留下只写一半的状态；
- 批量重加密与退役不会互相穿插：重加密整批持锁提交，退役在锁内判定
  "版本仍在使用中"，二者必然串行，不存在跑到一半源版本被退役的情况。
"""

from __future__ import annotations

from . import crypto
from .auth import Caller, Permission
from .errors import ErrorCode, KeyManagementError
from .keyring import KeyRing
from .models import Envelope, KeyState
from .records import CiphertextStore


def _aad(version: int) -> bytes:
    """把密钥版本绑定进完整性校验的附加认证数据。"""
    return f"envelope:v{version}".encode()


class EnvelopeCryptoService:
    def __init__(
        self, keyring: KeyRing | None = None, store: CiphertextStore | None = None
    ) -> None:
        self._keyring = keyring or KeyRing()
        self._store = store or CiphertextStore()

    @property
    def keyring(self) -> KeyRing:
        return self._keyring

    @property
    def store(self) -> CiphertextStore:
        return self._store

    def encrypt(self, caller: Caller, plaintext: bytes) -> Envelope:
        """用当前生效版本加密；加密期间版本不得被停用。
        产出的信封登记进密文台账（record_id 回填），并累计版本使用统计。"""
        caller.require(Permission.ENCRYPT)
        with self._keyring.lock:
            key = self._keyring.active_version()
            if key.state is not KeyState.ACTIVE:
                raise KeyManagementError(
                    ErrorCode.VERSION_NOT_ACTIVE,
                    f"版本 {key.version} 状态为 {key.state.value}，不能用于加密",
                )
            envelope = self._seal(key, plaintext)
            envelope.record_id = self._store.put(envelope)
            self._keyring.record_encrypt(key.version)
            return envelope

    def decrypt(
        self, caller: Caller, envelope: Envelope, expected_version: int | None = None
    ) -> bytes:
        """按信封上记录的版本解密历史数据；可指定期望版本以显式校验。
        已退役版本拒绝解密（VERSION_RETIRED），与不存在/已停用明确区分。"""
        caller.require(Permission.DECRYPT)
        self._validate(envelope)
        if expected_version is not None and envelope.version != expected_version:
            raise KeyManagementError(
                ErrorCode.VERSION_MISMATCH,
                f"信封版本 {envelope.version} 与期望版本 {expected_version} 不一致",
            )
        key = self._keyring.get(envelope.version)
        if key.state is KeyState.RETIRED:
            raise KeyManagementError(
                ErrorCode.VERSION_RETIRED,
                f"版本 {envelope.version} 已退役（终态），其密文不可再解密",
            )
        plaintext = self._open(key, envelope)
        self._keyring.record_decrypt(envelope.version)
        return plaintext

    def rotate(self, caller: Caller, version: int, material: bytes) -> None:
        """轮换主密钥版本（需要 ROTATE 权限）。"""
        caller.require(Permission.ROTATE)
        self._keyring.rotate(version, material)

    def deactivate(self, caller: Caller, version: int) -> None:
        """停用版本（需要 DEACTIVATE 权限）。"""
        caller.require(Permission.DEACTIVATE)
        self._keyring.deactivate(version)

    def retire(self, caller: Caller, version: int) -> None:
        """退役版本（需要 RETIRE 权限）。

        判定与状态变更在同一把锁内完成：仍有历史密文引用时抛
        VERSION_IN_USE 拒绝退役；退役是终态，不可再启用/解密。
        """
        caller.require(Permission.RETIRE)
        with self._keyring.lock:
            in_use = self._store.count_by_version(version)
            if in_use > 0:
                raise KeyManagementError(
                    ErrorCode.VERSION_IN_USE,
                    f"版本 {version} 仍有 {in_use} 条历史密文在使用，拒绝退役",
                )
            self._keyring.retire(version)

    def version_stats(self, caller: Caller, version: int) -> dict:
        """按版本查看使用统计（加密/解密次数、最后使用时间）。"""
        return self._keyring.stats(version)

    def reencrypt(
        self, caller: Caller, record_ids: list[int], target_version: int
    ) -> dict:
        """把一批记录批量重加密到目标版本之下（需要 REENCRYPT 权限）。

        - 整批持锁：与退役、轮换、停用互斥，不会互相穿插；
        - 先在内存中完成全部解旧封新，全部成功后才一次性提交台账，
          任何一条失败都不会留下只迁了一半的结果，重试从干净状态开始；
        - 明文只存在于服务进程内存，返回值不含任何明文；
        - 目标版本必须是当前 ACTIVE 版本，已退役版本不能作为目标。
        """
        caller.require(Permission.REENCRYPT)
        with self._keyring.lock:
            target = self._keyring.get(target_version)
            if target.state is KeyState.RETIRED:
                raise KeyManagementError(
                    ErrorCode.VERSION_RETIRED,
                    f"目标版本 {target_version} 已退役，不能用于重加密",
                )
            if target.state is not KeyState.ACTIVE:
                raise KeyManagementError(
                    ErrorCode.VERSION_NOT_ACTIVE,
                    f"目标版本 {target_version} 状态为 {target.state.value}，"
                    "只有当前生效版本才能作为重加密目标",
                )

            # 第一阶段：全部解旧封新（内存中），任何失败都不影响台账
            staged: list[tuple[int, Envelope]] = []
            for record_id in record_ids:
                old = self._store.get(record_id)
                old_key = self._keyring.get(old.version)
                if old_key.state is KeyState.RETIRED:
                    raise KeyManagementError(
                        ErrorCode.VERSION_RETIRED,
                        f"记录 {record_id} 所属版本 {old.version} 已退役，无法重加密",
                    )
                plaintext = self._open(old_key, old)
                new_envelope = self._seal(target, plaintext)
                new_envelope.record_id = record_id
                staged.append((record_id, new_envelope))

            # 第二阶段：整批提交（到此处不会再失败）
            for record_id, new_envelope in staged:
                self._store.replace(record_id, new_envelope)
                self._keyring.record_encrypt(target_version)
            return {
                "migrated": len(staged),
                "target_version": target_version,
                "record_ids": [rid for rid, _ in staged],
            }

    # ---- 内部原语 ----

    @staticmethod
    def _seal(key, plaintext: bytes) -> Envelope:
        """用指定密钥版本封装一份新信封。"""
        dek = crypto.generate_dek()
        wrapped_dek, wrap_nonce = crypto.wrap_dek(key.material, dek)
        ciphertext, nonce = crypto.encrypt_content(dek, plaintext, _aad(key.version))
        return Envelope(
            version=key.version,
            wrapped_dek=wrapped_dek,
            wrap_nonce=wrap_nonce,
            nonce=nonce,
            ciphertext=ciphertext,
        )

    @staticmethod
    def _open(key, envelope: Envelope) -> bytes:
        """用指定密钥版本解封信封，返回明文（不出服务进程）。"""
        dek = crypto.unwrap_dek(key.material, envelope.wrapped_dek, envelope.wrap_nonce)
        return crypto.decrypt_content(dek, envelope, _aad(envelope.version))

    @staticmethod
    def _validate(envelope: Envelope) -> None:
        if (
            not isinstance(envelope.version, int)
            or not envelope.wrapped_dek
            or not envelope.wrap_nonce
            or not envelope.nonce
            or not envelope.ciphertext
        ):
            raise KeyManagementError(
                ErrorCode.MALFORMED_ENVELOPE, "信封结构不完整或字段类型非法"
            )
