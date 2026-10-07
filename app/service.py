"""信封加密服务：组合密钥管理与加密原语，对外提供加解密、轮换、退役与批量重加密。

并发约定：所有会读写密钥状态或记录仓库的路径都持有 KeyRing 的同一把
可重入锁，与 rotate/deactivate/retire/reencrypt 互斥，因此：
- 不会出现"用正在停用的版本加密新数据"，也不会留下只写一半的状态；
- 批量重加密整体持锁，退役无法穿插进来，源版本不会跑到一半被退役；
- 退役判定（无记录引用）与记录仓库的变更在同一锁内完成，判定结果可靠。
"""

from __future__ import annotations

import time
from dataclasses import replace

from . import crypto
from .auth import Caller, Permission
from .errors import ErrorCode, KeyManagementError
from .keyring import KeyRing
from .models import Envelope, KeyState, KeyStats, KeyVersion
from .records import RecordStore


def _aad(version: int) -> bytes:
    """把密钥版本绑定进完整性校验的附加认证数据。"""
    return f"envelope:v{version}".encode()


class EnvelopeCryptoService:
    def __init__(self, keyring: KeyRing | None = None) -> None:
        self._keyring = keyring or KeyRing()
        self._records = RecordStore()

    @property
    def keyring(self) -> KeyRing:
        return self._keyring

    @property
    def records(self) -> RecordStore:
        return self._records

    # ---------- 加解密 ----------

    def encrypt(self, caller: Caller, plaintext: bytes) -> Envelope:
        """用当前生效版本加密；加密期间版本不得被停用或退役。"""
        caller.require(Permission.ENCRYPT)
        with self._keyring.lock:
            key = self._keyring.active_version()
            return self._encrypt_with_key(key, plaintext)

    def decrypt(
        self, caller: Caller, envelope: Envelope, expected_version: int | None = None
    ) -> bytes:
        """按信封上记录的版本解密历史数据；可指定期望版本以显式校验。"""
        caller.require(Permission.DECRYPT)
        with self._keyring.lock:
            return self._decrypt_envelope(envelope, expected_version)

    # ---------- 版本生命周期 ----------

    def rotate(self, caller: Caller, version: int, material: bytes) -> None:
        """轮换主密钥版本（需要 ROTATE 权限）。"""
        caller.require(Permission.ROTATE)
        self._keyring.rotate(version, material)

    def deactivate(self, caller: Caller, version: int) -> None:
        """停用版本（需要 DEACTIVATE 权限）。"""
        caller.require(Permission.DEACTIVATE)
        self._keyring.deactivate(version)

    def retire(self, caller: Caller, version: int) -> None:
        """退役版本（终态，需要 RETIRE 权限）。

        只有已停用、且记录仓库中没有任何密文再引用它的版本才允许退役；
        判定与状态变更在同一把锁内完成，与批量重加密互斥。
        """
        caller.require(Permission.RETIRE)
        with self._keyring.lock:
            in_use = version in self._records.versions_in_use()
            self._keyring.retire(version, in_use)

    def usage(self, caller: Caller, version: int) -> KeyStats:
        """按版本查询使用统计：加密次数、解密次数、最后使用时间。"""
        caller.require(Permission.DECRYPT)
        key = self._keyring.usage(version)
        return replace(key.stats)

    # ---------- 记录存取与批量重加密 ----------

    def store_record(self, caller: Caller, record_id: str, plaintext: bytes) -> None:
        """加密并以 record_id 落库；加密与入库在同一锁内，退役判定才能看到它。"""
        caller.require(Permission.ENCRYPT)
        with self._keyring.lock:
            key = self._keyring.active_version()
            envelope = self._encrypt_with_key(key, plaintext)
            self._records.put(record_id, envelope)

    def read_record(self, caller: Caller, record_id: str) -> bytes:
        """按 record_id 解密记录。"""
        caller.require(Permission.DECRYPT)
        with self._keyring.lock:
            return self._decrypt_envelope(self._records.get(record_id))

    def reencrypt_records(
        self, caller: Caller, record_ids: list[str], target_version: int
    ) -> int:
        """把一批记录整体重加密到目标版本（需要 REENCRYPT 权限）。

        - 目标版本必须是当前 ACTIVE 版本，不会产出已停用/已退役版本的密文；
        - 全程持锁：退役无法穿插，源版本不会中途被退役；
        - 先在内存中算完全部新信封，再一次换入仓库：任何一条失败，
          仓库保持原状，重试从干净状态重新开始；
        - 明文不出服务边界，返回值只是迁移条数。
        """
        caller.require(Permission.REENCRYPT)
        with self._keyring.lock:
            target = self._keyring.get(target_version)
            if target.state is not KeyState.ACTIVE:
                raise KeyManagementError(
                    ErrorCode.VERSION_NOT_ACTIVE,
                    f"目标版本 {target_version} 状态为 {target.state.value}，"
                    "重加密只能迁往当前生效版本",
                )
            # 第一阶段：全部解密+重加密，任何失败都在落库前抛出
            migrated: list[tuple[str, Envelope]] = []
            for record_id in record_ids:
                envelope = self._records.get(record_id)
                plaintext = self._decrypt_envelope(envelope)
                migrated.append((record_id, self._encrypt_with_key(target, plaintext)))
                plaintext = b""  # 尽快丢弃明文引用
                self._reencrypt_hook(record_id)
            # 第二阶段：整体换入，要么全部生效要么全部不生效
            for record_id, envelope in migrated:
                self._records.put(record_id, envelope)
            return len(migrated)

    # ---------- 内部原语（调用方需已持锁） ----------

    def _reencrypt_hook(self, record_id: str) -> None:
        """批量重加密每迁完一条记录（未落库）时回调；测试可借此做确定性并发。"""

    def _encrypt_with_key(self, key: KeyVersion, plaintext: bytes) -> Envelope:
        if key.state is not KeyState.ACTIVE:
            raise KeyManagementError(
                ErrorCode.VERSION_NOT_ACTIVE,
                f"版本 {key.version} 状态为 {key.state.value}，不能用于加密",
            )
        dek = crypto.generate_dek()
        wrapped_dek, wrap_nonce = crypto.wrap_dek(key.material, dek)
        ciphertext, nonce = crypto.encrypt_content(dek, plaintext, _aad(key.version))
        key.stats.encrypt_count += 1
        key.stats.last_used_at = time.time()
        return Envelope(
            version=key.version,
            wrapped_dek=wrapped_dek,
            wrap_nonce=wrap_nonce,
            nonce=nonce,
            ciphertext=ciphertext,
        )

    def _decrypt_envelope(
        self, envelope: Envelope, expected_version: int | None = None
    ) -> bytes:
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
        dek = crypto.unwrap_dek(key.material, envelope.wrapped_dek, envelope.wrap_nonce)
        plaintext = crypto.decrypt_content(dek, envelope, _aad(envelope.version))
        key.stats.decrypt_count += 1
        key.stats.last_used_at = time.time()
        return plaintext

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
