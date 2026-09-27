"""信封加密服务：组合密钥管理与加密原语，对外提供加解密与轮换入口。

并发约定：encrypt 全程持有 KeyRing 的锁，与 rotate/deactivate 互斥，
因此不会出现"用正在停用的版本加密新数据"，也不会留下只写一半的状态。
"""

from __future__ import annotations

from . import crypto
from .auth import Caller, Permission
from .errors import ErrorCode, KeyManagementError
from .keyring import KeyRing
from .models import Envelope, KeyState


def _aad(version: int) -> bytes:
    """把密钥版本绑定进完整性校验的附加认证数据。"""
    return f"envelope:v{version}".encode()


class EnvelopeCryptoService:
    def __init__(self, keyring: KeyRing | None = None) -> None:
        self._keyring = keyring or KeyRing()

    @property
    def keyring(self) -> KeyRing:
        return self._keyring

    def encrypt(self, caller: Caller, plaintext: bytes) -> Envelope:
        """用当前生效版本加密；加密期间版本不得被停用。"""
        caller.require(Permission.ENCRYPT)
        with self._keyring.lock:
            key = self._keyring.active_version()
            if key.state is not KeyState.ACTIVE:
                raise KeyManagementError(
                    ErrorCode.VERSION_NOT_ACTIVE,
                    f"版本 {key.version} 状态为 {key.state.value}，不能用于加密",
                )
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

    def decrypt(
        self, caller: Caller, envelope: Envelope, expected_version: int | None = None
    ) -> bytes:
        """按信封上记录的版本解密历史数据；可指定期望版本以显式校验。"""
        caller.require(Permission.DECRYPT)
        self._validate(envelope)
        if expected_version is not None and envelope.version != expected_version:
            raise KeyManagementError(
                ErrorCode.VERSION_MISMATCH,
                f"信封版本 {envelope.version} 与期望版本 {expected_version} 不一致",
            )
        key = self._keyring.get(envelope.version)
        dek = crypto.unwrap_dek(key.material, envelope.wrapped_dek, envelope.wrap_nonce)
        return crypto.decrypt_content(dek, envelope, _aad(envelope.version))

    def rotate(self, caller: Caller, version: int, material: bytes) -> None:
        """轮换主密钥版本（需要 ROTATE 权限）。"""
        caller.require(Permission.ROTATE)
        self._keyring.rotate(version, material)

    def deactivate(self, caller: Caller, version: int) -> None:
        """停用版本（需要 DEACTIVATE 权限）。"""
        caller.require(Permission.DEACTIVATE)
        self._keyring.deactivate(version)

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
