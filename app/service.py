"""密钥管理与信封加密服务：组合 KeyStore 与 EnvelopeCipher，做权限与并发控制。

并发约定：
- encrypt 在 keystore 的同一把锁内完成"取当前生效版本"与"加密"，
  rotate/disable 也必须先拿到同一把锁才能变更状态，
  因此不会出现用正在停用或已停用的版本加密新数据，也不会留下半写状态。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum

from app.crypto import Envelope, EnvelopeCipher
from app.errors import ErrorReason, KeyManagementError
from app.keystore import KeyStore, KeyVersion


class Permission(str, Enum):
    ENCRYPT = "ENCRYPT"
    DECRYPT = "DECRYPT"
    ROTATE = "ROTATE"
    DISABLE = "DISABLE"


@dataclass(frozen=True)
class Caller:
    name: str
    permissions: frozenset[Permission]


@dataclass
class EnvelopeService:
    keystore: KeyStore = field(default_factory=KeyStore)
    _write_lock: threading.RLock = field(default_factory=threading.RLock)

    def _require(self, caller: Caller, perm: Permission) -> None:
        if perm not in caller.permissions:
            raise KeyManagementError(
                ErrorReason.PERMISSION_DENIED,
                f"调用方 {caller.name!r} 缺少权限 {perm.value}",
            )

    def rotate(self, caller: Caller) -> KeyVersion:
        """轮换：生成并启用新版本。与加密写入互斥，不留半写状态。"""
        self._require(caller, Permission.ROTATE)
        with self._write_lock:
            return self.keystore.generate_version()

    def disable(self, caller: Caller, version: int) -> KeyVersion:
        self._require(caller, Permission.DISABLE)
        with self._write_lock:
            return self.keystore.disable(version)

    def encrypt(self, caller: Caller, plaintext: bytes) -> Envelope:
        """用当前生效版本加密；版本快照与加密在同一临界区完成。"""
        self._require(caller, Permission.ENCRYPT)
        with self._write_lock:
            # 在写锁内取版本快照：此刻该版本必定处于 ACTIVE，
            # 任何 disable/rotate 都要等本次加密完成后才能生效。
            kv = self.keystore.latest_active()
            return EnvelopeCipher.encrypt(plaintext, kv.version, kv.material)

    def decrypt(self, caller: Caller, envelope: Envelope) -> bytes:
        """按信封内记录的版本取主密钥解密，轮换后历史数据仍可解。"""
        self._require(caller, Permission.DECRYPT)
        kv = self.keystore.get(envelope.key_version)  # DISABLED 版本也可用于解密
        return EnvelopeCipher.decrypt(envelope, kv.material)
