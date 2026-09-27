"""密钥管理与信封加密服务（骨架）：组合 KeyStore 与 EnvelopeCipher，做权限与并发控制。"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum

from app.crypto import Envelope
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
        raise NotImplementedError

    def rotate(self, caller: Caller) -> KeyVersion:
        """轮换：生成并启用新版本。与加密写入互斥，不留半写状态。"""
        raise NotImplementedError

    def disable(self, caller: Caller, version: int) -> KeyVersion:
        raise NotImplementedError

    def encrypt(self, caller: Caller, plaintext: bytes) -> Envelope:
        """用当前生效版本加密；版本快照与取密钥在同一临界区完成。"""
        raise NotImplementedError

    def decrypt(self, caller: Caller, envelope: Envelope) -> bytes:
        """按信封内记录的版本取主密钥解密，轮换后历史数据仍可解。"""
        raise NotImplementedError
