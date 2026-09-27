"""密钥版本登记与生命周期管理（骨架：仅类型定义与空实现）。"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum


class KeyState(str, Enum):
    ACTIVE = "ACTIVE"        # 可用于加密新数据，也可解密
    DISABLED = "DISABLED"    # 仅可用于解密历史数据，不可加密新数据


@dataclass(frozen=True)
class KeyVersion:
    version: int
    material: bytes          # 主密钥材料（本地内存保存）
    state: KeyState = KeyState.ACTIVE


@dataclass
class KeyStore:
    """线程安全的密钥版本注册表。"""

    _versions: dict[int, KeyVersion] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock)

    def generate_version(self) -> KeyVersion:
        """生成新的主密钥材料并登记为下一个版本号。"""
        raise NotImplementedError

    def register_version(self, version: int, material: bytes) -> KeyVersion:
        """登记指定版本；拒绝重复登记与版本回退。"""
        raise NotImplementedError

    def activate(self, version: int) -> KeyVersion:
        """启用一个版本（DISABLED -> ACTIVE 不允许，见需求：停用不可逆）。"""
        raise NotImplementedError

    def disable(self, version: int) -> KeyVersion:
        """停用版本：之后不得再用于加密新数据。"""
        raise NotImplementedError

    def get(self, version: int) -> KeyVersion:
        """按版本号查询；不存在则抛 KEY_NOT_FOUND。"""
        raise NotImplementedError

    def latest_active(self) -> KeyVersion:
        """返回当前生效的最高 ACTIVE 版本。"""
        raise NotImplementedError
