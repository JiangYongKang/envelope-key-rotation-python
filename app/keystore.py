"""密钥版本登记与生命周期管理。

规则：
- 版本号单调递增，重复登记与版本回退都会被拒绝（原因可区分）。
- 状态机：ACTIVE -> DISABLED，停用不可逆；已停用版本不得再被启用或重复停用。
- 所有操作在锁内完成，保证与加密写入并发时不出现半写状态。
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from enum import Enum

from app.errors import ErrorReason, KeyManagementError

MASTER_KEY_BYTES = 32  # AES-256


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

    @property
    def lock(self) -> threading.RLock:
        """暴露锁给服务层，用于把"取当前版本"与"加密"放进同一临界区。"""
        return self._lock

    def _max_version(self) -> int:
        return max(self._versions, default=0)

    def generate_version(self) -> KeyVersion:
        """生成新的主密钥材料并登记为下一个版本号。"""
        with self._lock:
            return self._register_locked(self._max_version() + 1, os.urandom(MASTER_KEY_BYTES))

    def register_version(self, version: int, material: bytes) -> KeyVersion:
        """登记指定版本；拒绝重复登记与版本回退。"""
        if len(material) != MASTER_KEY_BYTES:
            raise KeyManagementError(
                ErrorReason.MALFORMED_ENVELOPE,
                f"主密钥材料长度必须为 {MASTER_KEY_BYTES} 字节，实际 {len(material)}",
            )
        with self._lock:
            return self._register_locked(version, material)

    def _register_locked(self, version: int, material: bytes) -> KeyVersion:
        if version in self._versions:
            raise KeyManagementError(
                ErrorReason.DUPLICATE_VERSION, f"版本 {version} 已登记，拒绝重复登记"
            )
        max_v = self._max_version()
        if version <= max_v:
            raise KeyManagementError(
                ErrorReason.VERSION_ROLLBACK,
                f"版本回退：登记版本 {version} 不大于当前最大版本 {max_v}",
            )
        kv = KeyVersion(version=version, material=material, state=KeyState.ACTIVE)
        self._versions[version] = kv
        return kv

    def activate(self, version: int) -> KeyVersion:
        """启用版本。停用不可逆，因此只允许对已是 ACTIVE 的版本幂等确认。"""
        with self._lock:
            kv = self.get(version)
            if kv.state is KeyState.DISABLED:
                raise KeyManagementError(
                    ErrorReason.KEY_DISABLED,
                    f"版本 {version} 已停用，停用不可逆，拒绝重新启用",
                )
            return kv

    def disable(self, version: int) -> KeyVersion:
        """停用版本：之后不得再用于加密新数据，但仍可解密历史数据。"""
        with self._lock:
            kv = self.get(version)
            if kv.state is KeyState.DISABLED:
                raise KeyManagementError(
                    ErrorReason.KEY_DISABLED, f"版本 {version} 已处于停用状态，拒绝重复停用"
                )
            updated = KeyVersion(version=kv.version, material=kv.material, state=KeyState.DISABLED)
            self._versions[version] = updated
            return updated

    def get(self, version: int) -> KeyVersion:
        """按版本号查询；不存在则抛 KEY_NOT_FOUND。"""
        with self._lock:
            kv = self._versions.get(version)
            if kv is None:
                raise KeyManagementError(ErrorReason.KEY_NOT_FOUND, f"版本 {version} 不存在")
            return kv

    def latest_active(self) -> KeyVersion:
        """返回当前生效的最高 ACTIVE 版本。"""
        with self._lock:
            active = [kv for kv in self._versions.values() if kv.state is KeyState.ACTIVE]
            if not active:
                raise KeyManagementError(
                    ErrorReason.NO_ACTIVE_KEY, "没有处于 ACTIVE 状态的主密钥版本"
                )
            return max(active, key=lambda kv: kv.version)
