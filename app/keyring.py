"""密钥版本管理：登记、启用、轮换、停用，线程安全。

状态机：PENDING --activate--> ACTIVE --deactivate/rotate--> DISABLED
所有状态变更都在同一把可重入锁内完成，加密方可以通过 `lock`
持锁读取当前生效版本，保证不会用到正在停用的版本。
"""

from __future__ import annotations

import threading

from .errors import ErrorCode, KeyManagementError
from .models import KeyState, KeyVersion


class KeyRing:
    """本地密钥版本仓库（内存实现），所有状态变更都在锁内完成。"""

    def __init__(self) -> None:
        self._versions: dict[int, KeyVersion] = {}
        self._active: int | None = None
        self._lock = threading.RLock()

    @property
    def lock(self) -> threading.RLock:
        """供加密路径持锁，与轮换/停用互斥。"""
        return self._lock

    def register(self, version: int, material: bytes) -> KeyVersion:
        """登记新版本；重复登记与版本回退会被拒绝。"""
        with self._lock:
            if version in self._versions:
                raise KeyManagementError(
                    ErrorCode.DUPLICATE_VERSION, f"版本 {version} 已登记，拒绝重复登记"
                )
            if self._versions and version <= max(self._versions):
                raise KeyManagementError(
                    ErrorCode.VERSION_REGRESSION,
                    f"版本 {version} 不大于已有最大版本 {max(self._versions)}，拒绝版本回退",
                )
            key = KeyVersion(version=version, material=material)
            self._versions[version] = key
            return key

    def activate(self, version: int) -> KeyVersion:
        """启用某个已登记版本为当前主密钥版本。"""
        with self._lock:
            key = self._require(version)
            if key.state is KeyState.RETIRED:
                raise KeyManagementError(
                    ErrorCode.VERSION_RETIRED, f"版本 {version} 已退役（终态），不能重新启用"
                )
            if key.state is KeyState.DISABLED:
                raise KeyManagementError(
                    ErrorCode.VERSION_NOT_ACTIVE, f"版本 {version} 已停用，不能重新启用"
                )
            if key.state is KeyState.ACTIVE:
                raise KeyManagementError(
                    ErrorCode.VERSION_NOT_ACTIVE, f"版本 {version} 已是当前生效版本"
                )
            if self._active is not None:
                self._versions[self._active].state = KeyState.DISABLED
            key.state = KeyState.ACTIVE
            self._active = version
            return key

    def rotate(self, version: int, material: bytes) -> KeyVersion:
        """轮换：登记并启用新版本，旧版本自动转为 DISABLED（原子完成）。"""
        with self._lock:
            self.register(version, material)
            return self.activate(version)

    def deactivate(self, version: int) -> KeyVersion:
        """停用版本；停用后不可再用于加密，也不可重复停用。"""
        with self._lock:
            key = self._require(version)
            if key.state is KeyState.RETIRED:
                raise KeyManagementError(
                    ErrorCode.VERSION_RETIRED, f"版本 {version} 已退役（终态），不能停用"
                )
            if key.state is KeyState.DISABLED:
                raise KeyManagementError(
                    ErrorCode.VERSION_NOT_ACTIVE, f"版本 {version} 已停用，不能重复停用"
                )
            key.state = KeyState.DISABLED
            if self._active == version:
                self._active = None
            return key

    def retire(self, version: int, in_use: bool) -> KeyVersion:
        """退役版本（终态）。仅允许已停用且无历史密文引用的版本。

        in_use 由调用方（服务层）在同一锁内判定后传入。
        """
        with self._lock:
            key = self._require(version)
            if key.state is KeyState.RETIRED:
                raise KeyManagementError(
                    ErrorCode.VERSION_RETIRED, f"版本 {version} 已退役，不能重复退役"
                )
            if key.state is not KeyState.DISABLED:
                raise KeyManagementError(
                    ErrorCode.VERSION_NOT_ACTIVE,
                    f"版本 {version} 状态为 {key.state.value}，只有已停用版本才能退役",
                )
            if in_use:
                raise KeyManagementError(
                    ErrorCode.VERSION_IN_USE,
                    f"版本 {version} 仍在使用中：仍有历史密文引用，拒绝退役",
                )
            key.state = KeyState.RETIRED
            return key

    def usage(self, version: int) -> KeyVersion:
        """按版本查询使用统计所在的密钥条目。"""
        with self._lock:
            return self._require(version)

    def get(self, version: int) -> KeyVersion:
        """按版本号取密钥，用于解密历史数据。"""
        with self._lock:
            return self._require(version)

    def active_version(self) -> KeyVersion:
        """返回当前生效版本；没有则抛 NO_ACTIVE_VERSION。"""
        with self._lock:
            if self._active is None:
                raise KeyManagementError(
                    ErrorCode.NO_ACTIVE_VERSION, "当前没有已启用的主密钥版本"
                )
            return self._versions[self._active]

    def _require(self, version: int) -> KeyVersion:
        if version not in self._versions:
            raise KeyManagementError(
                ErrorCode.VERSION_NOT_FOUND, f"版本 {version} 不存在"
            )
        return self._versions[version]
