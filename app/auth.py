"""调用方身份与权限模型。

身份由服务端自己确认：调用方只出示令牌（token），
服务端在本地身份注册表中查出它是谁、有哪些权限。
客户端在请求里声明的任何名称/权限都不被信任。
"""

from __future__ import annotations

import threading
from enum import Enum

from .errors import ErrorCode, KeyManagementError


class Permission(str, Enum):
    ENCRYPT = "ENCRYPT"
    DECRYPT = "DECRYPT"
    ROTATE = "ROTATE"
    DEACTIVATE = "DEACTIVATE"
    RETIRE = "RETIRE"          # 退役版本
    REENCRYPT = "REENCRYPT"    # 批量重加密


class Caller:
    """携带权限集合的调用方身份（由服务端构造，不接受客户端自报）。"""

    def __init__(self, name: str, permissions: frozenset[Permission]):
        self.name = name
        self.permissions = permissions

    def require(self, permission: Permission) -> None:
        """校验权限，越权抛 PERMISSION_DENIED。"""
        if permission not in self.permissions:
            raise KeyManagementError(
                ErrorCode.PERMISSION_DENIED,
                f"调用方 {self.name!r} 缺少 {permission.value} 权限",
            )


class IdentityRegistry:
    """服务端身份注册表：令牌 -> (名称, 权限集合)。

    只有服务端能登记身份；客户端只能出示令牌。
    令牌无法识别时抛 UNAUTHENTICATED（HTTP 层映射为 401）。
    """

    def __init__(self) -> None:
        self._identities: dict[str, Caller] = {}
        self._lock = threading.Lock()

    def provision(self, token: str, name: str, permissions: frozenset[Permission]) -> None:
        """服务端预置一个调用方身份。"""
        if not token:
            raise ValueError("令牌不能为空")
        with self._lock:
            self._identities[token] = Caller(name, permissions)

    def authenticate(self, token: str | None) -> Caller:
        """按令牌确认识别调用方；识别失败抛 UNAUTHENTICATED。"""
        if not token:
            raise KeyManagementError(
                ErrorCode.UNAUTHENTICATED, "未提供调用方令牌，身份无法识别"
            )
        with self._lock:
            caller = self._identities.get(token)
        if caller is None:
            raise KeyManagementError(
                ErrorCode.UNAUTHENTICATED, "调用方令牌未被服务端识别"
            )
        return caller
