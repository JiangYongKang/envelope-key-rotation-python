"""调用方权限模型与服务端身份校验。

身份可信原则：调用方是谁、有哪些权限，只能由服务端的 IdentityRegistry
根据凭据（token）解析得出；客户端自报的权限一律不被采纳。
"""

from __future__ import annotations

from enum import Enum

from .errors import ErrorCode, KeyManagementError


class Permission(str, Enum):
    ENCRYPT = "ENCRYPT"
    DECRYPT = "DECRYPT"
    ROTATE = "ROTATE"
    DEACTIVATE = "DEACTIVATE"
    RETIRE = "RETIRE"
    REENCRYPT = "REENCRYPT"


class Caller:
    """携带权限集合的调用方身份（由服务端构造，不接受客户端自报权限）。"""

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
    """服务端身份注册表：token -> (调用方名, 权限集合)。

    只认注册过的 token；未识别的 token 抛 UNAUTHENTICATED。
    """

    def __init__(self) -> None:
        self._identities: dict[str, Caller] = {}

    def register(self, token: str, name: str, permissions: frozenset[Permission]) -> None:
        """登记一个合法调用方凭据（服务端配置行为，不对外暴露）。"""
        self._identities[token] = Caller(name, permissions)

    def authenticate(self, token: str | None) -> Caller:
        """按凭据解析调用方身份；无法识别时抛 UNAUTHENTICATED。"""
        if not token or token not in self._identities:
            raise KeyManagementError(
                ErrorCode.UNAUTHENTICATED, "调用方身份未被服务端识别"
            )
        return self._identities[token]
