"""调用方权限模型。"""

from __future__ import annotations

from enum import Enum

from .errors import ErrorCode, KeyManagementError


class Permission(str, Enum):
    ENCRYPT = "ENCRYPT"
    DECRYPT = "DECRYPT"
    ROTATE = "ROTATE"
    DEACTIVATE = "DEACTIVATE"


class Caller:
    """携带权限集合的调用方身份。"""

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
