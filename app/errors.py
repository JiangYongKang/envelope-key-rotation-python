"""错误类型定义：每一种失败都有独立的原因码，便于定位卡在哪一环。"""

from __future__ import annotations

from enum import Enum


class ErrorReason(str, Enum):
    # 密钥管理类
    DUPLICATE_VERSION = "DUPLICATE_VERSION"        # 重复登记同一版本
    VERSION_ROLLBACK = "VERSION_ROLLBACK"          # 版本号回退（小于等于当前最大版本）
    KEY_NOT_FOUND = "KEY_NOT_FOUND"                # 版本不存在
    KEY_DISABLED = "KEY_DISABLED"                  # 对已停用版本执行了非法操作
    KEY_ALREADY_ACTIVE = "KEY_ALREADY_ACTIVE"      # 重复启用
    NO_ACTIVE_KEY = "NO_ACTIVE_KEY"                # 没有可用主密钥版本
    # 密文类
    TAMPERED_CIPHERTEXT = "TAMPERED_CIPHERTEXT"    # 密文/封装数据被篡改，认证失败
    VERSION_MISMATCH = "VERSION_MISMATCH"          # 密文关联的版本与预期不符
    MALFORMED_ENVELOPE = "MALFORMED_ENVELOPE"      # 信封结构不完整/无法解析
    # 权限类
    PERMISSION_DENIED = "PERMISSION_DENIED"        # 调用方缺少相应权限


class KeyManagementError(Exception):
    """所有密钥管理与信封加密失败的基类，携带可区分的原因码。"""

    def __init__(self, reason: ErrorReason, message: str):
        self.reason = reason
        super().__init__(f"[{reason.value}] {message}")
