"""错误类型：每一种失败都有可区分的原因码。"""

from __future__ import annotations

from enum import Enum


class ErrorCode(str, Enum):
    # 密钥版本管理类
    DUPLICATE_VERSION = "DUPLICATE_VERSION"          # 重复登记同一版本
    VERSION_REGRESSION = "VERSION_REGRESSION"        # 版本号回退
    VERSION_NOT_FOUND = "VERSION_NOT_FOUND"          # 版本不存在
    VERSION_NOT_ACTIVE = "VERSION_NOT_ACTIVE"        # 对已停用/未启用版本的非法操作
    NO_ACTIVE_VERSION = "NO_ACTIVE_VERSION"          # 当前没有可用主密钥版本
    # 信封加密类
    CIPHERTEXT_TAMPERED = "CIPHERTEXT_TAMPERED"      # 完整性校验失败（密文被篡改）
    VERSION_MISMATCH = "VERSION_MISMATCH"            # 密文关联的版本与预期不符
    MALFORMED_ENVELOPE = "MALFORMED_ENVELOPE"        # 信封结构损坏
    # 退役类
    VERSION_RETIRED = "VERSION_RETIRED"              # 对已退役版本的非法操作（终态）
    VERSION_IN_USE = "VERSION_IN_USE"                # 仍有历史密文引用，拒绝退役
    # 记录仓库类
    RECORD_NOT_FOUND = "RECORD_NOT_FOUND"            # 记录不存在
    # 权限类
    PERMISSION_DENIED = "PERMISSION_DENIED"          # 越权调用
    UNAUTHENTICATED = "UNAUTHENTICATED"              # 调用方身份未被服务端识别


class KeyManagementError(Exception):
    """所有业务错误的基类，携带可区分的原因码。"""

    def __init__(self, code: ErrorCode, message: str):
        self.code = code
        super().__init__(f"[{code.value}] {message}")
