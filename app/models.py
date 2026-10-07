"""数据模型：密钥版本、状态机、信封密文。"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum


class KeyState(str, Enum):
    PENDING = "PENDING"      # 已登记，未启用
    ACTIVE = "ACTIVE"        # 当前生效，可用于加密
    DISABLED = "DISABLED"    # 已停用，仅可用于解密历史数据
    RETIRED = "RETIRED"      # 已退役，终态：不可启用、不可解密


@dataclass
class KeyStats:
    """按版本统计的使用情况，用于判断是否可安全退役。"""

    encrypt_count: int = 0
    decrypt_count: int = 0
    last_used_at: float | None = None


@dataclass
class KeyVersion:
    version: int
    material: bytes          # 主密钥材料（本地内存保存）
    state: KeyState = KeyState.PENDING
    created_at: float = field(default_factory=time.time)
    stats: KeyStats = field(default_factory=KeyStats)


@dataclass
class Envelope:
    """信封加密结果：密文固定关联加密时生效的密钥版本。"""

    version: int             # 执行加密时生效的主密钥版本
    wrapped_dek: bytes       # 被主密钥封装的数据密钥
    wrap_nonce: bytes        # 封装数据密钥时使用的随机数
    nonce: bytes             # 内容加密的随机数
    ciphertext: bytes        # 内容密文（AEAD，自带完整性校验）
