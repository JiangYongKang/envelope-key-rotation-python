"""信封加密原语（骨架）：DEK 生成、主密钥封装、内容加密与完整性校验。"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Envelope:
    """一条密文记录：固定关联加密时生效的主密钥版本。"""

    key_version: int
    wrapped_dek: bytes       # 被主密钥版本封装的数据密钥
    dek_nonce: bytes
    ciphertext: bytes
    content_nonce: bytes
    tag: bytes               # 对关键部分的完整性校验值

    def to_bytes(self) -> bytes:
        raise NotImplementedError

    @staticmethod
    def from_bytes(raw: bytes) -> "Envelope":
        raise NotImplementedError


class EnvelopeCipher:
    """每次加密使用独立 DEK，用指定主密钥版本封装，并做 AEAD 完整性校验。"""

    @staticmethod
    def encrypt(plaintext: bytes, key_version: int, master_key: bytes) -> Envelope:
        raise NotImplementedError

    @staticmethod
    def decrypt(envelope: Envelope, master_key: bytes) -> bytes:
        """认证失败/篡改时抛错，绝不返回半截明文。"""
        raise NotImplementedError
