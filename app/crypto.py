"""信封加密原语：数据密钥生成、封装/解封、内容加解密。

算法选型：AES-256-GCM（AEAD），密文自带完整性校验；
任何篡改都会导致解密整体失败，不会返回半截明文。
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import ErrorCode, KeyManagementError
from .models import Envelope

DEK_SIZE = 32    # AES-256
NONCE_SIZE = 12  # GCM 标准随机数长度


def generate_dek() -> bytes:
    """生成一份独立的数据密钥。"""
    return os.urandom(DEK_SIZE)


def wrap_dek(master: bytes, dek: bytes) -> tuple[bytes, bytes]:
    """用主密钥封装数据密钥，返回 (wrapped_dek, nonce)。"""
    nonce = os.urandom(NONCE_SIZE)
    wrapped = AESGCM(master).encrypt(nonce, dek, b"keywrap")
    return wrapped, nonce


def unwrap_dek(master: bytes, wrapped_dek: bytes, nonce: bytes) -> bytes:
    """解封数据密钥；认证失败时抛 CIPHERTEXT_TAMPERED。"""
    try:
        return AESGCM(master).decrypt(nonce, wrapped_dek, b"keywrap")
    except InvalidTag as exc:
        raise KeyManagementError(
            ErrorCode.CIPHERTEXT_TAMPERED, "数据密钥解封失败：封装数据被篡改或主密钥不匹配"
        ) from exc


def encrypt_content(dek: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """用数据密钥加密内容，返回 (ciphertext, nonce)。"""
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)
    return ciphertext, nonce


def decrypt_content(dek: bytes, envelope: Envelope, aad: bytes) -> bytes:
    """解密内容；篡改或认证失败时抛错，绝不返回半截明文。"""
    try:
        return AESGCM(dek).decrypt(envelope.nonce, envelope.ciphertext, aad)
    except InvalidTag as exc:
        raise KeyManagementError(
            ErrorCode.CIPHERTEXT_TAMPERED, "内容解密失败：密文被篡改或完整性校验不通过"
        ) from exc
