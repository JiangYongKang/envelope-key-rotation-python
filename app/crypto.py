"""信封加密原语。

流程：
1. 每次加密生成独立的数据密钥 DEK（32 字节）。
2. 用当前主密钥版本以 AES-256-GCM 封装 DEK，AAD 绑定版本号。
3. 用 DEK 以 AES-256-GCM 加密内容，AAD 绑定版本号与封装后的 DEK。
4. 另用主密钥对全部关键字段计算 HMAC-SHA256 作为完整性校验值。

任何字段被篡改都会在解密前被 HMAC 或 AEAD 拦下，绝不返回半截明文。
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.errors import ErrorReason, KeyManagementError

DEK_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 32  # HMAC-SHA256
_HEADER = struct.Struct(">4sI")  # magic + key_version
_MAGIC = b"EKR1"


def _version_aad(key_version: int) -> bytes:
    return _MAGIC + struct.pack(">I", key_version)


@dataclass(frozen=True)
class Envelope:
    """一条密文记录：固定关联加密时生效的主密钥版本。"""

    key_version: int
    wrapped_dek: bytes       # 被主密钥版本封装的数据密钥（含 GCM 认证标签）
    dek_nonce: bytes
    ciphertext: bytes        # 内容密文（含 GCM 认证标签）
    content_nonce: bytes
    tag: bytes               # 对关键部分的完整性校验值

    def to_bytes(self) -> bytes:
        parts = [self.wrapped_dek, self.dek_nonce, self.ciphertext, self.content_nonce, self.tag]
        body = b"".join(struct.pack(">I", len(p)) + p for p in parts)
        return _HEADER.pack(_MAGIC, self.key_version) + body

    @staticmethod
    def from_bytes(raw: bytes) -> "Envelope":
        try:
            magic, key_version = _HEADER.unpack_from(raw, 0)
            if magic != _MAGIC:
                raise ValueError("bad magic")
            offset = _HEADER.size
            fields: list[bytes] = []
            for _ in range(5):
                (length,) = struct.unpack_from(">I", raw, offset)
                offset += 4
                fields.append(raw[offset : offset + length])
                if len(fields[-1]) != length:
                    raise ValueError("truncated field")
                offset += length
            if offset != len(raw):
                raise ValueError("trailing bytes")
        except (struct.error, ValueError) as exc:
            raise KeyManagementError(
                ErrorReason.MALFORMED_ENVELOPE, f"信封结构无法解析: {exc}"
            ) from exc
        return Envelope(
            key_version=key_version,
            wrapped_dek=fields[0],
            dek_nonce=fields[1],
            ciphertext=fields[2],
            content_nonce=fields[3],
            tag=fields[4],
        )


class EnvelopeCipher:
    """每次加密使用独立 DEK，用指定主密钥版本封装，并做完整性校验。"""

    @staticmethod
    def _integrity_tag(key_version: int, master_key: bytes, env_fields: tuple[bytes, ...]) -> bytes:
        mac = hmac.new(master_key, digestmod=hashlib.sha256)
        mac.update(_version_aad(key_version))
        for part in env_fields:
            mac.update(struct.pack(">I", len(part)))
            mac.update(part)
        return mac.digest()

    @staticmethod
    def encrypt(plaintext: bytes, key_version: int, master_key: bytes) -> Envelope:
        dek = os.urandom(DEK_BYTES)
        dek_nonce = os.urandom(NONCE_BYTES)
        content_nonce = os.urandom(NONCE_BYTES)

        # 用主密钥版本封装 DEK，AAD 绑定版本号
        wrapped_dek = AESGCM(master_key).encrypt(dek_nonce, dek, _version_aad(key_version))
        # 用 DEK 加密内容，AAD 绑定版本号与封装后的 DEK
        aad = _version_aad(key_version) + wrapped_dek
        ciphertext = AESGCM(dek).encrypt(content_nonce, plaintext, aad)

        tag = EnvelopeCipher._integrity_tag(
            key_version, master_key, (wrapped_dek, dek_nonce, ciphertext, content_nonce)
        )
        return Envelope(
            key_version=key_version,
            wrapped_dek=wrapped_dek,
            dek_nonce=dek_nonce,
            ciphertext=ciphertext,
            content_nonce=content_nonce,
            tag=tag,
        )

    @staticmethod
    def decrypt(envelope: Envelope, master_key: bytes, expected_version: int | None = None) -> bytes:
        """认证失败/篡改/版本不符时抛错，绝不返回半截明文。"""
        if expected_version is not None and envelope.key_version != expected_version:
            raise KeyManagementError(
                ErrorReason.VERSION_MISMATCH,
                f"信封关联版本 {envelope.key_version} 与预期版本 {expected_version} 不一致",
            )
        # 先校验完整性标签，任何字段被篡改都会在这里被拦下
        expected_tag = EnvelopeCipher._integrity_tag(
            envelope.key_version,
            master_key,
            (envelope.wrapped_dek, envelope.dek_nonce, envelope.ciphertext, envelope.content_nonce),
        )
        if not hmac.compare_digest(expected_tag, envelope.tag):
            raise KeyManagementError(
                ErrorReason.TAMPERED_CIPHERTEXT, "完整性校验失败：信封关键字段被篡改"
            )
        try:
            dek = AESGCM(master_key).decrypt(
                envelope.dek_nonce, envelope.wrapped_dek, _version_aad(envelope.key_version)
            )
        except Exception as exc:
            raise KeyManagementError(
                ErrorReason.TAMPERED_CIPHERTEXT, f"DEK 解封认证失败: {exc}"
            ) from exc
        aad = _version_aad(envelope.key_version) + envelope.wrapped_dek
        try:
            return AESGCM(dek).decrypt(envelope.content_nonce, envelope.ciphertext, aad)
        except Exception as exc:
            raise KeyManagementError(
                ErrorReason.TAMPERED_CIPHERTEXT, f"内容解密认证失败: {exc}"
            ) from exc
