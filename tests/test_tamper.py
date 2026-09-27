"""场景三：密文篡改、版本对不上、认证失败——只能解密失败，失败原因可区分。"""

import logging

import pytest

from app.crypto import Envelope, EnvelopeCipher
from app.errors import ErrorReason, KeyManagementError
from app.keystore import KeyState

logger = logging.getLogger(__name__)


def _flip(data: bytearray, index: int) -> None:
    data[index] ^= 0x01


def test_tampered_envelope_fails(svc, admin, writer, reader):
    # 准备：轮换到 v2，用 v1 加密历史数据
    v2 = svc.rotate(admin)
    v1 = next(
        kv for kv in svc.keystore.snapshot()
        if kv.state is KeyState.ACTIVE and kv.version < v2.version
    )
    env = EnvelopeCipher.encrypt(b"integrity-check", v1.version, v1.material)

    # 版本号改成另一个已存在版本 v2：能取到密钥但 HMAC/AEAD 对不上
    raw_version = bytearray(env.to_bytes())
    assert raw_version[7] == v1.version
    raw_version[7] = v2.version
    logger.info("输入: 版本号字段 v%s -> v%s（均已登记）", v1.version, v2.version)
    with pytest.raises(KeyManagementError) as exc:
        svc.decrypt(reader, Envelope.from_bytes(bytes(raw_version)))
    assert exc.value.reason is ErrorReason.TAMPERED_CIPHERTEXT
    logger.info("判定: 版本号被改成另一已存在版本 -> reason=%s", exc.value.reason.value)

    # 其它字段逐个翻转数据首字节
    layout = Envelope.from_bytes(env.to_bytes())
    fields = [
        ("wrapped_dek", layout.wrapped_dek),
        ("dek_nonce", layout.dek_nonce),
        ("ciphertext", layout.ciphertext),
        ("content_nonce", layout.content_nonce),
        ("tag", layout.tag),
    ]
    offset = 8  # header(magic4 + version4) 之后
    for name, value in fields:
        raw = bytearray(env.to_bytes())
        idx = offset + 4  # 跳过长度前缀，定位数据首字节
        _flip(raw, idx)
        logger.info("输入: 翻转字段 %s 第 %s 字节", name, idx)
        with pytest.raises(KeyManagementError) as exc:
            svc.decrypt(reader, Envelope.from_bytes(bytes(raw)))
        assert exc.value.reason is ErrorReason.TAMPERED_CIPHERTEXT
        logger.info("判定: 篡改 %s -> reason=%s（未返回任何明文）", name, exc.value.reason.value)
        offset += 4 + len(value)


def test_version_mismatch_is_distinct(svc, writer):
    env = svc.encrypt(writer, b"version-bound")
    kv = svc.keystore.latest_active()
    logger.info("输入: 信封实际版本 v%s，按预期版本 v99 解密", env.key_version)
    with pytest.raises(KeyManagementError) as exc:
        EnvelopeCipher.decrypt(env, kv.material, expected_version=99)
    assert exc.value.reason is ErrorReason.VERSION_MISMATCH
    logger.info("判定: 版本对不上 -> reason=%s", exc.value.reason.value)


def test_wrong_master_key_auth_failure(svc, writer):
    env = svc.encrypt(writer, b"auth-check")
    logger.info("输入: 用另一把主密钥解封 v%s 信封", env.key_version)
    with pytest.raises(KeyManagementError) as exc:
        EnvelopeCipher.decrypt(env, b"x" * 32)
    assert exc.value.reason is ErrorReason.TAMPERED_CIPHERTEXT
    logger.info("判定: 认证失败 -> reason=%s", exc.value.reason.value)


def test_malformed_envelope_is_distinct():
    logger.info("输入: 一段无法解析的字节")
    with pytest.raises(KeyManagementError) as exc:
        Envelope.from_bytes(b"not-an-envelope")
    assert exc.value.reason is ErrorReason.MALFORMED_ENVELOPE
    logger.info("判定: 结构损坏 -> reason=%s", exc.value.reason.value)


def test_unknown_version_on_decrypt(svc, reader):
    env = EnvelopeCipher.encrypt(b"ghost", 77, b"k" * 32)
    logger.info("输入: 信封关联版本 v77，注册表中不存在")
    with pytest.raises(KeyManagementError) as exc:
        svc.decrypt(reader, env)
    assert exc.value.reason is ErrorReason.KEY_NOT_FOUND
    logger.info("判定: 版本不存在 -> reason=%s", exc.value.reason.value)
