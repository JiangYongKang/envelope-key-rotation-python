"""信封加密与密钥轮换的行为测试。

每个用例都打印输入与判定依据（pytest -s 可见），失败原因按 ErrorCode 区分。
"""

from __future__ import annotations

import os
import threading
from dataclasses import replace

import pytest

from app.auth import Caller, Permission
from app.errors import ErrorCode, KeyManagementError
from app.models import Envelope
from app.service import EnvelopeCryptoService

ADMIN = Caller("admin", frozenset(Permission))  # 全权限
WRITER = Caller("writer", frozenset({Permission.ENCRYPT}))
READER = Caller("reader", frozenset({Permission.DECRYPT}))


def make_service() -> EnvelopeCryptoService:
    svc = EnvelopeCryptoService()
    svc.keyring.rotate(1, os.urandom(32))
    return svc


def expect_error(code: ErrorCode, fn, *args, **kwargs) -> KeyManagementError:
    with pytest.raises(KeyManagementError) as exc_info:
        fn(*args, **kwargs)
    err = exc_info.value
    print(f"  判定依据: 期望原因码={code.value}, 实际原因码={err.code.value}, 信息={err}")
    assert err.code is code, f"期望 {code}，实际 {err.code}"
    return err


# ---------- 1. 轮换前后解密 ----------

def test_decrypt_before_and_after_rotation():
    svc = make_service()
    print("场景: 轮换前后解密")
    print("  输入: 用 v1 加密 'hello-v1'，随后轮换到 v2 再加密 'hello-v2'")

    env1 = svc.encrypt(ADMIN, b"hello-v1")
    print(f"  v1 信封: version={env1.version}")
    assert env1.version == 1

    svc.rotate(ADMIN, 2, os.urandom(32))
    env2 = svc.encrypt(ADMIN, b"hello-v2")
    print(f"  v2 信封: version={env2.version}")
    assert env2.version == 2

    back1 = svc.decrypt(ADMIN, env1)
    back2 = svc.decrypt(ADMIN, env2)
    print(f"  判定依据: 轮换后旧密文解密={back1!r}, 新密文解密={back2!r}")
    assert back1 == b"hello-v1"
    assert back2 == b"hello-v2"


def test_disabled_version_still_decrypts_but_cannot_encrypt():
    svc = make_service()
    print("场景: 停用版本可解密不可加密")
    env = svc.encrypt(ADMIN, b"old-data")
    svc.rotate(ADMIN, 2, os.urandom(32))  # 轮换后 v1 自动转为 DISABLED
    print("  输入: v1 已停用，解密 v1 历史密文")
    assert svc.decrypt(ADMIN, env) == b"old-data"

    svc.deactivate(ADMIN, 2)  # 全部停用
    print("  输入: 所有版本均停用后尝试加密")
    expect_error(ErrorCode.NO_ACTIVE_VERSION, svc.encrypt, ADMIN, b"new-data")


# ---------- 2. 密文篡改 ----------

@pytest.mark.parametrize("field", ["ciphertext", "wrapped_dek", "nonce", "wrap_nonce", "version"])
def test_tampered_envelope_fails(field):
    svc = make_service()
    env = svc.encrypt(ADMIN, b"secret-payload")
    print(f"场景: 篡改字段 {field}")
    print(f"  输入: 原始信封 version={env.version}")

    if field == "version":
        tampered = replace(env, version=env.version + 1)
        # 版本号被改成不存在的版本 -> VERSION_NOT_FOUND
        expect_error(ErrorCode.VERSION_NOT_FOUND, svc.decrypt, ADMIN, tampered)
        # 版本号被改成另一个已存在版本 -> 解封认证失败
        svc.rotate(ADMIN, 2, os.urandom(32))
        tampered2 = replace(env, version=2)
        expect_error(ErrorCode.CIPHERTEXT_TAMPERED, svc.decrypt, ADMIN, tampered2)
        return

    raw = bytearray(getattr(env, field))
    raw[0] ^= 0xFF
    tampered = replace(env, **{field: bytes(raw)})
    expect_error(ErrorCode.CIPHERTEXT_TAMPERED, svc.decrypt, ADMIN, tampered)


def test_version_mismatch_with_expected_version():
    svc = make_service()
    env = svc.encrypt(ADMIN, b"data")
    print("场景: 显式期望版本校验")
    print(f"  输入: 信封 version={env.version}, 期望 version=99")
    expect_error(ErrorCode.VERSION_MISMATCH, svc.decrypt, ADMIN, env, 99)


def test_malformed_envelope_rejected():
    svc = make_service()
    print("场景: 信封结构损坏")
    bad = Envelope(version=1, wrapped_dek=b"", wrap_nonce=b"x", nonce=b"y", ciphertext=b"z")
    print(f"  输入: wrapped_dek 为空, envelope={bad}")
    expect_error(ErrorCode.MALFORMED_ENVELOPE, svc.decrypt, ADMIN, bad)


# ---------- 3. 版本回退与非法操作 ----------

def test_duplicate_register_rejected():
    svc = make_service()
    print("场景: 重复登记同一版本")
    print("  输入: 再次登记 version=1")
    expect_error(ErrorCode.DUPLICATE_VERSION, svc.keyring.register, 1, os.urandom(32))


def test_version_regression_rejected():
    svc = make_service()
    svc.rotate(ADMIN, 5, os.urandom(32))
    print("场景: 版本回退")
    print("  输入: 当前最大版本=5, 登记 version=3")
    expect_error(ErrorCode.VERSION_REGRESSION, svc.keyring.register, 3, os.urandom(32))


def test_operations_on_disabled_version_rejected():
    svc = make_service()
    svc.rotate(ADMIN, 2, os.urandom(32))  # v1 已因轮换转为 DISABLED
    print("场景: 对已停用版本的非法操作")
    print("  输入: 重复停用 v1")
    expect_error(ErrorCode.VERSION_NOT_ACTIVE, svc.deactivate, ADMIN, 1)
    print("  输入: 重新启用已停用的 v1")
    expect_error(ErrorCode.VERSION_NOT_ACTIVE, svc.keyring.activate, 1)


def test_unknown_version_rejected():
    svc = make_service()
    print("场景: 操作不存在的版本")
    print("  输入: 停用 version=42")
    expect_error(ErrorCode.VERSION_NOT_FOUND, svc.deactivate, ADMIN, 42)


# ---------- 4. 并发轮换与写入 ----------

def test_concurrent_rotation_and_encryption():
    svc = make_service()
    print("场景: 并发轮换与写入")
    n_threads, n_rounds = 8, 50
    errors: list[BaseException] = []
    envelopes: list[Envelope] = []
    lock = threading.Lock()

    def writer(tid: int):
        for i in range(n_rounds):
            try:
                env = svc.encrypt(ADMIN, f"t{tid}-m{i}".encode())
                with lock:
                    envelopes.append(env)
            except KeyManagementError as exc:
                # 轮换间隙允许 NO_ACTIVE_VERSION 之外的失败都算缺陷
                with lock:
                    errors.append(exc)

    def rotator():
        for v in range(2, 2 + n_rounds):
            try:
                svc.rotate(ADMIN, v, os.urandom(32))
            except KeyManagementError as exc:
                with lock:
                    errors.append(exc)

    threads = [threading.Thread(target=writer, args=(t,)) for t in range(n_threads)]
    threads.append(threading.Thread(target=rotator))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    versions = {e.version for e in envelopes}
    print(f"  输入: {n_threads} 个写入线程 x {n_rounds} 次, 1 个轮换线程轮换 {n_rounds} 次")
    print(f"  判定依据: 写入错误数={len(errors)}, 信封版本分布={sorted(versions)}")
    assert not errors, f"并发期间出现错误: {errors[:3]}"

    # 每个信封都必须能用其记录的版本完整解密（无半截状态）
    for env in envelopes:
        assert svc.decrypt(ADMIN, env)

    # 所有信封的版本在加密当时都是 ACTIVE：版本号必然落在已轮换范围内
    assert versions and min(versions) >= 1


# ---------- 5. 越权 ----------

def test_permission_denied_cases():
    svc = make_service()
    print("场景: 越权调用")
    print("  输入: WRITER(仅 ENCRYPT) 执行解密")
    env = svc.encrypt(WRITER, b"data")
    expect_error(ErrorCode.PERMISSION_DENIED, svc.decrypt, WRITER, env)

    print("  输入: READER(仅 DECRYPT) 执行轮换")
    expect_error(ErrorCode.PERMISSION_DENIED, svc.rotate, READER, 9, os.urandom(32))

    print("  输入: READER(仅 DECRYPT) 执行停用")
    expect_error(ErrorCode.PERMISSION_DENIED, svc.deactivate, READER, 1)

    print("  输入: READER(仅 DECRYPT) 执行加密")
    expect_error(ErrorCode.PERMISSION_DENIED, svc.encrypt, READER, b"x")

    # 有权限的调用方正常工作
    assert svc.decrypt(READER, env) == b"data"
