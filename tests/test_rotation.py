"""场景一：轮换前后解密；场景二：版本回退与重复登记被拒绝。"""

import logging

from app.errors import ErrorReason, KeyManagementError
from app.keystore import KeyStore

logger = logging.getLogger(__name__)


def test_decrypt_before_and_after_rotation(svc, admin, writer, reader):
    # 输入：用 v1 加密一条历史数据
    v1 = svc.keystore.latest_active()
    old_env = svc.encrypt(writer, b"history-record")
    logger.info("输入: 明文=%r, 加密版本=v%s", b"history-record", old_env.key_version)
    assert old_env.key_version == v1.version

    # 动作：轮换到 v2
    v2 = svc.rotate(admin)
    logger.info("动作: rotate -> v%s", v2.version)
    new_env = svc.encrypt(writer, b"fresh-record")
    assert new_env.key_version == v2.version

    # 判定依据：密文固定关联加密时版本，两版本都能解密
    assert svc.decrypt(reader, old_env) == b"history-record", "轮换后历史数据必须仍可解密"
    assert svc.decrypt(reader, new_env) == b"fresh-record"
    logger.info("判定: v%s 密文解出 %r；v%s 密文解出 %r -> 兼容历史数据",
                old_env.key_version, svc.decrypt(reader, old_env),
                new_env.key_version, b"fresh-record")


def test_duplicate_registration_rejected():
    ks = KeyStore()
    ks.register_version(1, b"a" * 32)
    logger.info("输入: 已登记 v1，再次登记同一版本号")
    try:
        ks.register_version(1, b"b" * 32)
    except KeyManagementError as e:
        logger.info("判定: reason=%s", e.reason.value)
        assert e.reason is ErrorReason.DUPLICATE_VERSION
    else:
        raise AssertionError("重复登记必须被拒绝")


def test_version_rollback_rejected():
    ks = KeyStore()
    ks.register_version(3, b"a" * 32)
    logger.info("输入: 当前最大版本 v3，尝试登记 v2")
    for bad_version in (2, 3):
        try:
            ks.register_version(bad_version, b"b" * 32)
        except KeyManagementError as e:
            logger.info("判定: 登记 v%s 被拒绝, reason=%s", bad_version, e.reason.value)
            # v3 重复登记与 v2 回退必须能区分开
            expected = ErrorReason.DUPLICATE_VERSION if bad_version == 3 else ErrorReason.VERSION_ROLLBACK
            assert e.reason is expected
        else:
            raise AssertionError(f"v{bad_version} 登记必须被拒绝")


def test_disabled_version_illegal_ops(svc, admin):
    v1 = svc.keystore.latest_active()
    logger.info("输入: 停用 v%s 后重复停用/重新启用", v1.version)
    svc.disable(admin, v1.version)
    for op, expected_reason in (
        (lambda: svc.disable(admin, v1.version), ErrorReason.KEY_DISABLED),
        (lambda: svc.keystore.activate(v1.version), ErrorReason.KEY_DISABLED),
    ):
        try:
            op()
        except KeyManagementError as e:
            logger.info("判定: 对停用版本的操作被拒绝, reason=%s", e.reason.value)
            assert e.reason is expected_reason
        else:
            raise AssertionError("对已停用版本的非法操作必须被拒绝")


def test_disabled_version_still_decrypts_but_not_encrypts(svc, admin, writer, reader):
    v1 = svc.keystore.latest_active()
    env = svc.encrypt(writer, b"old-but-readable")
    svc.rotate(admin)  # v2 接管加密
    svc.disable(admin, v1.version)
    logger.info("输入: v%s 已停用；其历史密文仍尝试解密", v1.version)

    # 判定依据：停用只禁止加密新数据，历史解密仍可用
    assert svc.decrypt(reader, env) == b"old-but-readable"
    # 当前生效版本是 v2，新加密绝不会落到 v1
    new_env = svc.encrypt(writer, b"new")
    assert new_env.key_version != v1.version
    logger.info("判定: 停用 v%s 历史解密成功，新加密落在 v%s", v1.version, new_env.key_version)
