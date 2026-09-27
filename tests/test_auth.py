"""场景五：越权请求被挡下，原因统一为 PERMISSION_DENIED。"""

import logging

import pytest

from app.errors import ErrorReason, KeyManagementError
from app.service import Permission

logger = logging.getLogger(__name__)


def test_writer_cannot_rotate_or_disable(svc, writer):
    logger.info("输入: 仅 ENCRYPT 的 writer 请求 rotate/disable")
    for action in (lambda: svc.rotate(writer), lambda: svc.disable(writer, 1)):
        with pytest.raises(KeyManagementError) as exc:
            action()
        assert exc.value.reason is ErrorReason.PERMISSION_DENIED
        logger.info("判定: 被拒绝 reason=%s", exc.value.reason.value)


def test_reader_can_only_decrypt(svc, reader, writer):
    env = svc.encrypt(writer, b"acl-check")
    assert svc.decrypt(reader, env) == b"acl-check"
    logger.info("输入: reader 尝试加密/轮换/停用")
    for action in (
        lambda: svc.encrypt(reader, b"x"),
        lambda: svc.rotate(reader),
        lambda: svc.disable(reader, 1),
    ):
        with pytest.raises(KeyManagementError) as exc:
            action()
        assert exc.value.reason is ErrorReason.PERMISSION_DENIED
    logger.info("判定: reader 的写操作全部被 reason=%s 挡下",
                ErrorReason.PERMISSION_DENIED.value)


def test_unprivileged_blocked_everywhere(svc, unprivileged):
    for perm_name, action in (
        ("ENCRYPT", lambda: svc.encrypt(unprivileged, b"x")),
        ("DECRYPT", lambda: svc.decrypt(unprivileged, None)),
        ("ROTATE", lambda: svc.rotate(unprivileged)),
        ("DISABLE", lambda: svc.disable(unprivileged, 1)),
    ):
        logger.info("输入: 无任何权限的调用方请求 %s", perm_name)
        with pytest.raises(KeyManagementError) as exc:
            action()
        assert exc.value.reason is ErrorReason.PERMISSION_DENIED
    assert Permission.ROTATE.value == "ROTATE"
    logger.info("判定: 四类操作对无权限调用方全部拒绝")
