"""pytest 公共配置：打开测试日志，保证单测日志里能看到输入和判定依据。"""

import logging
import os

import pytest

from app.service import Caller, EnvelopeService, Permission


@pytest.fixture()
def svc() -> EnvelopeService:
    service = EnvelopeService()
    # 直接用带全部权限的 bootstrap 身份生成首个版本
    boot = Caller("bootstrap", frozenset(Permission))
    service.rotate(boot)
    return service


@pytest.fixture()
def admin() -> Caller:
    return Caller("admin", frozenset(Permission))


@pytest.fixture()
def writer() -> Caller:
    return Caller("writer", frozenset({Permission.ENCRYPT}))


@pytest.fixture()
def reader() -> Caller:
    return Caller("reader", frozenset({Permission.DECRYPT}))


@pytest.fixture()
def unprivileged() -> Caller:
    return Caller("nobody", frozenset())


def pytest_configure(config):
    level = logging.DEBUG if os.getenv("TEST_DEBUG") else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        force=True,
    )
