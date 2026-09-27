"""HTTP 层端到端：鉴权、轮换兼容、篡改与错误原因码。"""

import base64
import logging

import pytest
from fastapi.testclient import TestClient

import main as main_module
from app.service import EnvelopeService, Caller, Permission

logger = logging.getLogger(__name__)


@pytest.fixture()
def client():
    # 每个用例使用全新服务（lifespan 启动时会自动登记 v1）
    main_module.service = EnvelopeService()
    with TestClient(main_module.app) as c:
        yield c


def _envelope(resp_json: dict) -> str:
    return resp_json["envelope"]


def test_full_flow_and_rotation_compatibility(client):
    # v1 加密
    r1 = client.post("/encrypt", json={"plaintext": "v1-data"}, headers={"X-Api-Key": "key-writer"})
    assert r1.status_code == 200
    assert r1.json()["key_version"] == 1
    env1 = _envelope(r1.json())
    logger.info("输入: v1 密文已生成 %s...", env1[:24])

    # 轮换
    rr = client.post("/keys/rotate", headers={"X-Api-Key": "key-admin"})
    assert rr.status_code == 200 and rr.json()["version"] == 2

    # v2 加密 + v1/v2 都能解
    r2 = client.post("/encrypt", json={"plaintext": "v2-data"}, headers={"X-Api-Key": "key-writer"})
    assert r2.json()["key_version"] == 2
    d1 = client.post("/decrypt", json={"envelope": env1}, headers={"X-Api-Key": "key-reader"})
    assert d1.json()["plaintext"] == "v1-data"
    logger.info("判定: 轮换后 HTTP 解密 v1 历史数据成功: %r", d1.json()["plaintext"])


def test_http_authorization_enforced(client):
    logger.info("输入: 无凭证与越权凭证请求敏感接口")
    assert client.post("/keys/rotate").status_code == 401
    denied = client.post("/keys/rotate", headers={"X-Api-Key": "key-reader"})
    assert denied.status_code == 403
    enc_denied = client.post(
        "/encrypt", json={"plaintext": "x"}, headers={"X-Api-Key": "key-reader"}
    )
    assert enc_denied.status_code == 403
    dec_denied = client.post(
        "/decrypt", json={"envelope": ""}, headers={"X-Api-Key": "key-writer"}
    )
    assert dec_denied.status_code == 403
    logger.info("判定: 401/403 按预期返回，越权请求未进入业务逻辑")


def test_http_tampered_ciphertext_reason(client):
    env = _envelope(
        client.post("/encrypt", json={"plaintext": "tamper-me"},
                    headers={"X-Api-Key": "key-writer"}).json()
    )
    raw = bytearray(base64.b64decode(env))
    raw[-5] ^= 0xFF  # 翻转 HMAC 标签字节
    tampered = base64.b64encode(bytes(raw)).decode()
    logger.info("输入: 翻转信封末段 1 字节后提交解密")
    resp = client.post("/decrypt", json={"envelope": tampered},
                       headers={"X-Api-Key": "key-reader"})
    assert resp.status_code == 400
    assert resp.json()["error"] == "TAMPERED_CIPHERTEXT"
    logger.info("判定: HTTP 返回可区分原因码 %s", resp.json()["error"])


def test_http_disable_conflict_reasons(client):
    # 停用 v1 后再次停用 -> 409 KEY_DISABLED
    client.post("/keys/1/disable", headers={"X-Api-Key": "key-admin"})
    resp = client.post("/keys/1/disable", headers={"X-Api-Key": "key-admin"})
    assert resp.status_code == 409 and resp.json()["error"] == "KEY_DISABLED"
    logger.info("判定: 重复停用 -> 409 %s", resp.json()["error"])

    # 不存在版本 -> 404 KEY_NOT_FOUND
    resp = client.post("/keys/99/disable", headers={"X-Api-Key": "key-admin"})
    assert resp.status_code == 404 and resp.json()["error"] == "KEY_NOT_FOUND"
    logger.info("判定: 停用不存在版本 -> 404 %s", resp.json()["error"])


def test_http_keys_listing(client):
    resp = client.get("/keys", headers={"X-Api-Key": "key-all"})
    assert resp.status_code == 200
    assert resp.json()["latest_active"] == 1
    logger.info("判定: 启动后自动登记 v1: %s", resp.json())
