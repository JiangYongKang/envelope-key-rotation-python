"""HTTP 层身份校验测试：401/403 状态与"客户端自报无效"。

使用 FastAPI TestClient 直接打本地应用；每个用例打印输入与判定依据。
"""

from __future__ import annotations

import base64
import os

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)

ADMIN = {"X-Caller-Token": "admin-token"}
READER = {"X-Caller-Token": "reader-token"}


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _ensure_key():
    """保证服务里有一个 ACTIVE 版本（模块级服务在用例间共享）。"""
    r = client.get("/")
    if r.json()["active"] is None:
        r = client.post(
            "/keys/rotate",
            json={"version": 1, "material_b64": _b64e(os.urandom(32))},
            headers=ADMIN,
        )
        assert r.status_code in (200, 201), r.text


def test_unrecognized_identity_is_401():
    _ensure_key()
    print("场景: 身份不被服务端识别 -> 401")
    print("  输入: 无令牌")
    r = client.post("/encrypt", json={"plaintext_b64": _b64e(b"x")})
    print(f"  判定依据: status={r.status_code}, body={r.json()}")
    assert r.status_code == 401
    assert r.json()["code"] == "UNAUTHENTICATED"

    print("  输入: 伪造令牌 forged-token")
    r = client.post(
        "/encrypt",
        json={"plaintext_b64": _b64e(b"x")},
        headers={"X-Caller-Token": "forged-token"},
    )
    print(f"  判定依据: status={r.status_code}, body={r.json()}")
    assert r.status_code == 401


def test_insufficient_permission_is_403():
    _ensure_key()
    print("场景: 身份合法但权限不够 -> 403")
    print("  输入: reader-token（仅 DECRYPT）执行加密")
    r = client.post("/encrypt", json={"plaintext_b64": _b64e(b"x")}, headers=READER)
    print(f"  判定依据: status={r.status_code}, body={r.json()}")
    assert r.status_code == 403
    assert r.json()["code"] == "PERMISSION_DENIED"


def test_client_cannot_stuff_permissions_in_request():
    _ensure_key()
    print("场景: 客户端在请求里塞权限声明也不能提权")
    print("  输入: reader-token + 自报头 X-Caller-Permissions: ENCRYPT,ROTATE,DEACTIVATE,RETIRE")
    r = client.post(
        "/encrypt",
        json={"plaintext_b64": _b64e(b"x")},
        headers={**READER, "X-Caller-Permissions": "ENCRYPT,ROTATE,DEACTIVATE,RETIRE"},
    )
    print(f"  判定依据: status={r.status_code}（自报头被忽略，仍 403）")
    assert r.status_code == 403

    print("  输入: 无令牌但自报 X-Caller-Name: admin")
    r = client.post(
        "/encrypt",
        json={"plaintext_b64": _b64e(b"x")},
        headers={"X-Caller-Name": "admin", "X-Caller-Permissions": "ENCRYPT"},
    )
    print(f"  判定依据: status={r.status_code}（自报身份不被识别，仍 401）")
    assert r.status_code == 401


def test_legit_identity_still_works():
    _ensure_key()
    print("场景: 合法身份按服务端认定的权限正常工作")
    r = client.post("/encrypt", json={"plaintext_b64": _b64e(b"hello")}, headers=ADMIN)
    print(f"  判定依据: 加密 status={r.status_code}")
    assert r.status_code == 200
    env = r.json()
    assert env["record_id"] is not None  # 加密产出已登记台账

    r = client.post("/decrypt", json=env, headers=READER)
    print(f"  判定依据: reader 解密 status={r.status_code}")
    assert r.status_code == 200
    assert base64.b64decode(r.json()["plaintext_b64"]) == b"hello"

    print("  输入: 查询当前版本统计")
    r = client.get(f"/keys/{env['version']}/stats", headers=READER)
    print(f"  判定依据: stats status={r.status_code}, body={r.json()}")
    assert r.status_code == 200
    assert r.json()["encrypt_count"] >= 1


def test_retire_and_reencrypt_over_http():
    """端到端：轮换 -> 批量重加密 -> 退役 -> 退役版本解密被拒。"""
    _ensure_key()
    print("场景: HTTP 端到端退役流程")
    r = client.get("/")
    current = r.json()["active"]
    v_old, v_new = current, current + 1

    r = client.post("/encrypt", json={"plaintext_b64": _b64e(b"e2e-data")}, headers=ADMIN)
    env = r.json()
    print(f"  输入: 在 v{v_old} 下加密一条记录 record_id={env['record_id']}")

    r = client.post(
        "/keys/rotate",
        json={"version": v_new, "material_b64": _b64e(os.urandom(32))},
        headers=ADMIN,
    )
    assert r.status_code in (200, 201), r.text

    print(f"  输入: 未迁走密文前退役 v{v_old}")
    r = client.post(f"/keys/{v_old}/retire", headers=ADMIN)
    print(f"  判定依据: status={r.status_code}, code={r.json()['code']}")
    assert r.status_code == 400
    assert r.json()["code"] == "VERSION_IN_USE"

    # 共享服务里可能还有前序用例留在 v_old 的记录，一并迁移（退役要求该版本完全无在册密文）
    import main as main_module

    ids = [
        rid
        for rid, e in main_module.service.store.snapshot().items()
        if e.version == v_old
    ]
    print(f"  输入: 批量重加密 v{v_old} 的全部在册记录 {ids} 到 v{v_new}")
    r = client.post(
        "/reencrypt",
        json={"record_ids": ids, "target_version": v_new},
        headers=ADMIN,
    )
    print(f"  判定依据: status={r.status_code}, body={r.json()}")
    assert r.status_code == 200
    assert r.json()["migrated"] == len(ids)
    assert "plaintext" not in r.text  # 响应不暴露明文

    print(f"  输入: 迁空后退役 v{v_old}")
    r = client.post(f"/keys/{v_old}/retire", headers=ADMIN)
    assert r.status_code == 200, r.text

    print(f"  输入: 解密指向已退役 v{v_old} 的旧信封")
    r = client.post("/decrypt", json=env, headers=ADMIN)
    print(f"  判定依据: status={r.status_code}, code={r.json()['code']}")
    assert r.status_code == 400
    assert r.json()["code"] == "VERSION_RETIRED"
