"""运维能力测试：身份校验、退役生命周期、使用统计、批量重加密及其并发。

每个用例都打印输入与判定依据（pytest -s 可见），失败原因按 ErrorCode 区分；
并发用例用 Event 做确定性同步，不使用固定 sleep。
"""

from __future__ import annotations

import os
import threading

import pytest
from fastapi.testclient import TestClient

from app.auth import Caller, IdentityRegistry, Permission
from app.errors import ErrorCode, KeyManagementError
from app.models import KeyState
from app.service import EnvelopeCryptoService
from main import app

ADMIN = Caller("admin", frozenset(Permission))  # 全权限


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


# ---------- 1. 调用方身份校验（服务端解析） ----------

def make_registry() -> IdentityRegistry:
    registry = IdentityRegistry()
    registry.register("admin-token", "admin", frozenset(Permission))
    registry.register("writer-token", "writer", frozenset({Permission.ENCRYPT}))
    registry.register("reader-token", "reader", frozenset({Permission.DECRYPT}))
    return registry


def test_unknown_token_rejected():
    registry = make_registry()
    print("场景: 身份未被服务端识别")
    print("  输入: token=None")
    expect_error(ErrorCode.UNAUTHENTICATED, registry.authenticate, None)
    print("  输入: token='forged-token'（未登记）")
    expect_error(ErrorCode.UNAUTHENTICATED, registry.authenticate, "forged-token")


def test_authenticated_identity_permissions_are_server_side():
    registry = make_registry()
    print("场景: 权限以服务端登记为准")
    writer = registry.authenticate("writer-token")
    print(f"  输入: writer-token 解析结果 permissions={sorted(p.value for p in writer.permissions)}")
    assert writer.permissions == frozenset({Permission.ENCRYPT})

    svc = make_service()
    env = svc.encrypt(writer, b"data")
    print("  输入: writer（仅 ENCRYPT）尝试解密")
    expect_error(ErrorCode.PERMISSION_DENIED, svc.decrypt, writer, env)


def test_client_cannot_self_grant_permissions():
    """客户端能给的只有 token；权限集合由服务端固定解析，无注入入口。"""
    registry = make_registry()
    print("场景: 合法身份也无法自我提权")
    reader = registry.authenticate("reader-token")
    svc = make_service()
    print("  输入: reader（仅 DECRYPT）尝试轮换/停用/退役/重加密")
    expect_error(ErrorCode.PERMISSION_DENIED, svc.rotate, reader, 9, os.urandom(32))
    expect_error(ErrorCode.PERMISSION_DENIED, svc.deactivate, reader, 1)
    expect_error(ErrorCode.PERMISSION_DENIED, svc.retire, reader, 1)
    expect_error(ErrorCode.PERMISSION_DENIED, svc.reencrypt_records, reader, [], 1)
    print("  判定依据: authenticate 只接受 token，调用方无法传入权限声明")


# ---------- 2. HTTP 状态：401 / 403 ----------

def test_http_identity_and_permission_status():
    client = TestClient(app)
    print("场景: HTTP 层的身份与权限状态码")
    material = {"version": 1000, "material_b64": __import__("base64").b64encode(os.urandom(32)).decode()}

    print("  输入: 不带 token 调用 /encrypt")
    r = client.post("/encrypt", json={"plaintext_b64": "eA=="})
    print(f"  判定依据: 状态码={r.status_code}, body={r.json()}")
    assert r.status_code == 401
    assert r.json()["code"] == "UNAUTHENTICATED"

    print("  输入: 伪造 token 调用 /encrypt")
    r = client.post("/encrypt", json={"plaintext_b64": "eA=="}, headers={"X-Caller-Token": "forged"})
    print(f"  判定依据: 状态码={r.status_code}, body={r.json()}")
    assert r.status_code == 401

    admin = {"X-Caller-Token": "dev-admin-token"}
    r = client.post("/keys/rotate", json=material, headers=admin)
    assert r.status_code == 201, r.text

    print("  输入: reader（仅 DECRYPT）调用 /encrypt")
    r = client.post("/encrypt", json={"plaintext_b64": "eA=="}, headers={"X-Caller-Token": "dev-reader-token"})
    print(f"  判定依据: 状态码={r.status_code}, body={r.json()}")
    assert r.status_code == 403
    assert r.json()["code"] == "PERMISSION_DENIED"

    print("  输入: reader 同时在请求里自报全权限头，尝试轮换（自我提权）")
    r = client.post(
        "/keys/rotate",
        json={"version": 1001, "material_b64": material["material_b64"]},
        headers={
            "X-Caller-Token": "dev-reader-token",
            "X-Caller-Permissions": "ENCRYPT,DECRYPT,ROTATE,DEACTIVATE,RETIRE,REENCRYPT",
            "X-Caller-Name": "admin",
        },
    )
    print(f"  判定依据: 状态码={r.status_code}, body={r.json()}（自报头被忽略）")
    assert r.status_code == 403

    print("  输入: writer（仅 ENCRYPT）加密后由 reader 解密，验证兼容行为")
    r = client.post("/encrypt", json={"plaintext_b64": "aGVsbG8="}, headers={"X-Caller-Token": "dev-writer-token"})
    assert r.status_code == 200, r.text
    r = client.post("/decrypt", json=r.json(), headers={"X-Caller-Token": "dev-reader-token"})
    print(f"  判定依据: 解密状态码={r.status_code}, 明文={r.json()}")
    assert r.status_code == 200
    assert r.json()["plaintext_b64"] == "aGVsbG8="


# ---------- 3. 版本使用统计 ----------

def test_usage_stats_per_version():
    svc = make_service()
    print("场景: 按版本统计加密/解密次数与最后使用时间")
    env1 = svc.encrypt(ADMIN, b"a")
    svc.encrypt(ADMIN, b"b")
    svc.decrypt(ADMIN, env1)
    stats1 = svc.usage(ADMIN, 1)
    print("  输入: v1 加密 2 次、解密 1 次")
    print(f"  判定依据: v1 encrypt_count={stats1.encrypt_count}, "
          f"decrypt_count={stats1.decrypt_count}, last_used_at={stats1.last_used_at}")
    assert stats1.encrypt_count == 2
    assert stats1.decrypt_count == 1
    assert stats1.last_used_at is not None

    svc.rotate(ADMIN, 2, os.urandom(32))
    stats2 = svc.usage(ADMIN, 2)
    print(f"  判定依据: v2 未使用 encrypt_count={stats2.encrypt_count}, last_used_at={stats2.last_used_at}")
    assert stats2.encrypt_count == 0
    assert stats2.decrypt_count == 0
    assert stats2.last_used_at is None

    print("  输入: 查询不存在版本的统计")
    expect_error(ErrorCode.VERSION_NOT_FOUND, svc.usage, ADMIN, 42)


# ---------- 4. 退役生命周期 ----------

def test_retire_requires_disabled_and_existing():
    svc = make_service()
    print("场景: 退役的前置条件")
    print("  输入: 退役不存在的版本 42")
    expect_error(ErrorCode.VERSION_NOT_FOUND, svc.retire, ADMIN, 42)
    print("  输入: 退役仍 ACTIVE 的 v1")
    expect_error(ErrorCode.VERSION_NOT_ACTIVE, svc.retire, ADMIN, 1)
    svc.keyring.register(2, os.urandom(32))
    print("  输入: 退役仍 PENDING 的 v2")
    expect_error(ErrorCode.VERSION_NOT_ACTIVE, svc.retire, ADMIN, 2)


def test_retire_rejected_while_records_in_use():
    svc = make_service()
    svc.store_record(ADMIN, "r1", b"payload-1")
    svc.rotate(ADMIN, 2, os.urandom(32))  # v1 自动 DISABLED，但 r1 仍引用 v1
    print("场景: 仍有历史密文引用的版本拒绝退役")
    print("  输入: v1 已停用，记录 r1 仍引用 v1，执行退役")
    expect_error(ErrorCode.VERSION_IN_USE, svc.retire, ADMIN, 1)
    print(f"  判定依据: v1 状态={svc.keyring.get(1).state.value}（退役被拒后保持 DISABLED）")
    assert svc.keyring.get(1).state is KeyState.DISABLED


def test_retired_version_is_terminal_and_decrypt_fails():
    svc = make_service()
    env = svc.encrypt(ADMIN, b"legacy")
    svc.rotate(ADMIN, 2, os.urandom(32))  # v1 DISABLED，env 未入库，无引用
    svc.retire(ADMIN, 1)
    print("场景: 退役是终态，退役后解密明确失败")
    print(f"  判定依据: v1 状态={svc.keyring.get(1).state.value}")
    assert svc.keyring.get(1).state is KeyState.RETIRED

    print("  输入: 解密引用了已退役 v1 的信封")
    expect_error(ErrorCode.VERSION_RETIRED, svc.decrypt, ADMIN, env)
    print("  输入: 解密引用不存在版本 99 的信封（对照组）")
    from dataclasses import replace
    expect_error(ErrorCode.VERSION_NOT_FOUND, svc.decrypt, ADMIN, replace(env, version=99))

    print("  输入: 重新启用已退役的 v1")
    expect_error(ErrorCode.VERSION_RETIRED, svc.keyring.activate, 1)
    print("  输入: 重复退役 v1")
    expect_error(ErrorCode.VERSION_RETIRED, svc.retire, ADMIN, 1)
    print("  输入: 停用已退役的 v1")
    expect_error(ErrorCode.VERSION_RETIRED, svc.deactivate, ADMIN, 1)

    print("  输入: 对照——已停用未退役的 v2 停用后历史密文仍可解密")
    env2 = svc.encrypt(ADMIN, b"still-readable")
    svc.deactivate(ADMIN, 2)
    assert svc.decrypt(ADMIN, env2) == b"still-readable"


# ---------- 5. 批量重加密 ----------

def test_reencrypt_records_roundtrip():
    svc = make_service()
    payloads = {f"r{i}": f"payload-{i}".encode() for i in range(5)}
    for rid, data in payloads.items():
        svc.store_record(ADMIN, rid, data)
    svc.rotate(ADMIN, 2, os.urandom(32))
    print("场景: 批量重加密到目标版本")
    print(f"  输入: 记录={sorted(payloads)}（均在 v1），目标版本=2")

    count = svc.reencrypt_records(ADMIN, sorted(payloads), 2)
    print(f"  判定依据: 返回值={count}（仅条数，不含明文）")
    assert count == 5
    assert isinstance(count, int)

    for rid, data in payloads.items():
        env = svc.records.get(rid)
        back = svc.read_record(ADMIN, rid)
        print(f"  判定依据: {rid} 版本={env.version}, 内容一致={back == data}")
        assert env.version == 2
        assert back == data

    stats1, stats2 = svc.usage(ADMIN, 1), svc.usage(ADMIN, 2)
    print(f"  判定依据: v1 decrypt_count={stats1.decrypt_count}, v2 encrypt_count={stats2.encrypt_count}")
    assert stats1.decrypt_count == 5
    assert stats2.encrypt_count == 5


def test_reencrypt_target_must_be_active():
    svc = make_service()
    svc.store_record(ADMIN, "r1", b"data")
    svc.keyring.register(2, os.urandom(32))  # PENDING
    print("场景: 重加密目标版本合法性")
    print("  输入: 目标版本=2（PENDING）")
    expect_error(ErrorCode.VERSION_NOT_ACTIVE, svc.reencrypt_records, ADMIN, ["r1"], 2)
    print("  输入: 目标版本=99（不存在）")
    expect_error(ErrorCode.VERSION_NOT_FOUND, svc.reencrypt_records, ADMIN, ["r1"], 99)

    svc.rotate(ADMIN, 3, os.urandom(32))  # v1 DISABLED
    print("  输入: 目标版本=1（DISABLED，且为源版本）")
    expect_error(ErrorCode.VERSION_NOT_ACTIVE, svc.reencrypt_records, ADMIN, ["r1"], 1)


def test_reencrypt_atomic_on_failure_and_retry():
    svc = make_service()
    for rid in ("r1", "r2"):
        svc.store_record(ADMIN, rid, f"data-{rid}".encode())
    svc.rotate(ADMIN, 2, os.urandom(32))
    print("场景: 整批失败不留半截结果，重试从干净状态开始")
    print("  输入: 批量=[r1, r2, ghost]，其中 ghost 不存在")
    expect_error(ErrorCode.RECORD_NOT_FOUND, svc.reencrypt_records, ADMIN, ["r1", "r2", "ghost"], 2)

    for rid in ("r1", "r2"):
        env = svc.records.get(rid)
        print(f"  判定依据: 失败后 {rid} 版本={env.version}（应保持 v1，未迁一半）")
        assert env.version == 1
        assert svc.read_record(ADMIN, rid) == f"data-{rid}".encode()

    print("  输入: 修正批量=[r1, r2] 后重试")
    assert svc.reencrypt_records(ADMIN, ["r1", "r2"], 2) == 2
    for rid in ("r1", "r2"):
        assert svc.records.get(rid).version == 2
        assert svc.read_record(ADMIN, rid) == f"data-{rid}".encode()
    print("  判定依据: 重试后全部迁到 v2，内容一致")


# ---------- 6. 批量重加密与退役的并发（确定性） ----------

class _HookedService(EnvelopeCryptoService):
    """在重加密循环中提供同步点：批处理持锁中途挂起，直到测试放行。"""

    def __init__(self) -> None:
        super().__init__()
        self.mid_batch = threading.Event()
        self.release_batch = threading.Event()

    def _reencrypt_hook(self, record_id: str) -> None:
        self.mid_batch.set()
        assert self.release_batch.wait(timeout=10), "测试同步超时"


def test_reencrypt_and_retire_are_mutually_exclusive():
    svc = _HookedService()
    svc.keyring.rotate(1, os.urandom(32))
    payloads = {f"r{i}": f"payload-{i}".encode() for i in range(3)}
    for rid, data in payloads.items():
        svc.store_record(ADMIN, rid, data)
    svc.rotate(ADMIN, 2, os.urandom(32))  # v1 DISABLED，记录仍在 v1
    print("场景: 批量重加密进行中，退役不得穿插")
    print(f"  输入: 记录={sorted(payloads)} 迁往 v2，同时另一线程退役 v1")

    order: list[str] = []
    retire_attempted = threading.Event()
    retire_outcome: dict[str, object] = {}

    def do_batch() -> None:
        svc.reencrypt_records(ADMIN, sorted(payloads), 2)
        order.append("batch_done")

    def do_retire() -> None:
        # 确定性探针：批处理保证持锁期间，锁一定抢不到（互斥的直接证据）
        locked_by_batch = not svc.keyring.lock.acquire(blocking=False)
        if not locked_by_batch:
            svc.keyring.lock.release()
        retire_outcome["locked_during_batch"] = locked_by_batch
        order.append("retire_attempt")
        retire_attempted.set()
        try:
            svc.retire(ADMIN, 1)
            retire_outcome["result"] = "ok"
        except KeyManagementError as exc:
            retire_outcome["result"] = exc.code
        order.append("retire_done")

    t_batch = threading.Thread(target=do_batch)
    t_batch.start()
    assert svc.mid_batch.wait(timeout=10), "批处理未进入持锁中途点"

    t_retire = threading.Thread(target=do_retire)
    t_retire.start()
    # 等退役线程完成探针并抵达锁等待点（事件同步，不用固定 sleep）
    assert retire_attempted.wait(timeout=10), "退役线程未抵达锁等待点"
    print(f"  判定依据: 批处理持锁期间锁不可抢占={retire_outcome['locked_during_batch']}")
    assert retire_outcome["locked_during_batch"] is True

    svc.release_batch.set()
    t_batch.join(timeout=10)
    t_retire.join(timeout=10)
    assert not t_batch.is_alive() and not t_retire.is_alive()

    print(f"  判定依据: 执行顺序={order}, 退役结果={retire_outcome['result']}")
    assert order.index("batch_done") < order.index("retire_done")
    # 批处理完成后 v1 已无引用，退役必须成功；批处理也绝不应因源版本退役而失败
    assert retire_outcome["result"] == "ok"
    assert svc.keyring.get(1).state is KeyState.RETIRED

    for rid, data in payloads.items():
        env = svc.records.get(rid)
        assert env.version == 2, f"{rid} 仍停留在 v{env.version}"
        assert svc.read_record(ADMIN, rid) == data
    print("  判定依据: 全部记录已迁到 v2 且内容一致，v1 已退役，无半截状态")


def test_retire_first_then_reencrypt_then_retire():
    """相反的确定顺序：记录仍引用时退役被拒，迁移完成后退役放行。"""
    svc = make_service()
    svc.store_record(ADMIN, "r1", b"data-1")
    svc.rotate(ADMIN, 2, os.urandom(32))
    print("场景: 先退役（被拒）-> 重加密 -> 再退役（放行）")
    print("  输入: r1 仍引用 v1 时退役 v1")
    expect_error(ErrorCode.VERSION_IN_USE, svc.retire, ADMIN, 1)

    print("  输入: 把 r1 迁往 v2")
    assert svc.reencrypt_records(ADMIN, ["r1"], 2) == 1

    print("  输入: 再次退役 v1")
    svc.retire(ADMIN, 1)
    print(f"  判定依据: v1 状态={svc.keyring.get(1).state.value}")
    assert svc.keyring.get(1).state is KeyState.RETIRED
    assert svc.read_record(ADMIN, "r1") == b"data-1"
