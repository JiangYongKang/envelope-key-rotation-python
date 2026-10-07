"""本轮新增行为测试：身份校验、版本退役、使用统计、批量重加密。

每个用例都打印输入与判定依据（pytest -s 可见），失败原因按 ErrorCode 区分；
并发用例使用事件/屏障做确定性同步，不依赖固定 sleep。
"""

from __future__ import annotations

import os
import threading

import pytest

from app.auth import Caller, IdentityRegistry, Permission
from app.errors import ErrorCode, KeyManagementError
from app.service import EnvelopeCryptoService

ALL_PERMS = frozenset(Permission)
ADMIN = Caller("admin", ALL_PERMS)


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


# ---------- 1. 调用方身份校验（服务端确认身份） ----------

def test_unrecognized_token_rejected():
    registry = IdentityRegistry()
    registry.provision("good-token", "admin", ALL_PERMS)
    print("场景: 身份不被服务端识别")
    print("  输入: 未在注册表中的令牌 'forged-token'")
    expect_error(ErrorCode.UNAUTHENTICATED, registry.authenticate, "forged-token")
    print("  输入: 空令牌")
    expect_error(ErrorCode.UNAUTHENTICATED, registry.authenticate, None)
    expect_error(ErrorCode.UNAUTHENTICATED, registry.authenticate, "")


def test_client_cannot_self_grant_permissions():
    """客户端无论怎么声明，权限都以服务端注册表为准。"""
    registry = IdentityRegistry()
    # 服务端只给 reader 预置了 DECRYPT 权限
    registry.provision("reader-token", "reader", frozenset({Permission.DECRYPT}))
    print("场景: 合法身份不能靠请求里塞的东西提权")
    caller = registry.authenticate("reader-token")
    print(f"  输入: 令牌 reader-token，服务端认定权限={sorted(p.value for p in caller.permissions)}")
    assert caller.permissions == frozenset({Permission.DECRYPT})

    svc = make_service()
    print("  输入: reader 尝试加密（自报多少权限都无效，服务端只认注册表）")
    expect_error(ErrorCode.PERMISSION_DENIED, svc.encrypt, caller, b"x")
    print("  输入: reader 尝试轮换")
    expect_error(ErrorCode.PERMISSION_DENIED, svc.rotate, caller, 9, os.urandom(32))
    print("  输入: reader 尝试退役")
    expect_error(ErrorCode.PERMISSION_DENIED, svc.retire, caller, 1)
    # 合法权限内操作正常
    env = svc.encrypt(ADMIN, b"data")
    assert svc.decrypt(caller, env) == b"data"
    print("  判定依据: reader 的 DECRYPT 权限内操作成功")


# ---------- 2. 版本使用统计 ----------

def test_version_usage_stats():
    svc = make_service()
    print("场景: 按版本查看使用统计")
    env1 = svc.encrypt(ADMIN, b"m1")
    svc.encrypt(ADMIN, b"m2")
    svc.decrypt(ADMIN, env1)
    stats = svc.version_stats(ADMIN, 1)
    print("  输入: v1 加密 2 次、解密 1 次后查询统计")
    print(f"  判定依据: stats={stats}")
    assert stats["version"] == 1
    assert stats["state"] == "ACTIVE"
    assert stats["encrypt_count"] == 2
    assert stats["decrypt_count"] == 1
    assert stats["last_used_at"] is not None

    svc.rotate(ADMIN, 2, os.urandom(32))
    env2 = svc.encrypt(ADMIN, b"m3")
    svc.decrypt(ADMIN, env2)
    stats1 = svc.version_stats(ADMIN, 1)
    stats2 = svc.version_stats(ADMIN, 2)
    print("  输入: 轮换到 v2 后 v2 加解密各 1 次")
    print(f"  判定依据: v1统计={stats1['encrypt_count']}/{stats1['decrypt_count']}, "
          f"v2统计={stats2['encrypt_count']}/{stats2['decrypt_count']}")
    assert stats1["encrypt_count"] == 2 and stats1["decrypt_count"] == 1
    assert stats2["encrypt_count"] == 1 and stats2["decrypt_count"] == 1
    assert stats2["last_used_at"] >= stats1["last_used_at"]


# ---------- 3. 退役生命周期 ----------

def test_retire_rejected_while_records_in_use():
    svc = make_service()
    print("场景: 仍在使用的版本拒绝退役")
    svc.encrypt(ADMIN, b"live-1")
    svc.encrypt(ADMIN, b"live-2")
    svc.rotate(ADMIN, 2, os.urandom(32))  # v1 转为 DISABLED
    print("  输入: v1 已停用，但台账中仍有 2 条 v1 密文")
    expect_error(ErrorCode.VERSION_IN_USE, svc.retire, ADMIN, 1)
    print(f"  判定依据: v1 在册密文数={svc.store.count_by_version(1)}")
    assert svc.keyring.get(1).state.value == "DISABLED"  # 拒绝退役后状态不变


def test_retire_requires_disabled_state():
    svc = make_service()
    print("场景: 未停用的版本不能退役")
    print("  输入: v1 处于 ACTIVE，直接退役")
    expect_error(ErrorCode.VERSION_NOT_DISABLED, svc.retire, ADMIN, 1)

    svc.keyring.register(2, os.urandom(32))  # PENDING
    print("  输入: v2 处于 PENDING，直接退役")
    expect_error(ErrorCode.VERSION_NOT_DISABLED, svc.retire, ADMIN, 2)

    print("  输入: 退役不存在的版本 42")
    expect_error(ErrorCode.VERSION_NOT_FOUND, svc.retire, ADMIN, 42)


def test_retire_success_then_terminal():
    svc = make_service()
    print("场景: 退役成功且为终态")
    svc.rotate(ADMIN, 2, os.urandom(32))  # v1 停用，且从未加密过数据
    print("  输入: v1 已停用且无在册密文，执行退役")
    svc.retire(ADMIN, 1)
    assert svc.keyring.get(1).state.value == "RETIRED"
    print("  判定依据: v1 状态=RETIRED")

    print("  输入: 重新启用已退役的 v1")
    expect_error(ErrorCode.VERSION_RETIRED, svc.keyring.activate, 1)
    print("  输入: 重复退役 v1")
    expect_error(ErrorCode.VERSION_RETIRED, svc.retire, ADMIN, 1)
    print("  输入: 停用已退役的 v1")
    expect_error(ErrorCode.VERSION_RETIRED, svc.deactivate, ADMIN, 1)


def test_decrypt_retired_version_fails_distinctly():
    svc = make_service()
    print("场景: 退役版本的解密失败原因可区分")
    env = svc.encrypt(ADMIN, b"classified")
    # 通过批量重加密迁走 v1 的全部密文，再退役 v1
    svc.rotate(ADMIN, 2, os.urandom(32))
    svc.reencrypt(ADMIN, [env.record_id], 2)
    svc.retire(ADMIN, 1)
    print(f"  输入: 解密版本指向已退役 v1 的信封（record_id={env.record_id}）")
    expect_error(ErrorCode.VERSION_RETIRED, svc.decrypt, ADMIN, env)

    from dataclasses import replace
    print("  输入: 解密指向不存在版本 99 的信封 -> VERSION_NOT_FOUND")
    expect_error(ErrorCode.VERSION_NOT_FOUND, svc.decrypt, ADMIN, replace(env, version=99))

    svc.deactivate(ADMIN, 2)
    env2 = svc.store.get(env.record_id)
    print("  输入: 解密指向已停用 v2 的信封 -> 正常解密（与退役区分）")
    assert svc.decrypt(ADMIN, env2) == b"classified"


# ---------- 4. 批量重加密 ----------

def _make_two_version_service(payloads: list[bytes]):
    """v1 下加密一批记录，随后轮换到 v2。返回 (svc, record_ids, envelopes)。"""
    svc = make_service()
    envelopes = [svc.encrypt(ADMIN, p) for p in payloads]
    svc.rotate(ADMIN, 2, os.urandom(32))
    return svc, [e.record_id for e in envelopes], envelopes


def test_batch_reencrypt_migrates_all_records():
    payloads = [f"record-{i}".encode() for i in range(5)]
    svc, ids, _ = _make_two_version_service(payloads)
    print("场景: 批量重加密迁移全部记录")
    print(f"  输入: record_ids={ids}, 源版本=v1, 目标版本=v2")

    result = svc.reencrypt(ADMIN, ids, 2)
    print(f"  判定依据: 返回={result}（不含明文）")
    assert result["migrated"] == 5
    assert result["target_version"] == 2
    assert "plaintext" not in result  # 返回值不暴露明文

    for rid, expect in zip(ids, payloads):
        env = svc.store.get(rid)
        assert env.version == 2, f"记录 {rid} 未迁到 v2"
        assert svc.decrypt(ADMIN, env) == expect  # 内容迁移前后完全一致
    print("  判定依据: 全部记录 version=2 且内容逐条一致")
    assert svc.store.count_by_version(1) == 0


def test_batch_reencrypt_is_atomic_on_failure():
    payloads = [b"a", b"b", b"c"]
    svc, ids, _ = _make_two_version_service(payloads)
    print("场景: 整批失败不留半截结果")
    bad_ids = [ids[0], 9999, ids[2]]
    print(f"  输入: record_ids={bad_ids}（含不存在的 9999）")
    expect_error(ErrorCode.RECORD_NOT_FOUND, svc.reencrypt, ADMIN, bad_ids, 2)

    print("  判定依据: 失败后所有记录仍停在 v1，无半截迁移")
    for rid in ids:
        assert svc.store.get(rid).version == 1
    assert svc.store.count_by_version(2) == 0

    print("  输入: 修正后用干净的状态重试")
    result = svc.reencrypt(ADMIN, ids, 2)
    assert result["migrated"] == 3
    for rid, expect in zip(ids, payloads):
        assert svc.decrypt(ADMIN, svc.store.get(rid)) == expect
    print("  判定依据: 重试成功，全部迁到 v2")


def test_reencrypt_target_must_be_active_and_not_retired():
    svc, ids, _ = _make_two_version_service([b"x"])
    print("场景: 重加密目标版本校验")
    svc.keyring.register(3, os.urandom(32))  # PENDING
    print("  输入: 目标 v3 处于 PENDING")
    expect_error(ErrorCode.VERSION_NOT_ACTIVE, svc.reencrypt, ADMIN, ids, 3)

    # 构造一个已退役版本：v3 先启用再停用再退役（无密文引用）
    svc.keyring.activate(3)   # v2 转 DISABLED，v3 ACTIVE
    svc.deactivate(ADMIN, 3)
    svc.retire(ADMIN, 3)
    print("  输入: 目标 v3 已退役")
    expect_error(ErrorCode.VERSION_RETIRED, svc.reencrypt, ADMIN, ids, 3)

    print("  输入: 目标 v2 已停用（非生效版本）")
    expect_error(ErrorCode.VERSION_NOT_ACTIVE, svc.reencrypt, ADMIN, ids, 2)


def test_reencrypt_requires_permission():
    svc, ids, _ = _make_two_version_service([b"x"])
    reader = Caller("reader", frozenset({Permission.DECRYPT}))
    print("场景: 重加密权限校验")
    print("  输入: 仅 DECRYPT 权限的调用方执行批量重加密")
    expect_error(ErrorCode.PERMISSION_DENIED, svc.reencrypt, reader, ids, 2)


# ---------- 5. 重加密与退役并发（确定性） ----------

class _PausableStore:
    """在台账操作上挂接事件，用于在临界区内制造可控停顿（不用固定 sleep）。"""

    def __init__(self, inner, pause_on: str, entered: threading.Event, release: threading.Event):
        self._inner = inner
        self._pause_on = pause_on
        self._entered = entered
        self._release = release

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def _maybe_pause(self, method: str):
        if method == self._pause_on and not self._entered.is_set():
            self._entered.set()
            self._release.wait(timeout=10)

    def count_by_version(self, version):
        self._maybe_pause("count_by_version")
        return self._inner.count_by_version(version)

    def replace(self, record_id, envelope):
        self._maybe_pause("replace")
        return self._inner.replace(record_id, envelope)


def _attach_store(svc, store) -> None:
    svc._store = store


def test_reencrypt_then_retire_serialized():
    """重加密提交期间退役必须排队：退役线程在锁外等待，重加密完成后退役才成功。"""
    svc, ids, _ = _make_two_version_service([b"r1", b"r2", b"r3"])
    payloads = [svc.decrypt(ADMIN, svc.store.get(rid)) for rid in ids]

    entered = threading.Event()   # 重加密已进入提交临界区
    release = threading.Event()   # 放行重加密
    store = _PausableStore(svc.store, "replace", entered, release)
    _attach_store(svc, store)

    retire_done = threading.Event()
    retire_outcome: list = []

    def do_reencrypt():
        svc.reencrypt(ADMIN, ids, 2)

    def do_retire():
        try:
            svc.retire(ADMIN, 1)
            retire_outcome.append("ok")
        except KeyManagementError as exc:
            retire_outcome.append(exc.code)
        finally:
            retire_done.set()

    print("场景: 重加密与退役并发（重加密先进入临界区）")
    t_re = threading.Thread(target=do_reencrypt)
    t_re.start()
    assert entered.wait(timeout=10), "重加密未进入提交临界区"
    print("  输入: 重加密已在提交临界区内停顿，此时发起退役 v1")

    t_ret = threading.Thread(target=do_retire)
    t_ret.start()
    # 确定性断言：重加密持锁期间，退役线程必然无法完成（不是 sleep 等待，是锁保证）
    assert not retire_done.wait(timeout=1.0), "退役穿插进了重加密的临界区"
    print("  判定依据: 重加密持锁期间退役线程被阻塞，未穿插")

    release.set()
    t_re.join(timeout=10)
    t_ret.join(timeout=10)

    print(f"  判定依据: 退役结果={retire_outcome}, v1 状态={svc.keyring.get(1).state.value}")
    assert retire_outcome == ["ok"], "重加密完成后退役应成功"
    assert svc.keyring.get(1).state.value == "RETIRED"
    assert svc.store.count_by_version(1) == 0
    for rid, expect in zip(ids, payloads):
        env = svc.store.get(rid)
        assert env.version == 2
        assert svc.decrypt(ADMIN, env) == expect
    print("  判定依据: 全部记录已迁到 v2 且内容一致，v1 干净退役")


def test_retire_then_reencrypt_serialized():
    """退役判定期间重加密必须排队：退役先被判拒（VERSION_IN_USE），重加密随后完整迁移。"""
    svc, ids, _ = _make_two_version_service([b"r1", b"r2"])

    entered = threading.Event()   # 退役已进入判定临界区
    release = threading.Event()   # 放行退役
    store = _PausableStore(svc.store, "count_by_version", entered, release)
    _attach_store(svc, store)

    reencrypt_done = threading.Event()
    retire_outcome: list = []
    reencrypt_outcome: list = []

    def do_retire():
        try:
            svc.retire(ADMIN, 1)
            retire_outcome.append("ok")
        except KeyManagementError as exc:
            retire_outcome.append(exc.code)

    def do_reencrypt():
        try:
            svc.reencrypt(ADMIN, ids, 2)
            reencrypt_outcome.append("ok")
        except KeyManagementError as exc:
            reencrypt_outcome.append(exc.code)
        finally:
            reencrypt_done.set()

    print("场景: 退役与重加密并发（退役先进入临界区）")
    t_ret = threading.Thread(target=do_retire)
    t_ret.start()
    assert entered.wait(timeout=10), "退役未进入判定临界区"
    print("  输入: 退役已在判定临界区内停顿，此时发起批量重加密到 v2")

    t_re = threading.Thread(target=do_reencrypt)
    t_re.start()
    # 确定性断言：退役持锁期间，重加密线程必然无法完成
    assert not reencrypt_done.wait(timeout=1.0), "重加密穿插进了退役的临界区"
    print("  判定依据: 退役持锁期间重加密线程被阻塞，未穿插")

    release.set()
    t_ret.join(timeout=10)
    t_re.join(timeout=10)

    print(f"  判定依据: 退役结果={retire_outcome}, 重加密结果={reencrypt_outcome}")
    assert retire_outcome == [ErrorCode.VERSION_IN_USE], "v1 仍有密文，退役必须被拒"
    assert reencrypt_outcome == ["ok"], "退役拒绝后重加密应完整完成"
    assert svc.keyring.get(1).state.value == "DISABLED"  # 未被退役
    assert svc.store.count_by_version(1) == 0
    for rid in ids:
        assert svc.store.get(rid).version == 2
    print("  判定依据: 退役被拒且状态不变，重加密从干净状态整批完成")
