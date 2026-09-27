"""场景四：加密写入与密钥轮换/停用并发。

不变量：
1. 加密在临界区内取版本快照并完成加密，停用/轮换拿不到锁 -> 不会用停用中的版本加密。
2. 每条产出的信封之后都能按记录的版本解密，不存在半写状态。
"""

import logging
import threading

from app.crypto import EnvelopeCipher
from app.errors import ErrorReason, KeyManagementError
from app.keystore import KeyState

logger = logging.getLogger(__name__)


def test_encrypt_and_disable_are_mutually_exclusive(svc, admin, writer):
    """确定性互斥：加密进行到一半时，停用必须被阻塞，且看到版本仍 ACTIVE。"""
    v1 = svc.keystore.latest_active()
    inside = threading.Event()
    release = threading.Event()
    real_encrypt = EnvelopeCipher.encrypt

    def slow_encrypt(plaintext, key_version, master_key):
        inside.set()
        assert release.wait(timeout=5), "加密线程未在 5s 内被放行"
        return real_encrypt(plaintext, key_version, master_key)

    svc.encrypt  # warm up
    EnvelopeCipher.encrypt = staticmethod(slow_encrypt)
    try:
        t_enc = threading.Thread(target=svc.encrypt, args=(writer, b"mid-flight"))
        t_enc.start()
        assert inside.wait(timeout=5), "加密线程未进入临界区"

        t_dis = threading.Thread(target=svc.disable, args=(admin, v1.version))
        t_dis.start()
        t_dis.join(timeout=0.5)
        # 判定依据：加密未放行前，停用拿不到锁，版本仍是 ACTIVE
        assert t_dis.is_alive(), "停用不应在加密临界区内完成"
        assert svc.keystore.get(v1.version).state is KeyState.ACTIVE
        logger.info("判定: 加密持有锁期间，停用 v%s 被阻塞且版本仍为 ACTIVE", v1.version)

        release.set()
        t_enc.join(timeout=5)
        t_dis.join(timeout=5)
        assert not t_enc.is_alive() and not t_dis.is_alive()
        assert svc.keystore.get(v1.version).state is KeyState.DISABLED
        logger.info("判定: 加密结束后停用才生效，v%s -> DISABLED", v1.version)
    finally:
        EnvelopeCipher.encrypt = staticmethod(real_encrypt)


def test_concurrent_rotation_and_writes(svc, admin, writer, reader):
    """压力场景：多线程轮换/加密/停用旧版本，所有产出信封必须可解密。"""
    errors: list[Exception] = []
    envelopes: list = []
    envelopes_lock = threading.Lock()
    barrier = threading.Barrier(8)
    rounds = {"rotate": 0}

    def do_rotate():
        barrier.wait()
        for _ in range(20):
            try:
                kv = svc.rotate(admin)
                rounds["rotate"] += 1
                # 停用除最新版本外的旧 ACTIVE 版本（模拟密钥到期）
                old_active = [
                    k.version
                    for k in svc.keystore.snapshot()
                    if k.state is KeyState.ACTIVE and k.version < kv.version
                ]
                for ov in old_active:
                    try:
                        svc.disable(admin, ov)
                    except KeyManagementError as exc:
                        # 两个轮换线程可能竞争停用同一旧版本：重复停用必须被拒绝且原因可区分
                        assert exc.reason is ErrorReason.KEY_DISABLED
                        logger.info("判定: 并发停用旧版本冲突 -> reason=%s", exc.reason.value)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

    def do_encrypt(idx):
        barrier.wait()
        for i in range(100):
            pt = f"writer-{idx}-{i}".encode()
            try:
                env = svc.encrypt(writer, pt)
                # 判定依据 1：记录版本此刻必须能在注册表中找到且为 ACTIVE
                assert svc.keystore.get(env.key_version).state is KeyState.ACTIVE
                with envelopes_lock:
                    envelopes.append((pt, env))
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

    threads = [threading.Thread(target=do_rotate) for _ in range(2)]
    threads += [threading.Thread(target=do_encrypt, args=(i,)) for i in range(6)]
    logger.info("输入: 2 轮换线程 x20 轮 + 6 加密线程 x100 条，并发启动")
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert all(not t.is_alive() for t in threads), "存在未结束线程"
    assert not errors, f"并发过程中出现异常: {errors[:3]}"

    # 判定依据 2：轮换与停用之后，每条历史密文都能原样解出（无半写状态）
    for pt, env in envelopes:
        assert svc.decrypt(reader, env) == pt
    logger.info(
        "判定: 共轮换 %s 次、产出 %s 条密文，全部可按记录版本解密，无异常",
        rounds["rotate"], len(envelopes),
    )
    assert rounds["rotate"] > 0 and len(envelopes) == 600
