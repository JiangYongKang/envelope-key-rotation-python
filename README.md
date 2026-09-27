# 本地密钥管理与信封加密服务

基于 FastAPI 的本地密钥生命周期管理 + 信封加密（Envelope Encryption）能力。
密钥材料只保存在进程内存中，适用于本地开发、演示与单机场景；不适用于需要持久化或
HSM/KMS 托管的生产环境。

## 1. 密钥版本模型

- 每次 `rotate` 生成一把 32 字节随机主密钥（AES-256），登记为**单调递增**的新版本号。
- 每个版本有两种状态，状态机不可逆：
  - `ACTIVE`：可用于加密新数据，也可解密；
  - `DISABLED`：仅可用于解密历史数据，**不得再加密新数据，也不能重新启用**。
- 密文记录（信封）固定关联**执行加密那一刻生效的主密钥版本号**，与后续轮换无关。

登记/状态变更的拒绝规则（原因码互不相同）：

| 场景 | 错误原因码 |
| --- | --- |
| 重复登记同一版本号 | `DUPLICATE_VERSION` |
| 登记版本号 ≤ 已有最大版本 | `VERSION_ROLLBACK` |
| 操作的版本不存在 | `KEY_NOT_FOUND` |
| 停用一个已停用版本 / 重新启用已停用版本 | `KEY_DISABLED` |
| 加密时没有任何 ACTIVE 版本 | `NO_ACTIVE_KEY` |
| 调用方缺少对应权限 | `PERMISSION_DENIED` |

## 2. 轮换与停用规则

- **轮换**：生成新版本并登记为 ACTIVE；旧版本保持 ACTIVE，可继续解密历史数据。
- **停用**：旧版本到期后可显式停用；停用后该版本不能加密新数据，但历史密文仍可解密。
- **并发保证**：`encrypt` 在同一把锁内完成"取当前 ACTIVE 版本快照 + 加密"，
  `rotate` / `disable` 必须先拿到同一把锁。因此：
  - 不会用"正在停用/已经停用"的版本加密新数据；
  - 不会留下只写一半的状态；并发停用冲突会以 `KEY_DISABLED` 明确拒绝其中一方。

## 3. 信封加密格式与兼容范围

每条密文由以下部分组成（见 `app/crypto.py`）：

```
magic(4) | key_version(4)
| len | wrapped_dek      # DEK 用主密钥版本 AES-256-GCM 封装，AAD 绑定版本号
| len | dek_nonce
| len | ciphertext       # 内容用一次性 DEK AES-256-GCM 加密，AAD 绑定版本号+wrapped_dek
| len | content_nonce
| len | tag              # 主密钥对全部关键字段的 HMAC-SHA256
```

- 每次加密生成**独立的一次性 DEK**（32 字节随机）。
- 解密先校验 HMAC，再做两次 AEAD 解密；任何一步失败都直接报错，**绝不返回半截明文**。
- 失败原因可区分：
  - `TAMPERED_CIPHERTEXT`：任一字段被篡改、主密钥不对、AEAD 认证失败；
  - `VERSION_MISMATCH`：调用方指定的预期版本与信封记录版本不一致；
  - `MALFORMED_ENVELOPE`：信封字节无法解析；
  - `KEY_NOT_FOUND`：信封关联的版本在注册表中不存在。
- **兼容范围**：轮换、停用都不影响历史密文解密，前提是信封记录的版本材料仍在
  注册表中（本实现材料存于内存，进程重启后旧密文将无法解密）。

## 4. HTTP 接口

所有接口通过 `X-Api-Key` 头鉴权，本地内置调用方（仅用于演示）：

| API Key | 权限 |
| --- | --- |
| `key-admin` | ROTATE、DISABLE |
| `key-writer` | ENCRYPT |
| `key-reader` | DECRYPT |
| `key-all` | 全部 |

| 方法与路径 | 权限 | 说明 |
| --- | --- | --- |
| `POST /keys/rotate` | ROTATE | 生成并启用新版本，返回 `{version, state}` |
| `POST /keys/{version}/disable` | DISABLE | 停用指定版本 |
| `GET /keys` | 已认证即可 | 查看各版本状态与最新 ACTIVE 版本 |
| `POST /encrypt` | ENCRYPT | body `{"plaintext": "..."}`，返回版本号与 base64 信封 |
| `POST /decrypt` | DECRYPT | body `{"envelope": "<base64>"}`，返回版本号与明文 |

错误响应统一为 `{"error": "<原因码>", "detail": "..."}`，状态码：
401（未认证）、403（越权）、404（版本不存在）、409（登记/状态冲突）、400（密文问题）。

## 5. 本地验证方法

```bash
# 安装依赖（需 Python 3.14+，使用 uv）
uv sync

# 运行全部单测（20 个，覆盖五类场景，日志会打印输入和判定依据）
uv run pytest -q
# 需要更详细日志时
TEST_DEBUG=1 uv run pytest -q

# 启动服务（启动时自动登记 v1）
uv run fastapi dev main.py --port 8000

# 手工验证一轮轮换
curl -s -X POST localhost:8000/encrypt -H "X-Api-Key: key-writer" \
  -H 'Content-Type: application/json' -d '{"plaintext":"hello"}'
curl -s -X POST localhost:8000/keys/rotate -H "X-Api-Key: key-admin"
curl -s localhost:8000/keys -H "X-Api-Key: key-all"
```

测试场景与文件对应：

| 场景 | 文件 |
| --- | --- |
| 轮换前后解密、重复登记、版本回退、停用版本非法操作 | `tests/test_rotation.py` |
| 密文篡改、版本对不上、认证失败、结构损坏 | `tests/test_tamper.py` |
| 并发轮换与写入（确定性互斥 + 压力测试） | `tests/test_concurrency.py` |
| 越权（服务层 + HTTP 层） | `tests/test_auth.py`、`tests/test_http.py` |

## 6. 代码结构

```
app/errors.py    原因码与统一异常
app/keystore.py  线程安全的密钥版本注册表与状态机
app/crypto.py    DEK 生成、AES-GCM 封装/加密、HMAC 完整性校验、信封序列化
app/service.py   权限校验、加密/轮换互斥的业务编排
main.py          FastAPI 接口
tests/           五类场景单测
```
