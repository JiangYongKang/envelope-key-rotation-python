# envelope-key-rotation-python

本地密钥管理与信封加密服务：支持主密钥版本的全生命周期管理（登记、启用、轮换、停用），
加密采用信封加密，轮换后新旧数据都能被正确处理，所有失败都带可区分的原因码。

## 密钥版本模型

每个主密钥版本有三个状态，状态机单向流转：

```
PENDING --activate--> ACTIVE --rotate/deactivate--> DISABLED
```

| 状态 | 含义 | 可加密 | 可解密 |
|------|------|--------|--------|
| PENDING | 已登记未启用 | 否 | 否 |
| ACTIVE | 当前生效版本（全局唯一） | 是 | 是 |
| DISABLED | 已停用 | 否 | 是（解密历史数据） |

- 版本号单调递增：重复登记报 `DUPLICATE_VERSION`，登记不大于现有最大版本的号报 `VERSION_REGRESSION`。
- 信封密文固定记录**执行加密时生效的那个版本号**，解密按信封上的版本取密钥，因此轮换后历史数据仍可解密。
- 对已停用版本的非法操作（重复停用、重新启用）报 `VERSION_NOT_ACTIVE`；操作不存在的版本报 `VERSION_NOT_FOUND`。

## 信封加密

每次加密生成一份独立的数据密钥（DEK）：

1. `DEK = os.urandom(32)`，用 DEK 以 AES-256-GCM 加密内容；
2. 用当前 ACTIVE 主密钥以 AES-256-GCM 封装 DEK（key wrap）；
3. 密钥版本号作为 AAD 绑定进 GCM 认证标签，对关键部分做完整性校验。

信封结构：`{version, wrapped_dek, wrap_nonce, nonce, ciphertext}`。

解密失败原因可区分，且任何失败都不会返回半截明文（GCM 认证不通过即整体失败）：

| 原因码 | 触发条件 |
|--------|----------|
| `CIPHERTEXT_TAMPERED` | 密文 / 封装密钥 / 随机数被篡改，认证失败 |
| `VERSION_MISMATCH` | 信封版本与调用方期望版本不一致 |
| `VERSION_NOT_FOUND` | 信封指向的版本不存在 |
| `MALFORMED_ENVELOPE` | 信封字段缺失或类型非法 |

## 并发与权限

- `encrypt` 全程持有 KeyRing 的可重入锁，与 `rotate` / `deactivate` 互斥：
  不会用正在停用或已停用的版本加密新数据，轮换也不会留下只写一半的状态。
- 调用方（`Caller`）携带权限集合，越权调用报 `PERMISSION_DENIED`：

| 权限 | 允许的操作 |
|------|-----------|
| `ENCRYPT` | 加密 |
| `DECRYPT` | 解密 |
| `ROTATE` | 登记 / 启用 / 轮换 |
| `DEACTIVATE` | 停用 |

## 兼容范围

- 轮换 / 停用后，所有历史信封仍可解密（密钥材料在本地内存中保留）。
- 当前实现为**内存版 KeyRing**，进程重启后密钥与版本状态不持久，密文不可跨进程解密；
  如需持久化，替换 `KeyRing` 的存储层即可，版本模型与信封格式不变。
- 信封格式与 AAD 约定（`envelope:v{version}`）视为稳定接口，改动需同步升版本。

## HTTP API

```bash
uv run python main.py   # 启动本地服务
```

请求头携带调用方身份：`X-Caller-Name`、`X-Caller-Permissions`（逗号分隔，如 `ENCRYPT,DECRYPT`）。

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/keys/register` | 登记版本（ROTATE） |
| POST | `/keys/{v}/activate` | 启用版本（ROTATE） |
| POST | `/keys/rotate` | 轮换（ROTATE） |
| POST | `/keys/{v}/deactivate` | 停用（DEACTIVATE） |
| POST | `/encrypt` | 加密（ENCRYPT） |
| POST | `/decrypt` | 解密（DECRYPT） |

业务错误以 HTTP 400 返回，body 含 `{"code": <原因码>, "message": ...}`。

## 本地验证

```bash
uv sync                 # 安装依赖
uv run pytest -q -s     # 运行测试，-s 可看到每个用例的输入与判定依据
```

测试覆盖：轮换前后解密、停用版本可解密不可加密、密文/封装/随机数/版本号篡改、
版本回退、重复登记、对已停用版本的非法操作、并发轮换与写入、越权调用。
