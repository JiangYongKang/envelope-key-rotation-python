# envelope-key-rotation-python

本地密钥管理与信封加密服务：支持主密钥版本的全生命周期管理（登记、启用、轮换、停用、**退役**），
加密采用信封加密，轮换后新旧数据都能被正确处理；调用方身份由**服务端**校验，
支持按版本的使用统计与**批量重加密**，所有失败都带可区分的原因码。

## 密钥版本模型

每个主密钥版本有四个状态，状态机单向流转，RETIRED 为终态：

```
PENDING --activate--> ACTIVE --rotate/deactivate--> DISABLED --retire--> RETIRED
```

| 状态 | 含义 | 可加密 | 可解密 | 可退役 |
|------|------|--------|--------|--------|
| PENDING | 已登记未启用 | 否 | 否 | 否 |
| ACTIVE | 当前生效版本（全局唯一） | 是 | 是 | 否 |
| DISABLED | 已停用 | 否 | 是（解密历史数据） | 仅当无密文引用 |
| RETIRED | 已退役（终态） | 否 | 否 | — |

- 版本号单调递增：重复登记报 `DUPLICATE_VERSION`，登记不大于现有最大版本的号报 `VERSION_REGRESSION`。
- 信封密文固定记录**执行加密时生效的那个版本号**，解密按信封上的版本取密钥，因此轮换后历史数据仍可解密。
- 对已停用版本的非法操作（重复停用、重新启用）报 `VERSION_NOT_ACTIVE`；操作不存在的版本报 `VERSION_NOT_FOUND`。

### 退役规则

- 只有 **DISABLED** 且**记录仓库中没有任何密文再引用它**的版本才允许退役；
  仍有引用时报 `VERSION_IN_USE`（“版本仍在使用中”），与 `VERSION_NOT_ACTIVE`（未停用）可区分。
- 退役是终态：对已退役版本做启用/停用/重复退役/解密，一律报 `VERSION_RETIRED`，
  与 `VERSION_NOT_FOUND`（版本不存在）、`VERSION_NOT_ACTIVE`（已停用）明确区分。
- 退役判定（无引用）与状态变更在同一把锁内完成，与批量重加密互斥，判定结果不会被并发改写。

### 使用统计

`GET /keys/{v}/usage`（或服务层 `usage()`）按版本返回：

- `encrypt_count`：该版本执行的加密次数
- `decrypt_count`：该版本执行的解密次数
- `last_used_at`：最后一次被使用的时间（未使用过为 `null`）

结合记录引用情况，可用于判断一个 DISABLED 版本是否可以安全退役。

## 调用方身份校验

身份与权限**只由服务端确认**：客户端通过 `X-Caller-Token` 头出示凭据，
服务端身份注册表（`IdentityRegistry`）按凭据解析出调用方与其权限集合。
客户端在请求里自报的任何身份/权限信息一律被忽略，无法借此提权。

| 情形 | HTTP 状态 | 原因码 |
|------|-----------|--------|
| 未携带或伪造凭据 | 401 | `UNAUTHENTICATED` |
| 身份合法但权限不够 | 403 | `PERMISSION_DENIED` |
| 其他业务错误 | 400 | 各自原因码 |

| 权限 | 允许的操作 |
|------|-----------|
| `ENCRYPT` | 加密、写入记录 |
| `DECRYPT` | 解密、读取记录、查询使用统计 |
| `ROTATE` | 登记 / 启用 / 轮换 |
| `DEACTIVATE` | 停用 |
| `RETIRE` | 退役 |
| `REENCRYPT` | 批量重加密 |

本地开发默认凭据（见 `main.py:_build_registry`，生产环境应替换为外部身份源）：
`dev-admin-token`（全权限）、`dev-writer-token`（ENCRYPT）、`dev-reader-token`（DECRYPT）。

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
| `VERSION_RETIRED` | 信封指向的版本已退役（终态，不可解密） |
| `MALFORMED_ENVELOPE` | 信封字段缺失或类型非法 |

## 批量重加密

`POST /records/reencrypt`（服务层 `reencrypt_records()`）把一批记录整体迁到目标版本：

- **目标必须是当前 ACTIVE 版本**：不会产出已停用/已退役版本的密文；目标非法报
  `VERSION_NOT_ACTIVE` / `VERSION_NOT_FOUND`。
- **原子生效**：先在内存中算完全部新信封，再一次换入记录仓库；任何一条失败
  （如记录不存在，报 `RECORD_NOT_FOUND`）仓库保持原状，不会出现只迁一半的结果，
  重试从干净状态重新开始。
- **明文不出边界**：解密-重加密全部在服务端完成，返回值只是迁移条数。
- **与退役互斥**：整批持同一把锁，退役无法穿插；源版本不会跑到一半被退役导致整批失败，
  退役也不会在批处理进行中把版本状态改掉。两个方向的顺序都有确定语义：
  - 先迁完 → 源版本不再被引用，随后退役放行；
  - 先退役（仍被引用）→ 拒绝退役报 `VERSION_IN_USE`，批处理不受影响。

## 并发与兼容范围

- `encrypt` / `store_record` / `reencrypt_records` / `retire` 都持有 KeyRing 的同一把
  可重入锁，与 `rotate` / `deactivate` 互斥：不会用正在停用或已退役的版本加密新数据，
  轮换/退役/迁移都不会留下只写一半的状态。
- 上一轮接口行为保持兼容：按版本号的登记/启用/轮换/停用与加解密接口路径、
  请求体、信封格式与 AAD 约定（`envelope:v{version}`）均不变，仅身份校验方式
  从“客户端自报”改为“服务端按凭据解析”。
- 轮换 / 停用后，所有历史信封仍可解密；版本退役后其密文不可再解密（`VERSION_RETIRED`），
  退役前请先用批量重加密把存量数据迁走。
- 当前实现为**内存版 KeyRing 与记录仓库**，进程重启后密钥、版本状态与记录不持久；
  如需持久化，替换 `KeyRing` / `RecordStore` 的存储层即可，版本模型与信封格式不变。

## HTTP API

```bash
uv run python main.py   # 启动本地服务
```

请求头携带调用方凭据：`X-Caller-Token`（见“调用方身份校验”）。

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/keys/register` | 登记版本（ROTATE） |
| POST | `/keys/{v}/activate` | 启用版本（ROTATE） |
| POST | `/keys/rotate` | 轮换（ROTATE） |
| POST | `/keys/{v}/deactivate` | 停用（DEACTIVATE） |
| POST | `/keys/{v}/retire` | 退役（RETIRE，终态） |
| GET  | `/keys/{v}/usage` | 版本使用统计（DECRYPT） |
| POST | `/encrypt` | 加密（ENCRYPT） |
| POST | `/decrypt` | 解密（DECRYPT） |
| POST | `/records` | 加密并落库一条记录（ENCRYPT） |
| GET  | `/records/{id}` | 解密读取记录（DECRYPT） |
| POST | `/records/reencrypt` | 批量重加密到目标版本（REENCRYPT） |

业务错误 body 含 `{"code": <原因码>, "message": ...}`，状态码见“调用方身份校验”。

## 本地验证

```bash
uv sync                 # 安装依赖
uv run pytest -q -s     # 运行测试，-s 可看到每个用例的输入与判定依据
```

测试覆盖：

- 上一轮：轮换前后解密、停用版本可解密不可加密、密文/封装/随机数/版本号篡改、
  版本回退、重复登记、对已停用版本的非法操作、并发轮换与写入、越权调用；
- 本轮：身份未识别（401）/权限不足（403）/自我提权无效、按版本使用统计、
  退役前置条件与终态语义、仍在使用的版本被拒退役（`VERSION_IN_USE`）、
  退役后解密失败（`VERSION_RETIRED`）、批量重加密的内容一致性与原子性、
  重加密与退役的并发互斥（Event 确定性同步，不依赖固定 sleep）。
