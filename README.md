# envelope-key-rotation-python

本地密钥管理与信封加密服务：支持主密钥版本的全生命周期管理（登记、启用、轮换、停用、**退役**），
加密采用信封加密，轮换后新旧数据都能被正确处理；调用方身份由**服务端确认**，
支持**批量重加密**把存量数据迁到新版本，所有失败都带可区分的原因码。

## 密钥版本模型

每个主密钥版本有四个状态，状态机单向流转，`RETIRED` 为终态：

```
PENDING --activate--> ACTIVE --rotate/deactivate--> DISABLED --retire--> RETIRED
```

| 状态 | 含义 | 可加密 | 可解密 | 可退役 |
|------|------|--------|--------|--------|
| PENDING | 已登记未启用 | 否 | 否 | 否 |
| ACTIVE | 当前生效版本（全局唯一） | 是 | 是 | 否 |
| DISABLED | 已停用 | 否 | 是（解密历史数据） | 是（需无在册密文） |
| RETIRED | 已退役（终态） | 否 | 否 | — |

- 版本号单调递增：重复登记报 `DUPLICATE_VERSION`，登记不大于现有最大版本的号报 `VERSION_REGRESSION`。
- 信封密文固定记录**执行加密时生效的那个版本号**，解密按信封上的版本取密钥，因此轮换后历史数据仍可解密。
- 对已停用版本的非法操作（重复停用、重新启用）报 `VERSION_NOT_ACTIVE`；操作不存在的版本报 `VERSION_NOT_FOUND`。

### 退役规则

- 只有 **DISABLED** 状态、且**密文台账中已无任何记录引用该版本**时，才允许退役：
  - 未停用（PENDING/ACTIVE）就退役：报 `VERSION_NOT_DISABLED`；
  - 仍有历史密文在用：报 `VERSION_IN_USE`（"版本仍在使用中"），与其他拒绝明确区分；
  - 重复退役 / 对退役版本启用、停用：报 `VERSION_RETIRED`。
- 退役是**终态**：不能再被启用，其密文一律拒绝解密。
- 解密失败原因三分：`VERSION_NOT_FOUND`（版本不存在）、`VERSION_NOT_ACTIVE`（版本已停用相关非法操作）、
  `VERSION_RETIRED`（版本已退役），互不混淆。

### 版本使用统计

`GET /keys/{v}/stats`（或服务层 `version_stats`）返回：

```json
{"version": 1, "state": "DISABLED", "encrypt_count": 12, "decrypt_count": 30, "last_used_at": 1760000000.0}
```

加密/解密次数与最后使用时间可用于判断版本是否还有流量、能否安全退役。

## 信封加密

每次加密生成一份独立的数据密钥（DEK）：

1. `DEK = os.urandom(32)`，用 DEK 以 AES-256-GCM 加密内容；
2. 用当前 ACTIVE 主密钥以 AES-256-GCM 封装 DEK（key wrap）；
3. 密钥版本号作为 AAD 绑定进 GCM 认证标签，对关键部分做完整性校验。

信封结构：`{version, wrapped_dek, wrap_nonce, nonce, ciphertext}`；
每条加密产出同时登记进**密文台账**并回填 `record_id`，作为退役判定与批量重加密的依据。

解密失败原因可区分，且任何失败都不会返回半截明文（GCM 认证不通过即整体失败）：

| 原因码 | 触发条件 |
|--------|----------|
| `CIPHERTEXT_TAMPERED` | 密文 / 封装密钥 / 随机数被篡改，认证失败 |
| `VERSION_MISMATCH` | 信封版本与调用方期望版本不一致 |
| `VERSION_NOT_FOUND` | 信封指向的版本不存在 |
| `VERSION_RETIRED` | 信封指向的版本已退役 |
| `MALFORMED_ENVELOPE` | 信封字段缺失或类型非法 |

## 调用方身份校验

身份由**服务端自己确认**：客户端只在请求头出示令牌 `X-Caller-Token`，
服务端在本地身份注册表（`IdentityRegistry`）中查出调用方是谁、有哪些权限。
客户端自报的任何名称/权限（如 `X-Caller-Name`、`X-Caller-Permissions`）**一律不被信任、被忽略**。

HTTP 状态语义：

| 情况 | 状态码 | 原因码 |
|------|--------|--------|
| 无令牌 / 令牌未在服务端登记 | 401 | `UNAUTHENTICATED` |
| 身份合法但权限不够 | 403 | `PERMISSION_DENIED` |
| 其他业务失败 | 400 | 对应原因码 |

权限表：

| 权限 | 允许的操作 |
|------|-----------|
| `ENCRYPT` | 加密 |
| `DECRYPT` | 解密 |
| `ROTATE` | 登记 / 启用 / 轮换 |
| `DEACTIVATE` | 停用 |
| `RETIRE` | 退役 |
| `REENCRYPT` | 批量重加密 |

本地开发缺省预置三个身份（生产用环境变量 `EKR_IDENTITIES` 覆盖，JSON 格式同下）：

```json
{
  "admin-token":  {"name": "admin",  "permissions": ["ENCRYPT","DECRYPT","ROTATE","DEACTIVATE","RETIRE","REENCRYPT"]},
  "writer-token": {"name": "writer", "permissions": ["ENCRYPT"]},
  "reader-token": {"name": "reader", "permissions": ["DECRYPT"]}
}
```

## 批量重加密

`POST /reencrypt`（`REENCRYPT` 权限）把一批台账记录整体迁到目标版本之下：

```json
{"record_ids": [1, 2, 3], "target_version": 2}
```

- **内容一致**：迁移后逐条解密结果与迁移前完全一致；
- **不明文暴露**：解旧封新全部在服务进程内存中完成，响应只含迁移数量与记录号，不含明文；
- **目标校验**：目标版本必须是当前 ACTIVE 版本；已退役版本作为目标报 `VERSION_RETIRED`，
  其他非生效状态报 `VERSION_NOT_ACTIVE`——不会产出用已退役版本加密的记录；
- **整批原子**：先在内存中完成全部记录的解旧封新，全部成功后才一次性提交台账；
  任何一条失败（如记录不存在 `RECORD_NOT_FOUND`）都不会留下只迁了一半的结果，重试从干净状态开始；
- **与退役互斥**：批量重加密与退役共用同一把锁，二者必然串行——
  不会在用已退役版本加密数据，也不会出现迁到一半源版本被退役导致整批失败。

## 并发与权限

- `encrypt` / `retire` / `reencrypt` 全程持有 KeyRing 的同一把可重入锁，与 `rotate` / `deactivate` 互斥：
  不会用正在停用或已停用的版本加密新数据，轮换/退役/重加密都不会留下只写一半的状态。
- 越权调用报 `PERMISSION_DENIED`（HTTP 403），身份无法识别报 `UNAUTHENTICATED`（HTTP 401）。

## 兼容范围

- 轮换 / 停用后，所有历史信封仍可解密（密钥材料在本地内存中保留）；**版本一旦退役，其密文不可再解密**。
- 批量重加密只迁移**本服务台账在册**的记录（即本进程加密产出、或被显式登记的信封）；
  进程外持有的信封不在迁移范围内，需调用方自行解密后重新加密。
- 当前实现为**内存版 KeyRing + 内存台账**，进程重启后密钥、版本状态与台账不持久，
  密文不可跨进程解密；如需持久化，替换 `KeyRing` / `CiphertextStore` 的存储层即可，版本模型与信封格式不变。
- 信封格式与 AAD 约定（`envelope:v{version}`）视为稳定接口，改动需同步升版本。
- 按版本号操作与加解密的接口路径与上一轮保持一致；仅鉴权方式改为服务端令牌校验
  （原 `X-Caller-Name` / `X-Caller-Permissions` 头不再生效）。

## HTTP API

```bash
uv run python main.py   # 启动本地服务
```

请求头携带调用方令牌：`X-Caller-Token`。

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/keys/register` | 登记版本（ROTATE） |
| POST | `/keys/{v}/activate` | 启用版本（ROTATE） |
| POST | `/keys/rotate` | 轮换（ROTATE） |
| POST | `/keys/{v}/deactivate` | 停用（DEACTIVATE） |
| POST | `/keys/{v}/retire` | 退役（RETIRE，终态） |
| GET | `/keys/{v}/stats` | 版本使用统计 |
| POST | `/encrypt` | 加密（ENCRYPT），响应含 `record_id` |
| POST | `/decrypt` | 解密（DECRYPT） |
| POST | `/reencrypt` | 批量重加密（REENCRYPT） |

业务错误 body 含 `{"code": <原因码>, "message": ...}`，状态码见"调用方身份校验"一节。

## 本地验证

```bash
uv sync                 # 安装依赖
uv run pytest -q -s     # 运行测试，-s 可看到每个用例的输入与判定依据
```

测试覆盖：

- 上一轮：轮换前后解密、停用版本可解密不可加密、密文/封装/随机数/版本号篡改、
  版本回退、重复登记、对已停用版本的非法操作、并发轮换与写入、越权调用；
- 本轮：令牌身份校验（401/403、客户端自报无效）、版本使用统计、
  仍在使用的版本被拒退役（`VERSION_IN_USE`）、退役为终态、退役后解密失败原因可区分、
  批量重加密（内容一致、整批原子、目标校验）、重加密与退役并发互斥
  （确定性断言：用事件在临界区内制造可控停顿，不依赖固定 sleep）。

手工验证 HTTP 行为示例：

```bash
uv run python main.py &                      # 启动服务（端口见输出）
TOKEN=admin-token
curl -X POST localhost:8000/keys/rotate -H "X-Caller-Token: $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"version":1,"material_b64":"'"$(head -c32 /dev/urandom | base64)"'"}'
curl -X POST localhost:8000/encrypt -H "X-Caller-Token: $TOKEN" \
     -H 'Content-Type: application/json' -d '{"plaintext_b64":"aGVsbG8="}'
curl -X POST localhost:8000/encrypt -d '{"plaintext_b64":"aGVsbG8="}'        # 401
curl -X POST localhost:8000/encrypt -H "X-Caller-Token: reader-token" \
     -H 'Content-Type: application/json' -d '{"plaintext_b64":"aGVsbG8="}'   # 403
```
