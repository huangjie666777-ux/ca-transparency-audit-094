# Local Test CA

本机联调用的证书签发与吊销后端（Python 3.10 + FastAPI + cryptography）。
服务只绑定 `127.0.0.1`，无前端，数据与私钥均保存在本机数据目录。

除传统的 JSON 签发接口外，另提供一套 **ACME（RFC 8555）子集**自动申领通道，
可用 JWS 签名请求完成注册账号 → 下单 → http-01 验证 → 签发 7 天证书。

## 启动

```sh
.venv/bin/python -m pip install -r requirements.lock.txt

# 默认数据目录为 ./data，可用 LOCAL_CA_DATA_DIR 覆盖
LOCAL_CA_DATA_DIR=./data .venv/bin/python -m uvicorn app.main:app \
  --host 127.0.0.1 --port 8000
```

- 数据目录为空时，启动会自动生成 4096 位 RSA 自签根 CA（有效期 10 年）。
- 重启时复用同一 CA、SQLite 记录与透明度日志（索引、历史根、日志身份）。
- 已有数据库但 CA 私钥/证书缺失、只存在其一、密钥与证书不匹配，或证书与
  数据库绑定的指纹不一致时，服务拒绝启动（`app.ca.CAError`），不会静默换 CA。
- 数据库里已有透明度日志但 `log_key.pem` 缺失或与库中 `log_id` 不匹配时，
  同样拒绝启动（`app.audit_key.LogKeyError`）。

### ACME / http-01 相关配置

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `LOCAL_CA_HTTP01_PORT` | `80` | http-01 校验目标端口；TCP **永远只连 127.0.0.1** |
| `LOCAL_CA_HTTP01_TIMEOUT` | `5` | 挑战请求超时（秒） |
| `LOCAL_CA_HTTP01_MAX_BYTES` | `8192` | 挑战响应 body 大小上限（字节） |

## 密钥与数据存放

默认 `./data/`（已在 `.gitignore` 中忽略）：

- `ca_key.pem`：CA 私钥，PKCS#8 PEM、**无口令加密**，文件权限 `0600`，
  仅存本机，不提供任何下载接口；请只在隔离的本机联调环境使用。
- `ca_cert.pem`：CA 证书，权限 `0644`，可通过接口下载。
- `log_key.pem`：审计日志树头签名用的 **Ed25519** 私钥，权限 `0600`，
  与 CA 密钥相互独立，无下载接口。
- `log_pubkey.raw`：对应的 32 字节原始 Ed25519 公钥，权限 `0644`，供带外
  预置为核验信任锚。
- `ca.sqlite3`：证书记录、幂等键、吊销状态、CRL 编号、ACME 表与透明度
  审计日志（`audit_*` 表，WAL 模式）。

## 签发策略

- CSR 必须是合法 PEM 且签名自洽；公钥只接受 RSA，且至少 2048 位。
- 必须携带非空 `subjectAltName`；只允许 DNSName，不允许 IP/URI/邮件等；
  CN 不能代替 SAN。
- DNS 名称按标签匹配，仅接受 `lab.test` 与其任意层级子域
  （如 `api.lab.test`、`a.b.lab.test`）；拒绝通配符，大小写归一。
- `days` 为 1–30 的整数；证书有效期不会越过 CA 自身到期时间。
- 签发证书：CA=false、KeyUsage=`digitalSignature,keyEncipherment`、
  EKU 仅 `serverAuth`，并设置规范化后的 SAN、SKI/AKI；不照搬 CSR 中其他扩展。

## 接口

| 方法/路径 | 说明 |
| --- | --- |
| `GET /health` | 健康检查 |
| `GET /ca/certificate` | 下载 CA 证书 PEM |
| `POST /certificates` | 提交 `{csr, days, idempotency_key}` 签发 |
| `GET /certificates/{hex_serial}` | 查询证书与吊销状态（JSON） |
| `GET /certificates/{hex_serial}/pem` | 下载证书 PEM |
| `POST /certificates/{hex_serial}/revoke` | 吊销，body 为 `{reason}` |
| `POST /crl/publish` | 发布下一版 CRL（编号原子递增） |
| `GET /crl/current` / `/crl/current.pem` | 查看/下载当前 CRL |

序列号为十六进制正整数。签发接口幂等：同幂等键 + 同 CSR(DER) + 同天数
返回原证书；同键不同内容返回 `409`。并发重试只产生一条记录，签发失败无半成品。

吊销保留首次吊销时间与原因（RFC 5280 原因：`unspecified`、
`key_compromise`、`ca_compromise`、`affiliation_changed`、`superseded`、
`cessation_of_operation`、`certificate_hold`、`privilege_withdrawn`、
`aa_compromise`）。同原因重复调用幂等，不同原因 `409`，未知序列号 `404`，
吊销不可撤回。CRL 由 CA 签名，包含全部吊销记录，`CRLNumber` 持久化递增，
启动时即发布首份空 CRL。

## ACME（RFC 8555 子集）

### 范围

实现：`directory`、`newNonce`、`newAccount`、`newOrder`、授权与挑战、
`finalize`、证书下载；所有查询均为 **POST-as-GET**（空 payload 的 JWS POST）。

**不实现**：换钥（`keyChange`）、账号停用、ACME 侧吊销（`revokeCert`）。
需要吊销 ACME 证书时，使用下面的传统 `/certificates/{serial}/revoke` 接口
（ACME 签发的证书与传统接口、CRL 完全互通）。

固定策略：

- 账号密钥仅接受 **RSA ≥ 2048 + RS256**；注册请求 protected 带 `jwk`，
  其余请求带 `kid`（账号 URL）；重复公钥注册复用原账号。
- 校验 JWS 签名、protected 中的 `url`（必须与请求 URL 一致）与 `nonce`。
- nonce 有效期 **5 分钟**、一次性；并发重放最多一个请求成功，其余返回
  `badNonce` 并补发新 nonce。
- 每个订单**恰好一个** `dns` identifier，且必须是 `lab.test` 或其子域，
  拒绝通配符；订单/授权 **10 分钟**过期。
- 仅支持 **http-01**：按账号 JWK 指纹校验
  `keyAuthorization = token + "." + JWK_SHA256_thumbprint`。
- 本机校验只走 **HTTP**，TCP 固定连接 `127.0.0.1`（端口可配），HTTP `Host`
  头为目标域名，路径为 `/.well-known/acme-challenge/<token>`；**禁止重定向**，
  超时与响应大小受限。
- 未完成授权或订单已过期一律不签发。
- `finalize` 接收 **base64url 编码的 DER CSR**；CSR 的 SAN 必须与订单域名
  完全一致；复用旧签发策略与 CA，签发 **7 天**证书。
- 同一订单并发以相同 CSR finalize 只签发一张证书；同一订单换不同 CSR 返回
  `409 orderAlreadyIssued`。
- 账号、授权、订单、证书均关联落 **同一个 SQLite**（`acme_*` 表），
  重启后订单可继续；签发失败整体回滚，不留孤立证书。

### ACME 端点

| 方法/路径 | 身份 | 说明 |
| --- | --- | --- |
| `GET/HEAD /acme/directory` | 无 | 目录与能力声明 |
| `GET/HEAD /acme/new-nonce` | 无 | 204 + `Replay-Nonce` |
| `POST /acme/new-account` | jwk | 注册/复用账号 |
| `POST /acme/new-order` | kid | 下单 |
| `POST /acme/account/{id}` | kid | POST-as-GET 查询账号 |
| `POST /acme/order/{id}` | kid | POST-as-GET 查询订单 |
| `POST /acme/order/{id}/finalize` | kid | 提交 DER CSR 签发 |
| `POST /acme/authz/{id}` | kid | POST-as-GET 查询授权 |
| `POST /acme/challenge/{id}` | kid | 触发/应答 http-01 挑战 |
| `POST /acme/cert/{id}` | kid | POST-as-GET 下载证书链（PEM） |

错误返回 `application/problem+json`
（`{"type": "urn:ietf:params:acme:error:<code>", ...}`），并带新的
`Replay-Nonce`。订单状态：`pending → ready → valid`（或 `invalid`）。

## 透明度审计日志（RFC 6962 子集）

服务另维护一条**只追加**的证书透明度审计日志，供运维核对“哪些证书入账”
与“历史是否被改写”。纯后端、无 SCT；旧签发与 ACME 成功签发都会把**完整
证书 DER**作为叶子追加到同一个 SQLite（`audit_*` 表）。

### 规则与边界

- 叶子索引从 **0** 连续递增；证书、申领关联（ACME 订单）与日志叶子在**同一
  事务**原子提交，任何一步失败整体回滚，不留单边记录。
- 幂等重放（旧接口同幂等键、ACME 同订单同 CSR）**不新增叶子**；并发签发由
  写事务串行化，不重复、不跳号。
- **吊销不改日志**：不删除叶子、不改历史根，只更新证书状态。
- 哈希采用 RFC 6962 §2.1 的 SHA-256 规则：叶子 `SHA256(0x00 || DER)`、
  内部节点 `SHA256(0x01 || left || right)`、空树 `SHA256("")`。
- Merkle 节点**持久化**到 `audit_nodes`；追加一片叶子只物化其晋升路径上的
  O(log n) 个节点，根/证明只从持久化节点读取，支持非满树，**不会重算全库**，
  也不会用“返回全部叶子”代替证明。
- 每次提交都为该树大小保存一个**签名树头**（`audit_sth`），因此每个历史
  大小都有可验证的根。

### 树头签名与日志身份

- 树头由一把**独立持久化的 Ed25519 密钥**签名（`log_key.pem`，权限 `0600`，
  与 4096 位 RSA CA 密钥分离）；原始 32 字节公钥另写 `log_pubkey.raw`
  （`0644`）供带外预置/固定。
- 日志身份 `log_id = SHA256(Ed25519 公钥)`。树头签名覆盖
  `域名分隔串 || log_id || 大端8字节 tree_size || root_hash`，把身份、大小
  和根绑定在一起。
- 重启保留索引、全部历史根与日志身份，只做校验不重建。**库里已有日志而
  `log_key.pem` 缺失、或密钥与库中身份不匹配时，拒绝启动**
  （`app.audit_key.LogKeyError` / `app.audit_store.AuditError`）。

### 旧库一次性迁移

首次以新版本启动、库中尚无日志时，在开放签发前把 `certificates` 中的旧证书
按**序列号数值升序**在**单事务**内一次性建入日志（空库则落一个签名空树头）。
迁移任一步失败整批回滚，不产生半成品日志；此后重启不再迁移。

### 审计接口

| 方法/路径 | 说明 |
| --- | --- |
| `GET /audit/v1/key` | 日志身份、算法与原始 Ed25519 公钥（base64url） |
| `GET /audit/v1/head?tree_size=N` | 最新（省略 N）或指定历史大小的签名树头 |
| `GET /audit/v1/inclusion/{index}?tree_size=N` | 指定叶子的包含证明 + 证书 DER + 该快照树头 |
| `GET /audit/v1/consistency?first=a&second=b` | 两个树大小之间的一致性证明（含两端树头） |

二进制值（根、节点、签名、公钥、证书 DER、log_id）一律为**无填充
base64url**。包含证明的叶子、路径与根读自**同一提交快照**。越界/未提交的
树大小、叶子索引返回 `404`，非法大小区间返回 `400`。

### 独立核验

`app/audit_verify.py` 提供与服务端隔离的核验逻辑（不导入数据库或签名代码），
`scripts/audit_demo.py` 是可运行演示。核验**仅凭**：

1. 带外预置的固定公钥（`data/log_pubkey.raw`，**绝不信任响应里自带的公钥**）；
2. 证书 DER、签名树头与证明。

可独立验证：树头签名与 `log_id`、证书包含性、两个树头的历史前缀一致性；
对篡改的叶子/证明/签名、非法大小、多余节点一律拒绝。

```sh
# 服务运行后（默认数据目录 ./data）
.venv/bin/python scripts/audit_demo.py \
  --base http://127.0.0.1:8000 \
  --pinned-key ./data/log_pubkey.raw
```

### curl 速查

```sh
curl -s http://127.0.0.1:8000/audit/v1/key
curl -s http://127.0.0.1:8000/audit/v1/head
curl -s 'http://127.0.0.1:8000/audit/v1/head?tree_size=0'
curl -s http://127.0.0.1:8000/audit/v1/inclusion/0
curl -s 'http://127.0.0.1:8000/audit/v1/consistency?first=1&second=3'
```

## 附带修复

http-01 挑战响应体若不是合法 UTF-8（无法等于纯 ASCII 的 key authorization），
现在明确判定为挑战失败（`400 incorrectResponse`），不再抛未处理异常导致 `500`。

## curl 演示

```sh
# 下载 CA 证书
curl -s http://127.0.0.1:8000/ca/certificate -o ca_cert.pem

# 生成带 SAN 的 CSR
openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj '/CN=api.lab.test' \
  -addext 'subjectAltName=DNS:api.lab.test,DNS:lab.test'

# 签发（用 Python 把 PEM 安全编码进 JSON）
python - <<'PY'
import json, urllib.request
payload = {
    "csr": open("server.csr").read(),
    "days": 7,
    "idempotency_key": "demo-1",
}
req = urllib.request.Request(
    "http://127.0.0.1:8000/certificates",
    data=json.dumps(payload).encode(),
    headers={"Content-Type": "application/json"},
)
body = json.load(urllib.request.urlopen(req))
open("server.pem", "w").write(body["certificate"])
print(body["serial"], body["replayed"])
PY

openssl verify -CAfile ca_cert.pem server.pem

# 查询 / 吊销 / CRL
curl -s http://127.0.0.1:8000/certificates/<serial>
curl -s -X POST http://127.0.0.1:8000/certificates/<serial>/revoke \
  -H 'Content-Type: application/json' -d '{"reason":"key_compromise"}'
curl -s -X POST http://127.0.0.1:8000/crl/publish
curl -s http://127.0.0.1:8000/crl/current.pem -o crl.pem
openssl crl -in crl.pem -noout -CAfile ca_cert.pem -text
```

## ACME curl 演示

ACME 请求体是 JWS（`application/jose+json`），直接用 curl 手写签名不现实；
下面用内联 Python 生成账号密钥、做 JWS 签名，网络仍由 `curl` 风格的 HTTP
调用完成。挑战文件需要由“目标域名”的 HTTP 服务给出——本实验中验证器只连
`127.0.0.1:${LOCAL_CA_HTTP01_PORT}`，所以在该端口起一个静态服务即可。

```sh
# 1) 启动 CA（另一个终端），http-01 校验指向本机 5002 端口
LOCAL_CA_HTTP01_PORT=5002 .venv/bin/python -m uvicorn app.main:app \
  --host 127.0.0.1 --port 8000

# 2) 取目录与 nonce
curl -s http://127.0.0.1:8000/acme/directory | python -m json.tool
curl -s -D - -o /dev/null http://127.0.0.1:8000/acme/new-nonce

# 3) 完整流程：注册账号 → 下单 → 起挑战服务 → finalize → 下载证书
.venv/bin/python - <<'PY'
import json, os, threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import urllib.error
import urllib.request

from app.jws import b64url, jwk_thumbprint, public_jwk, sign_jws

BASE = "http://127.0.0.1:8000"
DOMAIN = "demo.lab.test"

def http(method, url, data=None, headers=None):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        resp = urllib.request.urlopen(req)
    except urllib.error.HTTPError as e:
        resp = e
    return resp

def nonce():
    return http("GET", f"{BASE}/acme/new-nonce").headers["Replay-Nonce"]

# --- account key -----------------------------------------------------------
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
jwk = public_jwk(key.public_key())
thumbprint = jwk_thumbprint(jwk)

def jpost(path, payload_obj, *, kid=None, empty=False):
    url = BASE + path
    identity = {"kid": kid} if kid else {"jwk": jwk}
    if empty:
        body = sign_jws(b"", key, url, nonce(), **identity)
    else:
        body = sign_jws(json.dumps(payload_obj).encode(), key, url, nonce(), **identity)
    return http("POST", url, data=json.dumps(body).encode(),
                headers={"Content-Type": "application/jose+json"})

# --- registration ----------------------------------------------------------
r = jpost("/acme/new-account", {"termsOfServiceAgreed": True})
account_url = r.headers["Location"]
print("account:", r.status, account_url)

# --- order -----------------------------------------------------------------
r = jpost("/acme/new-order",
          {"identifiers": [{"type": "dns", "value": DOMAIN}]}, kid=account_url)
order = json.loads(r.read())
order_url = r.headers["Location"]
authz_url = order["authorizations"][0]
finalize_url = order["finalize"]

r = jpost(authz_url[len(BASE):], None, kid=account_url, empty=True)
authz = json.loads(r.read())
ch = next(c for c in authz["challenges"] if c["type"] == "http-01")

# Serve key authorization at /.well-known/acme-challenge/<token> on the port
# the verifier uses (5002), Host header is ignored by this toy server.
key_auth = ch["token"] + "." + thumbprint
webroot = "/tmp/acme-demo/.well-known/acme-challenge"
os.makedirs(webroot, exist_ok=True)
open(os.path.join(webroot, ch["token"]), "w").write(key_auth)

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory="/tmp/acme-demo", **kw)
    def log_message(self, *a):
        pass

srv = ThreadingHTTPServer(("127.0.0.1", 5002), Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()

r = jpost(ch["url"][len(BASE):], {}, kid=account_url)
print("challenge:", r.status, json.loads(r.read())["status"])

# --- CSR (DER, base64url) --------------------------------------------------
csr_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
csr = (
    x509.CertificateSigningRequestBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DOMAIN)]))
    .add_extension(x509.SubjectAlternativeName([x509.DNSName(DOMAIN)]), False)
    .sign(csr_key, hashes.SHA256())
)
csr_der = csr.public_bytes(serialization.Encoding.DER)

r = jpost(finalize_url[len(BASE):], {"csr": b64url(csr_der)}, kid=account_url)
order = json.loads(r.read())
print("order:", order["status"])

# --- download certificate chain -------------------------------------------
r = jpost(order["certificate"][len(BASE):], None, kid=account_url, empty=True)
open("demo.pem", "wb").write(r.read())
print("certificate chain saved to demo.pem")
srv.shutdown()
PY

curl -s http://127.0.0.1:8000/ca/certificate -o ca_cert.pem
openssl verify -CAfile ca_cert.pem demo.pem
openssl x509 -in demo.pem -noout -subject -ext subjectAltName -dates
```

## 测试

```sh
.venv/bin/python -m pytest -q
```

测试覆盖：CSR/域名/密钥策略、证书扩展与链验证、幂等与并发去重、
吊销原因冲突、CRL 编号并发一致、重启复用，以及 CA 缺失/不匹配拒绝启动。

ACME 测试（`tests/test_acme.py`）额外覆盖：目录/nonce、账号注册复用与跨账号
隔离、JWS 签名/url/nonce 校验、nonce 过期与并发重放、POST-as-GET、
订单域名策略、http-01 成功/错误 body/重定向/超大响应（本机起真实 HTTP
服务校验 `Host` 头与路径）、未验证与过期拒签、CSR SAN 匹配、同订单同 CSR
并发只签一张、不同 CSR 冲突、签发失败不留孤证、重启后继续，以及旧接口
`days` 拒绝布尔/字符串和 ACME 证书与旧接口/CRL 的互通；另覆盖非 UTF-8
挑战响应返回 `400` 而非 `500`，以及 ACME 证书恰好入账一片且失败不留日志。

透明度审计测试（`tests/test_audit.py`）覆盖：空树/叶/节点哈希前缀、对多种
非满树大小的包含与一致性证明及独立参考实现互验、篡改叶子/证明/签名/大小与
多余/非法节点被拒、旧签发与并发签发索引连续无重无跳、幂等重放不增叶、吊销
不改历史、最新与历史树头、同快照包含与一致性接口、越界明确拒绝、旧库按
序列号数值升序一次性迁移与失败整批回滚、重启保留索引/历史根/身份，以及日志
密钥缺失或不匹配拒绝启动。
