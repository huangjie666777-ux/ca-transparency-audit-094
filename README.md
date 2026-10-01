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
- 重启时复用同一 CA 与 SQLite 记录。
- 已有数据库但 CA 私钥/证书缺失、只存在其一、密钥与证书不匹配，或证书与
  数据库绑定的指纹不一致时，服务拒绝启动（`app.ca.CAError`），不会静默换 CA。

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
- `ca.sqlite3`：证书记录、幂等键、吊销状态与 CRL 编号（WAL 模式）。

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

## 透明度审计日志（RFC 6962）

签发（含传统签发与 ACME 签发）的证书 DER 会追加到一棵 **Merkle 树**日志，
供运维核对入账与历史完整性。纯后端实现，无 SCT。

### 格式与边界

- 叶输入为**完整证书 DER**，叶哈希 = `SHA256(0x00 || DER)`。
- 节点哈希 = `SHA256(0x01 || left || right)`；空树根 = `SHA256("")`。
- 叶索引从 0 连续递增；证书、幂等关联与日志在**同一事务**提交，
  失败不留单边记录。幂等重放不增叶，吊销不删历史，并发不跳号/重号。
- 树节点持久化到 SQLite（`log_nodes`），追加只更新必要路径；支持非满树，
  根与证明从存储节点计算，不重算全库、不返回全部叶子代替证明。
- 树头绑定日志身份、大小与根，由**独立持久 Ed25519 密钥**签名
  （`log_key.pem`，与 CA 的 RSA 密钥分离）。签名消息格式：
  `HEAD_PREFIX || log_id(16 字节) || tree_size(8 字节大端) || root_hash(32 字节)`，
  其中 `HEAD_PREFIX` 为 ASCII `ltca-transparency-log-head` 加一个零字节。
- 证明读取在**同一快照事务**内完成；越界请求明确拒绝。

### 启动迁移

- 启动时若日志未初始化，对旧库证书按**序列号数值升序**一次性建日志，
  再开放签发；迁移失败整批回滚。
- 重启保留索引、历史根与日志身份。已有日志但签名密钥缺失或不匹配时
  **拒绝启动**（`app.log_signing.LogKeyError`）。

### 审计接口

| 方法/路径 | 说明 |
| --- | --- |
| `GET /log/public-key` | 日志身份与 Ed25519 公钥（原始 base64url + PEM） |
| `GET /log/head` | 最新签名树头 |
| `GET /log/head/{size}` | 指定大小的历史签名树头 |
| `GET /log/proof/inclusion/{index}?size={size}` | 包含证明（默认最新大小） |
| `GET /log/proof/consistency?old={m}&new={n}` | 两个树大小间的一致性证明 |

### 独立验证

`app/verify.py` 提供不依赖数据库/网络的验证逻辑，仅凭预置信任公钥、
证书、树头和证明核验包含性与历史前缀一致性；拒绝篡改、非法大小或多余节点，
不信任响应自带公钥。

演示脚本：

```sh
# 把信任的公钥（out-of-band 获取）存到文件
curl -s http://127.0.0.1:8000/log/public-key \
  | python -c "import sys,json; print(json.load(sys.stdin)['public_key'])" \
  > log_pub.b64

# 验证证书包含性 + 与历史大小 1 的一致性
.venv/bin/python -m app.audit_verify \
  --base-url http://127.0.0.1:8000 \
  --trust-key log_pub.b64 \
  --cert server.pem \
  --old-size 1
```

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

透明度审计测试（`tests/test_audit_*.py`）覆盖：RFC 6962 叶/节点/空树
向量、包含证明与一致性证明的生成-验证模糊测试（40 叶内全部索引）、
篡改/非法大小/多余节点拒绝、签发追加连续叶、幂等重放不增叶、吊销保留
历史、并发不重号不跳号、ACME 签发入日志、旧库按序列号数值升序迁移、
迁移失败整批回滚、重启保留根与日志身份、签名密钥缺失/不匹配拒绝启动、
审计接口（公钥、最新/历史树头、包含/一致性证明、越界拒绝）、独立验证
逻辑拒绝篡改与非法大小，以及非 UTF-8 挑战响应返回 400 而非 500。

ACME 测试（`tests/test_acme.py`）额外覆盖：目录/nonce、账号注册复用与跨账号
隔离、JWS 签名/url/nonce 校验、nonce 过期与并发重放、POST-as-GET、
订单域名策略、http-01 成功/错误 body/重定向/超大响应（本机起真实 HTTP
服务校验 `Host` 头与路径）、未验证与过期拒签、CSR SAN 匹配、同订单同 CSR
并发只签一张、不同 CSR 冲突、签发失败不留孤证、重启后继续，以及旧接口
`days` 拒绝布尔/字符串和 ACME 证书与旧接口/CRL 的互通。
