# Local Test CA

本机联调用的证书签发与吊销后端（Python 3.10 + FastAPI + cryptography）。
服务只绑定 `127.0.0.1`，无前端，数据与私钥均保存在本机数据目录。

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

## 测试

```sh
.venv/bin/python -m pytest -q
```

测试覆盖：CSR/域名/密钥策略、证书扩展与链验证、幂等与并发去重、
吊销原因冲突、CRL 编号并发一致、重启复用，以及 CA 缺失/不匹配拒绝启动。
