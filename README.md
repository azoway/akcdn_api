# AKCDN API

自建 HTTP 服务：在 [AKCDN](https://cdn.akile.ai/?ref=48521618) 按 `targets` 新建转发规则。额满时可按 `delauto` 腾位。

用 `AKILE_EMAIL` / `AKILE_PASSWORD` 登录上游；会话缓存在本地文件，过期或失效时**自动重新登录**（调用方无感）。暂不支持开启两步验证 / 验证码的账号。

## 快速开始

```bash
cd /path/to/akcdn_api
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # 编辑填入密钥
python3 app.py                     # 默认监听 127.0.0.1:8787
curl -s http://127.0.0.1:8787/healthz
# {"ok":true,"version":"1.0.0"}
```

对外访问示例：`HOST=0.0.0.0 PORT=8787 python3 app.py`（生产更建议本机只听 `127.0.0.1`，前面用 Caddy 反代 HTTPS）。

## 环境变量（`.env`）

| 变量 | 必填 | 说明 |
|------|------|------|
| `AKCDN_API_KEY` | 是 | 调用本服务鉴权；未配则 `/v1/rules` 返回 503 |
| `AKILE_EMAIL` | 是 | Akile 邮箱 |
| `AKILE_PASSWORD` | 是 | Akile 密码 |
| `SESSION_FILE` | 否 | 会话文件路径，默认 `.akcdn_session.json`（相对路径相对项目根） |
| `HOST` | 否 | 默认 `127.0.0.1` |
| `PORT` | 否 | 默认 `8787` |

`.env`、`config.json`、`.akcdn_session.json` 已在 `.gitignore`，勿提交。

## systemd 部署

先创建运行用户（若要用 unit 里的 `User=akcdn`），或把 `User`/`Group` 改成服务器上已有账号：

```bash
# 可选：专用系统用户（无登录壳）
sudo useradd --system --home /opt/akcdn_api --shell /usr/sbin/nologin akcdn

sudo mkdir -p /opt/akcdn_api
sudo rsync -a --exclude .venv ./ /opt/akcdn_api/
sudo chown -R akcdn:akcdn /opt/akcdn_api
sudo -u akcdn bash -lc 'cd /opt/akcdn_api && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt'
sudo -u akcdn cp /opt/akcdn_api/.env.example /opt/akcdn_api/.env
# 编辑 /opt/akcdn_api/.env 填入 AKCDN_API_KEY / AKILE_EMAIL / AKILE_PASSWORD
```

`/etc/systemd/system/akcdn-api.service`：

```ini
[Unit]
Description=AKCDN API
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/akcdn_api
EnvironmentFile=/opt/akcdn_api/.env
ExecStart=/opt/akcdn_api/.venv/bin/python /opt/akcdn_api/app.py
Restart=on-failure
User=akcdn
Group=akcdn

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now akcdn-api
sudo systemctl status akcdn-api
```

## Caddy HTTPS 反代（可选）

本服务可只听本机：`HOST=127.0.0.1` `PORT=8787`。前面用 Caddy 终止 TLS：

```caddy
# /etc/caddy/Caddyfile 片段
api.example.com {
	reverse_proxy 127.0.0.1:8787
}
```

改完后 `sudo systemctl reload caddy`，再 `curl -s https://api.example.com/healthz`。

## 端点

| 方法 | 路径 | 鉴权 | 说明 |
|------|------|------|------|
| `GET` | `/healthz` 或 `/` | 否 | `{"ok":true,"version":"1.0.0"}` |
| `POST` | `/v1/rules` | 是 | 规则 upsert / exists / dry_run |

鉴权头二选一：`Authorization: Bearer <AKCDN_API_KEY>` 或 `X-API-Key: <AKCDN_API_KEY>`。

### curl 示例

```bash
export AKCDN_API_KEY='your-key'

curl -s http://127.0.0.1:8787/healthz
# 经 Caddy：curl -s https://api.example.com/healthz

curl -s -X POST http://127.0.0.1:8787/v1/rules \
  -H "Authorization: Bearer $AKCDN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "delauto": 1,
    "listen_port": "auto",
    "entry_whitelist": "203.0.113.10/32",
    "protocol": "tcp+udp",
    "proxy_protocol": true,
    "targets": [{"host": "203.0.113.10", "port": 443, "weight": 1}]
  }'
```

## POST `/v1/rules` 字段

| 字段 | 说明 |
|------|------|
| `targets` | 必填 `[{host,port,weight}]`；与已有规则 targets 相同 → `action:"exists"`（传了 `entry_whitelist` 时还要求 whitelist 也相同，见下） |
| `name` | 可选；省略用 maxId×2；冲突则改自动名 |
| `node_id` / `node_name` | 默认 `node_id=5`（SH-HK） |
| `listen_port` | 整数或 `"auto"` |
| `protocol` | `tcp` / `udp` / `tcp+udp`（默认后者） |
| `proxy_protocol` / `receive_proxy_protocol` | 默认 false |
| `entry_whitelist` | 可选；显式 IPv4 `/32`（如 `203.0.113.10/32`）；不支持 `auto`。**传了就以 `targets + entry_whitelist` 去重**（仅 targets 相同、whitelist 不同 → 不算重复，走新建）；不传则仍只按 `targets` 去重 |
| `enabled` | 默认 true |
| `delauto` | 顶层，默认 **1**：额度满时 `0`=409 / `1`=删同节点最前 / `2`=删全局最前 |
| `dry_run` | 只算不写；额度满时用 `would_delete` 预览 |

## 响应里的入口 IP

成功响应（`create` / `update` / `exists` / `dry-run`）的 `rule` 对象里带入口地址：

| 字段 | 说明 |
|------|------|
| `listen_port` | 监听端口 |
| `listen_host` | 入口 IP：优先取规则的 `connect_host`，其次 `connect_hosts[0]`，再退回节点的 `connect_host`；旧键（`listen_host`/`listen_ip`/`entry_ip`/`node_ip`/`ip`…）仍兼容 |
| `node_ip` | 与 `listen_host` 同值（语义更直白） |
| `listen` | `"<listen_host>:<listen_port>"`，两者齐全时才有 |

```json
{
  "ok": true,
  "action": "create",
  "rule": {
    "id": 42,
    "name": "22",
    "node_id": 5,
    "node_name": "SH-HK",
    "listen_port": 20001,
    "listen_host": "198.51.100.11",
    "node_ip": "198.51.100.11",
    "listen": "198.51.100.11:20001",
    "protocol": "tcp+udp",
    "entry_whitelist": null,
    "enabled": true
  }
}
```

`exists` 时若匹配到的规则自己没带 `connect_host`，会按它的 `node_id` 去 `/nodes/available` 补一次入口 IP。

## Quantumult X 手动任务

`examples/quanx_akcdn_whitelist.js` 是把「本机公网 IP 加白到一条转发规则」做成一步操作的脚本：取直连 IPv4 → `POST /v1/rules` → 把入口地址写进剪贴板。

直连 IPv4 按下面的顺序试，第一个能解析出公网 IPv4 的就用；全部失败则报错：

1. `https://api-ipv4.ip.sb/ip`
2. `https://ipconfig.io`
3. `https://ddns.oray.com/checkip`
4. `https://whois.pconline.com.cn/ipJson.jsp?json=true`
5. `https://ipv4.icanhazip.com`
6. `https://v4.ident.me`

想在 `argument` 里写 `ip_url=...` 就只用那一个地址，跳过整个列表。

放进 Quantumult X 的 `[task_local]` 里用 `event-interaction`，点任务才跑，不会定时触发：

```ini
[task_local]
event-interaction https://raw.githubusercontent.com/azoway/akcdn_api/main/examples/quanx_akcdn_whitelist.js, tag=AKCDN白名单, img-url=globe.system, enabled=true, argument=token=YOUR_TOKEN&host=203.0.113.10&port=12345
```

参数写在 `argument=` 里，用 `&` 连接（别写成脚本 URL 的 `?argument=`，那样 `$argument` 是空的）。多个转发目标用 `targets`，逗号写成 `%2C`：

```ini
argument=token=YOUR_TOKEN&targets=HOST_A:12345%2CHOST_B:443:2&url=https://YOUR_HOST/akcdn_api/v1/rules
```

常用参数：`token`（必填，不带 `Bearer` 前缀）、`host`+`port` 或 `targets`、`url`、`entry_whitelist`（写了就不查直连 IP）、`listen_port`、`delauto`、`protocol`、`proxy_protocol`、`name`。完整说明写在脚本头部注释里。

## 单测

纯离线，不碰真网（`api.cdn` 全被 stub）：

```bash
source .venv/bin/activate
pip install -r requirements.txt   # 含 pytest
pytest -q
```

覆盖去重判断：未传 `entry_whitelist` → 同 targets 即 `exists`；传了且与已有相同 → `exists`（`matched_by:"targets+whitelist"`）；传了但与已有不同 → 不算重复，走 `create`。

另覆盖入口 IP 解析：`connect_host` / `connect_hosts[0]` 优先、旧键兜底，以及 `create` / `dry-run` / `exists` 响应里的 `listen_host` / `node_ip` / `listen`。

## 登录与会话

链路：`密码登录` → `oauth/app` → `oauth/login` → CDN `/oauth/session`。  
会话文件仍有效则响应里 `login_performed:false`；文件过期或 token 调 `/overview` 失败时自动重登。
