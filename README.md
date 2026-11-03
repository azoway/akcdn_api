# AKCDN 白名单

Quantumult X 手动任务。读取本机公网 IPv4，调用 [AKCDN 开放接口](https://cdn.akile.ai/console/api-keys)，替换一条已有转发规则的入口白名单。

转发规则在控制台创建和修改。这个任务只改白名单。

密钥在控制台「API 密钥」创建，权限与账号相同。写在任务参数里，不要放进仓库。

## 添加任务

脚本在仓库根目录：`quanx_akcdn_whitelist.js`。配置文件里的 `[task_local]`：

```ini
[task_local]
event-interaction https://raw.githubusercontent.com/azoway/akcdn_api/master/quanx_akcdn_whitelist.js, tag=AKCDN白名单, img-url=globe.system, enabled=true, argument=token=ak_你的密钥&id=12345
```

`event-interaction` 只在点任务时运行。

参数写在 `argument=` 里，用 `&` 连接。不要写成脚本地址后面的 `?argument=`，那样读到的参数是空的。

也可以把参数放在脚本链接的 `#` 后面。同一项两边都写时，以 `argument=` 为准：

```ini
event-interaction https://raw.githubusercontent.com/azoway/akcdn_api/master/quanx_akcdn_whitelist.js#token=ak_你的密钥&id=12345, tag=AKCDN白名单, img-url=globe.system, enabled=true
```

指定 `id` 就只改这一条。不写 `id` 时，脚本先取规则列表，再改最后一条：

```ini
argument=token=ak_你的密钥
```

官方列表越老越靠前。不写 id 时改的是最后一条，前面的规则保持原样。

## 参数

| 参数 | 说明 |
|------|------|
| `token` | 必填。控制台 API 密钥。`key` 同样可用 |
| `id` | 规则 id。不写则更新列表最后一条。`rule_id` 同样可用 |
| `entry_whitelist` | 写了就用这个 IPv4，不再查本机 IP。可以带 `/32` |
| `ip_url` | 只向这个地址查本机 IP。不写则按下面的顺序试 |

`host`、`port`、`targets` 会被忽略。

## 本机 IP

查 IP 和改白名单都走直连，不走代理策略。默认按顺序用第一个公网 IPv4：

1. `https://api-ipv4.ip.sb/ip`
2. `https://ipconfig.io`
3. `https://ddns.oray.com/checkip`
4. `https://whois.pconline.com.cn/ipJson.jsp?json=true`
5. `https://ipv4.icanhazip.com`
6. `https://v4.ident.me`

## 通知

成功时通知里有规则名、id、监听端口、新白名单和原来的值。值没变时显示「未变化」。失败时副标题是「失败」，正文是接口返回的原因。

开放接口不返回入口 IP，通知不会写入剪贴板。

## 脚本请求

- `GET https://cdnapi.akile.ai/api/open/rules`
- `PUT https://cdnapi.akile.ai/api/open/rules/<id>/entry-whitelist`

请求头是 `X-API-Key`。请求体是 `{"entry_whitelist":"203.0.113.10"}`。只接受一个 IPv4，可以带 `/32`。每个来源 IP 每分钟最多 120 次。
