/*
AKCDN：把白名单 IP 写成一条转发规则。

配置文件 -> [task_local] 粘贴下面这一行，保存后在任务里点「AKCDN白名单」。
这是手动任务：event-interaction 不会按时间自动跑。

[task_local]
event-interaction https://raw.githubusercontent.com/azoway/akcdn_api/main/examples/quanx_akcdn_whitelist.js, tag=AKCDN白名单, img-url=globe.system, enabled=true, argument=token=YOUR_TOKEN&host=203.0.113.10&port=12345

参数写在逗号后面的 argument= 里，用 & 连接。不要写进脚本 URL 的 ?argument=，那样 $argument 是空的。
英文逗号用来分隔 tag、img-url、enabled、argument。参数值里的逗号写成 %2C，例如多个转发目标：
argument=token=YOUR_TOKEN&targets=203.0.113.10:12345%2C203.0.113.10:443:2

和现有任务一样，也可以把参数放在脚本链接的 # 后面。同一项两边都写时，以 argument= 为准：
event-interaction https://raw.githubusercontent.com/azoway/akcdn_api/main/examples/quanx_akcdn_whitelist.js#token=YOUR_TOKEN&host=203.0.113.10&port=12345, tag=AKCDN, img-url=globe.system, enabled=false

链接用仓库 raw 地址。也可把脚本文件内容本地托管后改 URL。

参数：
  token                      必填。Bearer，不要带 Bearer 前缀
  host、port                 单个转发目标。和 targets 二选一
  weight                     默认 1
  targets                    多个目标，host:port 或 host:port:weight，目标之间用 %2C
  entry_whitelist            写了就用这个值，不再查询直连 IP
  listen_port                默认 auto。写数字则固定入口端口，例如 listen_port=11015
  url                        默认 https://YOUR_HOST/akcdn_api/v1/rules
  delauto                    默认 1
  protocol                   默认 tcp+udp。要编码时写成 tcp%2Budp
  proxy_protocol             默认 false。可写 true/false 或 1/0
  receive_proxy_protocol     默认 false
  name                       不传则由服务端命名
  ip_url                     直连 IP 只查这个地址，跳过默认列表。默认按顺序试这六个：
                             1. https://api-ipv4.ip.sb/ip
                             2. https://ipconfig.io
                             3. https://ddns.oray.com/checkip
                             4. https://whois.pconline.com.cn/ipJson.jsp?json=true
                             5. https://ipv4.icanhazip.com
                             6. https://v4.ident.me
                             第一个能抠出公网 IPv4 的就用，全挂了才报错

没写 entry_whitelist 时，用直连策略取本机公网 IPv4。建规则的请求仍走当前策略。
listen_port=auto 时，每次新建的入口端口可能变化。
创建成功后点这条通知，会把入口地址写入剪贴板。系统需允许 Quantumult X 发通知。
*/

const DEFAULT_API = "https://YOUR_HOST/akcdn_api/v1/rules";
// 直连 IP 查询地址，按顺序试，取第一个能抠出公网 IPv4 的。
// api-ipv4.ip.sb 首选（纯 IPv4、响应干净），ipconfig.io 走独立线路，
// 其余是国内可达的备用源。改这个列表时同步改文件头部注释。
const IP_URLS = [
  "https://api-ipv4.ip.sb/ip",
  "https://ipconfig.io",
  "https://ddns.oray.com/checkip",
  "https://whois.pconline.com.cn/ipJson.jsp?json=true",
  "https://ipv4.icanhazip.com",
  "https://v4.ident.me",
];

function parseArgument(raw) {
  const out = {};
  String(raw || "")
    .split("&")
    .forEach((part) => {
      if (!part) return;
      const idx = part.indexOf("=");
      const key = decodeURIComponent(idx === -1 ? part : part.slice(0, idx)).trim();
      const value = decodeURIComponent(idx === -1 ? "" : part.slice(idx + 1)).trim();
      if (key) out[key] = value;
    });
  return out;
}

function scriptParams() {
  const sourcePath =
    typeof $environment !== "undefined" && $environment && $environment.sourcePath
      ? String($environment.sourcePath)
      : "";
  const hashIndex = sourcePath.indexOf("#");
  const fromHash = hashIndex >= 0 ? sourcePath.slice(hashIndex + 1) : "";
  const fromOption = typeof $argument === "string" ? $argument : "";
  return Object.assign(parseArgument(fromHash), parseArgument(fromOption));
}

function toBool(value, fallback) {
  if (value == null || value === "") return fallback;
  const text = String(value).toLowerCase();
  if (["1", "true", "yes", "on"].includes(text)) return true;
  if (["0", "false", "no", "off"].includes(text)) return false;
  throw new Error(`无法识别的布尔值: ${value}`);
}

function toInt(value, fallback) {
  if (value == null || value === "") return fallback;
  const num = Number(value);
  if (!Number.isInteger(num)) throw new Error(`无法识别的整数: ${value}`);
  return num;
}

function listenPort(value) {
  const text = value == null || value === "" ? "auto" : String(value);
  return /^\d+$/.test(text) ? Number(text) : text;
}

function parseTargetItem(item) {
  const text = String(item || "").trim();
  if (!text) return null;
  const parts = text.split(":");
  if (parts.length < 2) {
    throw new Error(`转发目标格式错误: ${text}，应为 host:port 或 host:port:weight`);
  }
  const weight = parts.length >= 3 ? Number(parts.pop()) : 1;
  const port = Number(parts.pop());
  const host = parts.join(":");
  if (!host || !Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`转发目标格式错误: ${text}`);
  }
  if (!Number.isInteger(weight) || weight <= 0) {
    throw new Error(`权重错误: ${text}`);
  }
  return { host, port, weight };
}

function buildTargets(args) {
  if (args.targets) {
    const targets = args.targets
      .split(",")
      .map(parseTargetItem)
      .filter(Boolean);
    if (!targets.length) throw new Error("targets 为空");
    return targets;
  }
  if (!args.host || !args.port) {
    throw new Error("缺少转发目标，argument 需要 host 和 port，或 targets");
  }
  return [
    parseTargetItem(
      `${args.host}:${args.port}${args.weight ? `:${args.weight}` : ""}`
    ),
  ];
}

function isPublicIPv4(ip) {
  const parts = String(ip)
    .split(".")
    .map((item) => Number(item));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return false;
  }
  const [a, b] = parts;
  if (a === 0 || a === 10 || a === 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a >= 224) return false;
  return true;
}

function extractPublicIPv4(text) {
  const matched = String(text).match(
    /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g
  );
  if (!matched) return "";
  return matched.find(isPublicIPv4) || "";
}

function reasonText(error) {
  if (!error) return "未知错误";
  if (typeof error === "string") return error;
  return error.error || error.message || JSON.stringify(error);
}

function fetchText(url, timeout) {
  return $task
    .fetch({
      url,
      method: "GET",
      timeout,
      headers: {
        Accept: "text/plain, application/json, */*",
        "User-Agent":
          "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Quantumult X",
      },
      opts: {
        policy: "direct",
        redirection: true,
      },
    })
    .then((res) => {
      const code = Number(res && (res.statusCode != null ? res.statusCode : res.status));
      if (code && (code < 200 || code >= 300)) {
        throw new Error(`${url} HTTP ${code}`);
      }
      return String((res && res.body) || "");
    });
}

async function getDirectIPv4(ipUrl) {
  const urls = ipUrl ? [ipUrl] : IP_URLS;
  const errors = [];
  for (const url of urls) {
    try {
      const body = await fetchText(url, 8);
      const ip = extractPublicIPv4(body);
      if (ip) {
        console.log(`直连 IP ${ip} <- ${url}`);
        return ip;
      }
      errors.push(`${url} 没有公网 IPv4: ${body.replace(/\s+/g, " ").slice(0, 80)}`);
    } catch (error) {
      errors.push(`${url} ${reasonText(error)}`);
    }
  }
  throw new Error(`获取直连 IP 失败\n${errors.join("\n")}`);
}

function buildBody(args, ip) {
  const body = {
    delauto: toInt(args.delauto, 1),
    listen_port: listenPort(args.listen_port),
    entry_whitelist: ip,
    protocol: args.protocol || "tcp+udp",
    proxy_protocol: toBool(args.proxy_protocol, false),
    receive_proxy_protocol: toBool(args.receive_proxy_protocol, false),
    targets: buildTargets(args),
  };
  if (args.name) body.name = args.name;
  return body;
}

function bearerToken(token) {
  const text = String(token || "").trim();
  return /^bearer\s+/i.test(text) ? text.replace(/^bearer\s+/i, "") : text;
}

function postRule(url, token, body) {
  return $task.fetch({
    url,
    method: "POST",
    timeout: 30,
    headers: {
      Authorization: `Bearer ${bearerToken(token)}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(body),
  });
}

function describeSuccess(data) {
  const rule = data.rule || {};
  const listen =
    rule.listen ||
    (rule.listen_host && rule.listen_port
      ? `${rule.listen_host}:${rule.listen_port}`
      : "");
  const targets = (rule.targets || [])
    .map((item) => `${item.host}:${item.port}`)
    .join(", ");
  const lines = [
    listen ? `入口 ${listen} ` : "",
    "",
    rule.entry_whitelist ? `白名单 ${rule.entry_whitelist}` : "",
    targets ? `转发 ${targets}` : "",
    rule.node_name ? `节点 ${rule.node_name}` : "",
    rule.name ? `规则 ${rule.name}${rule.id != null ? ` / id ${rule.id}` : ""}` : "",
  ];
  if (data.quota) {
    lines.push(
      `配额 ${data.quota.used}/${data.quota.limit}，剩余 ${data.quota.remaining}`
    );
  }
  return {
    listen,
    message: lines.filter(Boolean).join("\n"),
  };
}

(async () => {
  try {
    const args = scriptParams();
    if (!args.token) {
      throw new Error("argument 缺少 token");
    }
    const preset = String(args.entry_whitelist || "").trim();
    const ip = preset || (await getDirectIPv4(args.ip_url));
    if (preset) console.log(`使用 argument 白名单 ${preset}`);
    const payload = buildBody(args, ip);
    console.log(`创建规则 ${JSON.stringify(payload)}`);
    const res = await postRule(args.url || DEFAULT_API, args.token, payload);
    const code = Number(res && (res.statusCode != null ? res.statusCode : res.status));
    let data;
    try {
      data = JSON.parse(res.body || "");
    } catch (error) {
      throw new Error(
        `接口不是 JSON\nHTTP ${code || "?"}\n${String(res.body || "").slice(0, 300)}`
      );
    }
    if ((code && (code < 200 || code >= 300)) || data.ok === false) {
      throw new Error(data.message || data.msg || JSON.stringify(data).slice(0, 500));
    }
    const result = describeSuccess(data);
    console.log(result.message);
    if (result.listen) {
      $notify("AKCDN 白名单", result.listen, result.message, {
        "update-pasteboard": result.listen,
      });
    } else {
      $notify("AKCDN 白名单", ip, result.message);
    }
  } catch (error) {
    const message = reasonText(error);
    console.log(message);
    $notify("AKCDN 白名单", "失败", message);
  } finally {
    $done();
  }
})();
