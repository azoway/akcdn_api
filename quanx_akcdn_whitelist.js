/*
AKCDN：把本机公网 IPv4 写成一条已有规则的入口白名单。

配置文件 -> [task_local] 粘贴下面这一行，保存后在任务里点「AKCDN白名单」。
event-interaction 不会按时间自动跑。

[task_local]
event-interaction https://raw.githubusercontent.com/azoway/akcdn_api/master/quanx_akcdn_whitelist.js, tag=AKCDN白名单, img-url=globe.system, enabled=true, argument=token=ak_你的密钥&id=12345

参数写在逗号后面的 argument= 里，用 & 连接。不要写进脚本 URL 的 ?argument=，那样 $argument 是空的。
也可以把参数放在脚本链接的 # 后面。同一项两边都写时，以 argument= 为准。

不写 id 时，先拉官方规则列表，更新最后一条。列表越老越靠前，前面的规则不会被改。

argument=token=ak_你的密钥

参数：
  token                      必填。控制台 API 密钥
  id                         规则 id。不写则更新列表最后一条。rule_id 同样可用
  entry_whitelist            写了就用这个 IPv4，不再查询直连 IP。可带 /32
  ip_url                     直连 IP 只查这个地址。不写则按顺序试：
                             1. https://api-ipv4.ip.sb/ip
                             2. https://ipconfig.io
                             3. https://ddns.oray.com/checkip
                             4. https://whois.pconline.com.cn/ipJson.jsp?json=true
                             5. https://ipv4.icanhazip.com
                             6. https://v4.ident.me

host、port、targets 会忽略。官方接口只能改已有规则的白名单。
查 IP 和改白名单都走直连。
*/

const OPEN_API = "https://cdnapi.akile.ai/api/open";
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

function apiToken(value) {
  return String(value || "").trim();
}

function explicitRuleId(args) {
  const raw = args.id || args.rule_id || "";
  if (!raw) return null;
  if (!/^\d+$/.test(String(raw))) {
    throw new Error(`规则 id 必须是正整数: ${raw}`);
  }
  const num = Number(raw);
  if (!Number.isInteger(num) || num <= 0) {
    throw new Error(`规则 id 必须是正整数: ${raw}`);
  }
  return num;
}

function positiveId(value) {
  if (typeof value === "number" && Number.isInteger(value) && value > 0) return value;
  if (typeof value === "string" && /^\d+$/.test(value)) {
    const num = Number(value);
    if (num > 0) return num;
  }
  return null;
}

function latestRule(rules) {
  if (!Array.isArray(rules) || !rules.length) {
    throw new Error("账号下没有可更新的转发规则");
  }
  for (let i = rules.length - 1; i >= 0; i -= 1) {
    const rule = rules[i];
    const id = positiveId(rule && rule.id);
    if (id) return Object.assign({}, rule, { id });
  }
  throw new Error("规则列表里没有可用 id");
}

function normalizeWhitelist(value) {
  const text = String(value || "").trim();
  const matched = text.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/32)?$/);
  if (!matched) throw new Error(`白名单不是单个 IPv4: ${value}`);
  const octets = [1, 2, 3, 4].map((index) => Number(matched[index]));
  if (octets.some((n) => n > 255)) throw new Error(`白名单不是合法 IPv4: ${value}`);
  return octets.join(".");
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

function errorText(data, code, raw) {
  if (data && typeof data.error === "string" && data.error) return data.error;
  if (data && data.error && data.error.message) return data.error.message;
  if (data && typeof data.message === "string" && data.message) return data.message;
  return `HTTP ${code || "?"}\n${String(raw || "").slice(0, 300)}`;
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

function requestJSON(method, url, token, body) {
  const headers = {
    Accept: "application/json",
    "X-API-Key": token,
  };
  const req = {
    url,
    method,
    timeout: 30,
    headers,
    opts: {
      policy: "direct",
      redirection: true,
    },
  };
  if (body != null) {
    headers["Content-Type"] = "application/json";
    req.body = JSON.stringify(body);
  }
  return $task.fetch(req).then((res) => {
    const code = Number(res && (res.statusCode != null ? res.statusCode : res.status));
    const raw = String((res && res.body) || "");
    let data = null;
    if (raw) {
      try {
        data = JSON.parse(raw);
      } catch (error) {
        throw new Error(`接口不是 JSON\nHTTP ${code || "?"}\n${raw.slice(0, 300)}`);
      }
    }
    if (code && (code < 200 || code >= 300)) {
      throw new Error(errorText(data, code, raw));
    }
    if (data && data.error && data.data == null) {
      throw new Error(errorText(data, code, raw));
    }
    if (data && Object.prototype.hasOwnProperty.call(data, "data")) return data.data;
    return data;
  });
}

function describeSuccess(rule, pickedLatest) {
  const lines = [];
  if (pickedLatest) lines.push("未指定规则 id，已更新列表最后一条");
  const name = rule.name ? String(rule.name) : "";
  if (name && rule.id != null) lines.push(`规则 ${name} / id ${rule.id}`);
  else if (name) lines.push(`规则 ${name}`);
  else if (rule.id != null) lines.push(`规则 id ${rule.id}`);
  if (rule.listen_port) lines.push(`端口 ${rule.listen_port}`);
  if (rule.node_name) lines.push(`节点 ${rule.node_name}`);
  if (rule.entry_whitelist) lines.push(`白名单 ${rule.entry_whitelist}`);
  if (rule.previous) lines.push(`之前 ${rule.previous}`);
  lines.push(rule.changed === false ? "未变化" : "已更新");
  return lines.join("\n");
}

async function main() {
  try {
    const args = scriptParams();
    const token = apiToken(args.token || args.key || "");
    if (!token) throw new Error("argument 缺少 token");
    if (args.host || args.port || args.targets) {
      console.log("已忽略 host/port/targets：官方接口只能改已有规则的白名单");
    }

    const preset = String(args.entry_whitelist || "").trim();
    const ip = preset ? normalizeWhitelist(preset) : await getDirectIPv4(args.ip_url);
    if (preset) console.log(`使用 argument 白名单 ${ip}`);

    let ruleId = explicitRuleId(args);
    let picked = null;
    let pickedLatest = false;
    if (ruleId == null) {
      const rules = await requestJSON("GET", `${OPEN_API}/rules`, token);
      picked = latestRule(rules);
      ruleId = picked.id;
      pickedLatest = true;
      console.log(`未指定规则 id，使用最新一条 ${picked.name || ""} / id ${ruleId}`);
    }

    const updated = await requestJSON(
      "PUT",
      `${OPEN_API}/rules/${ruleId}/entry-whitelist`,
      token,
      { entry_whitelist: ip }
    );
    const rule = Object.assign({}, picked || {}, updated || {});
    const message = describeSuccess(rule, pickedLatest);
    console.log(message);
    $notify("AKCDN 白名单", rule.entry_whitelist || ip, message);
  } catch (error) {
    const message = reasonText(error);
    console.log(message);
    $notify("AKCDN 白名单", "失败", message);
  }
}

if (typeof $task !== "undefined") {
  main().finally(() => {
    $done();
  });
}
