"""POST /v1/rules — upsert / exists / dry_run / delauto."""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any, Optional

from . import DEFAULT_NODE_ID, META_KEYS
from .auth import resolve_token
from .errors import ApiError
from . import http_client as api
from .util import (
    as_int,
    extract_list,
    id_of,
    node_id_of,
    normalize_name,
    normalize_whitelist,
    parse_traffic,
    pick,
    req_bool,
    req_str,
    unwrap,
)


def upsert_rule(body: Any) -> dict:
    if not isinstance(body, dict) or isinstance(body, list):
        raise ApiError("config_invalid", "请求体必须是 JSON 对象（单条 rule）", 400)

    dry_run = bool(body.get("dry_run"))
    delauto = parse_delauto(body)
    if (
        isinstance(body.get("rule"), dict)
        and not isinstance(body.get("rule"), list)
    ):
        rule_raw = pick(body["rule"], lambda k: k not in META_KEYS)
    else:
        rule_raw = pick(body, lambda k: k not in META_KEYS)

    rule = parse_rule(rule_raw)
    resolved = resolve_token()
    token = resolved["token"]
    login_performed = resolved["login_performed"]

    def with_login(err: Exception) -> Exception:
        if isinstance(err, ApiError):
            err.login_performed = login_performed
        return err

    try:
        overview = unwrap(api.cdn("GET", "/overview", token=token))
        if not isinstance(overview, dict):
            overview = {}
        pack = check_subscription(overview)
        rules = list_rules(token)

        def quota_of(lst):
            q = rule_quota(overview, lst)
            rem = None
            if q["limit"] is not None and q["used"] is not None:
                rem = max(q["limit"] - q["used"], 0)
            return {"used": q["used"], "limit": q["limit"], "remaining": rem}

        # 传了 entry_whitelist → targets + whitelist 都相同才算重复；否则沿用只按 targets 去重。
        wanted_whitelist = rule["entry_whitelist"] or ""
        dup = find_rule_by_targets(rules, rule["targets"], wanted_whitelist or None)
        if dup:
            if wanted_whitelist:
                matched_by = "targets+whitelist"
                message = (
                    "已存在相同 targets 与 entry_whitelist"
                    f"（{wanted_whitelist}）的规则，未新建也未更新"
                )
            else:
                matched_by = "targets"
                message = "已存在相同 targets 的规则，未新建也未更新"
            summary = summarize_rule(dup)
            if not summary.get("node_ip"):
                fallback = node_by_id(token, dup.get("node_id"))
                if fallback:
                    summary = summarize_rule(dup, fallback)
            return {
                "ok": True,
                "action": "exists",
                "login_performed": login_performed,
                "matched_by": matched_by,
                "delauto": delauto,
                "deleted": False,
                "deleted_rule": None,
                "rule": summary,
                "account": pack,
                "quota": quota_of(rules),
                "message": message,
            }

        named = resolve_rule_name(rules, rule["name"])
        final_name = named["name"]
        name_source = named["name_source"]
        rule["name"] = final_name
        existing = find_rule_by_name(rules, rule["name"])
        quota = rule_quota(overview, rules)
        limit, used = quota["limit"], quota["used"]

        node = resolve_node(token, rule)
        if node.get("online") is False:
            raise ApiError("node_offline", f"入口节点当前离线: {node['name']}", 409, "换节点或等恢复后重试")

        action = "update" if existing else "create"
        existing_id = existing["id"] if existing else None
        if existing and existing_id is None:
            raise ApiError(
                "rule_unaddressable",
                f"规则 {rule['name']} 存在但没有 id",
                409,
                None,
                existing.get("raw"),
            )

        deleted = False
        deleted_rule = None
        would_delete = None

        if action == "create" and limit is not None and used is not None and used >= limit:
            if delauto == 0:
                raise ApiError(
                    "rule_quota_exceeded",
                    f"规则额度不足：已用 {used} / 上限 {limit}",
                    409,
                    "传 delauto=1（同节点）或 delauto=2（全局）以自动腾出名额，或手动删规则",
                    {"used": used, "limit": limit, "remaining": max(limit - used, 0), "delauto": delauto},
                )
            if dry_run:
                victim = pick_auto_delete_victim(rules, delauto, node["id"])
                if not victim:
                    raise ApiError(
                        "rule_quota_exceeded",
                        f"规则额度不足且找不到可按 delauto={delauto} 删除的规则",
                        409,
                        "同节点下没有可删规则，可试 delauto=2" if delauto == 1 else "规则列表为空或无法解析 id",
                        {"used": used, "limit": limit, "remaining": 0, "delauto": delauto},
                    )
                would_delete = summarize_deleted_rule(victim)
            else:
                freed = free_quota_by_delete(
                    token, rules, delauto=delauto, node_id=node["id"], limit=limit, used=used
                )
                deleted = freed["deleted"]
                deleted_rule = freed["deleted_rule"]
                rules = freed["rules"]
                used = freed["used"]
                if name_source == "client" and final_name and not find_rule_by_name(rules, final_name):
                    rule["name"] = final_name
                else:
                    renamed = resolve_rule_name(rules, None)
                    rule["name"] = renamed["name"]
                    name_source = renamed["name_source"]
                existing = find_rule_by_name(rules, rule["name"])
                if existing:
                    raise ApiError(
                        "rule_name_conflict",
                        f"腾出名额后规则名仍冲突: {rule['name']}",
                        409,
                        "省略 name 让服务端重新生成",
                    )

        listen_port = resolve_port(token, node, rule["listen_port"], existing)
        payload = {
            "name": rule["name"],
            "node_id": node["id"],
            "listen_port": listen_port,
            "protocol": rule["protocol"],
            "proxy_protocol": rule["proxy_protocol"],
            "receive_proxy_protocol": rule["receive_proxy_protocol"],
            "entry_whitelist": rule["entry_whitelist"],
            "targets": rule["targets"],
            "enabled": rule["enabled"],
        }

        if dry_run:
            out = {
                "ok": True,
                "action": "dry-run",
                "would": action,
                "login_performed": login_performed,
                "name_source": name_source,
                "delauto": delauto,
                "deleted": False,
                "deleted_rule": None,
                "rule": _with_entry(
                    {
                        "id": existing_id,
                        "name": rule["name"],
                        "node_name": node["name"],
                        "node_id": node["id"],
                        "listen_port": listen_port,
                        "entry_whitelist": rule["entry_whitelist"] or None,
                    },
                    entry_point(_dry_entry_source(existing, listen_port), node),
                ),
                "payload": payload,
                "account": pack,
                "quota": {
                    "used": used,
                    "limit": limit,
                    "remaining": max(limit - used, 0) if limit is not None and used is not None else None,
                },
            }
            if would_delete:
                out["would_delete"] = would_delete
                out["quota"] = {
                    "used": used - 1 if used is not None else None,
                    "limit": limit,
                    "remaining": max(limit - (used - 1), 0)
                    if limit is not None and used is not None
                    else None,
                }
            return out

        if action == "create":
            response = api.cdn("POST", "/rules", token=token, body=payload)
        else:
            response = api.cdn("PUT", f"/rules/{existing_id}", token=token, body=payload)

        data = unwrap(response)
        merged = dict(payload)
        if isinstance(data, dict):
            for key in ("id", "rule_id"):
                if data.get(key) is not None:
                    merged[key] = data[key]
            for key in (
                "connect_host",
                "connect_hosts",
                "listen_host",
                "listen_ip",
                "entry_ip",
                "node_ip",
                "ip",
                "host",
                "address",
                "listen_address",
            ):
                if isinstance(data.get(key), str) and data[key].strip():
                    merged[key] = data[key].strip()
            if isinstance(data.get("node"), dict):
                merged["node"] = data["node"]

        final_id = id_of(merged)
        if final_id is None:
            final_id = existing_id
        merged["listen_port"] = listen_port
        listen = listen_address(merged, node)
        if not listen:
            point = entry_point(merged, node)
            listen = {"host": point["host"], "port": listen_port} if point["host"] else None
        used_after = used + 1 if action == "create" and used is not None else used
        out = {
            "ok": True,
            "action": action,
            "login_performed": login_performed,
            "name_source": name_source,
            "delauto": delauto,
            "deleted": deleted,
            "deleted_rule": deleted_rule,
            "rule": _with_entry(
                {
                    "id": final_id,
                    "name": rule["name"],
                    "node_name": node["name"],
                    "node_id": node["id"],
                    "listen_port": listen_port,
                    "protocol": rule["protocol"],
                    "entry_whitelist": rule["entry_whitelist"] or None,
                    "proxy_protocol": rule["proxy_protocol"],
                    "receive_proxy_protocol": rule["receive_proxy_protocol"],
                    "enabled": rule["enabled"],
                    "targets": rule["targets"],
                },
                listen or entry_point(merged, node),
            ),
            "account": pack,
            "quota": {
                "used": used_after,
                "limit": limit,
                "remaining": max(limit - used_after, 0)
                if limit is not None and used_after is not None
                else None,
            },
        }
        return out
    except Exception as err:
        raise with_login(err)


def parse_delauto(body: dict) -> int:
    raw = body.get("delauto")
    if raw is None and isinstance(body.get("rule"), dict):
        raw = body["rule"].get("delauto")
    if raw is None or raw == "":
        return 1
    if isinstance(raw, (int, float)):
        n = int(raw)
    else:
        try:
            n = int(str(raw).strip(), 10)
        except ValueError:
            n = -1
    if n not in (0, 1, 2):
        raise ApiError(
            "config_invalid",
            "delauto 只能是 0 / 1 / 2",
            400,
            "0=不删 1=删同节点最前 2=删全局最前",
        )
    return n


def parse_rule(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise ApiError("config_invalid", "rule 必须是对象", 400)

    name = None
    if isinstance(raw.get("name"), str) and raw["name"].strip():
        name = raw["name"].strip()
    elif raw.get("name") is not None and raw.get("name") != "":
        raise ApiError(
            "config_invalid",
            "rule.name 必须是字符串（也可省略，由服务端按 maxId*2 生成）",
            400,
        )

    protocol = str(raw.get("protocol") or "tcp+udp").strip().lower()
    if protocol not in ("tcp", "udp", "tcp+udp"):
        raise ApiError(
            "config_invalid",
            f"rule.protocol 非法: {protocol}",
            400,
            "可选 tcp / udp / tcp+udp",
        )

    entry_whitelist = "" if raw.get("entry_whitelist") is None else str(raw["entry_whitelist"]).strip()
    if entry_whitelist.lower() == "auto":
        raise ApiError(
            "config_invalid",
            'entry_whitelist 不再支持 "auto"，请显式传入 IPv4 /32（如 203.0.113.10/32）',
            400,
        )
    if entry_whitelist:
        entry_whitelist = normalize_whitelist(entry_whitelist)

    listen_port = raw.get("listen_port")
    if listen_port is None or (
        isinstance(listen_port, str) and listen_port.strip().lower() in ("", "auto")
    ):
        listen_port = "auto"
    elif isinstance(listen_port, str) and re.match(r"^\d+$", listen_port.strip()):
        listen_port = int(listen_port.strip(), 10)
    elif not isinstance(listen_port, int) or isinstance(listen_port, bool):
        raise ApiError("config_invalid", 'rule.listen_port 必须是整数或 "auto"', 400)
    if isinstance(listen_port, int) and (listen_port < 1 or listen_port > 65535):
        raise ApiError("config_invalid", f"rule.listen_port 超出范围: {listen_port}", 400)

    targets_raw = raw.get("targets")
    if not isinstance(targets_raw, list) or not targets_raw:
        raise ApiError("config_invalid", "rule.targets 必须是非空数组", 400)
    targets = []
    for i, item in enumerate(targets_raw):
        if not isinstance(item, dict):
            raise ApiError("config_invalid", f"rule.targets[{i + 1}] 必须是对象", 400)
        host = req_str(item, "host", f"rule.targets[{i + 1}]")
        port = item.get("port")
        if isinstance(port, str) and re.match(r"^\d+$", port.strip()):
            port = int(port.strip(), 10)
        if not isinstance(port, int) or isinstance(port, bool) or port < 1 or port > 65535:
            raise ApiError("config_invalid", f"rule.targets[{i + 1}].port 必须是 1-65535", 400)
        weight = 1 if item.get("weight") is None else item.get("weight")
        if not isinstance(weight, int) or isinstance(weight, bool) or weight < 1:
            raise ApiError("config_invalid", f"rule.targets[{i + 1}].weight 必须是 >=1 的整数", 400)
        targets.append({"host": host, "port": port, "weight": weight})

    node_id = None if raw.get("node_id") is None or raw.get("node_id") == "" else as_int(raw.get("node_id"))
    node_name = (
        raw["node_name"].strip()
        if isinstance(raw.get("node_name"), str) and raw["node_name"].strip()
        else None
    )

    return {
        "name": name,
        "node_id": node_id,
        "node_name": node_name,
        "protocol": protocol,
        "entry_whitelist": entry_whitelist,
        "listen_port": listen_port,
        "proxy_protocol": req_bool(raw, "proxy_protocol", False),
        "receive_proxy_protocol": req_bool(raw, "receive_proxy_protocol", False),
        "enabled": req_bool(raw, "enabled", True),
        "targets": targets,
    }


def normalize_rule(raw: dict) -> dict:
    targets = coerce_targets(raw)
    nid = node_id_of(raw)
    node_name = None
    if isinstance(raw.get("node_name"), str):
        node_name = raw["node_name"]
    elif isinstance(raw.get("node"), dict) and isinstance(raw["node"].get("name"), str):
        node_name = raw["node"]["name"]
    host = entry_host_from(raw)
    if not host and isinstance(raw.get("node"), dict):
        host = entry_host_from(raw["node"])
    listen_port = as_int(raw.get("listen_port"))
    return {
        "raw": raw,
        "id": id_of(raw),
        "name": raw["name"].strip() if isinstance(raw.get("name"), str) else None,
        "node_id": nid,
        "node_name": node_name,
        "listen_port": listen_port,
        "listen_host": host,
        "node_ip": host,
        "listen": f"{host}:{listen_port}" if host and listen_port else None,
        "protocol": raw["protocol"] if isinstance(raw.get("protocol"), str) else None,
        "proxy_protocol": raw["proxy_protocol"] if isinstance(raw.get("proxy_protocol"), bool) else None,
        "receive_proxy_protocol": raw["receive_proxy_protocol"]
        if isinstance(raw.get("receive_proxy_protocol"), bool)
        else None,
        "enabled": raw["enabled"] if isinstance(raw.get("enabled"), bool) else None,
        "entry_whitelist": rule_whitelist(raw),
        "targets": targets,
        "targetsKey": targets_key(targets),
    }


def coerce_targets(item: dict) -> list:
    if isinstance(item.get("targets"), list):
        lst = item["targets"]
    elif isinstance(item.get("target"), dict):
        lst = [item["target"]]
    else:
        lst = []
    out = []
    for t in lst:
        if not isinstance(t, dict):
            continue
        w = as_int(t.get("weight"))
        out.append(
            {
                "host": t["host"] if isinstance(t.get("host"), str) else None,
                "port": as_int(t.get("port")),
                "weight": w if w is not None else 1,
            }
        )
    return out


def list_rules(token: str) -> list:
    payload = api.cdn("GET", "/rules", token=token)
    return [normalize_rule(x) for x in extract_list(payload, "rules")]


def find_rule_by_name(rules: list, name: str) -> Optional[dict]:
    for r in rules:
        if r.get("name") == name:
            return r
    return None


# 远端规则上 entry_whitelist 的可能字段名（按顺序取第一个非空的）
WHITELIST_FIELDS = (
    "entry_whitelist",
    "entry_ip_whitelist",
    "entry_whitelist_cidr",
    "ip_whitelist",
    "whitelist",
)


def find_rule_by_targets(
    rules: list, targets: list, entry_whitelist: Optional[str] = None
) -> Optional[dict]:
    """按 targets 去重；传了 entry_whitelist 时 whitelist 也必须相同。

    - 未传（None / 空串）→ 只比 targets，与旧行为一致
    - 传了（规范化后的 IPv4/32）→ targets + entry_whitelist 都相同才算重复
    """
    key = targets_key(targets)
    if key == "[]":
        return None
    wanted = whitelist_key(entry_whitelist)
    for r in rules:
        if r.get("targetsKey") != key and targets_key(r.get("targets")) != key:
            continue
        if wanted and rule_whitelist(r) != wanted:
            continue
        return r
    return None


def whitelist_key(value: Any) -> str:
    """规范化 entry_whitelist 到可比较的形式；空/无效 → ""。"""
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text or text.lower() in ("none", "off", "null", "auto"):
        return ""
    try:
        return normalize_whitelist(text)
    except ApiError:
        return text.lower()


def rule_whitelist(item: dict) -> str:
    """从规则对象（规范化的 / 原始 API 形态）取 entry_whitelist，返回规范化值或 ""。"""
    if not isinstance(item, dict):
        return ""
    holders = [item]
    if isinstance(item.get("raw"), dict):
        holders.append(item["raw"])
    for holder in holders:
        for field in WHITELIST_FIELDS:
            value = holder.get(field)
            canonical = whitelist_key(value)
            if canonical:
                return canonical
    return ""


def targets_key(targets: list) -> str:
    items = []
    for t in targets or []:
        if not isinstance(t, dict):
            continue
        host = t["host"].strip().lower() if isinstance(t.get("host"), str) else ""
        port = as_int(t.get("port"))
        weight = as_int(t.get("weight"))
        if weight is None:
            weight = 1
        if not host or port is None:
            continue
        items.append({"host": host, "port": port, "weight": weight})
    items.sort(key=lambda a: (a["host"], a["port"], a["weight"]))
    return json.dumps(items, separators=(",", ":"))


def resolve_rule_name(rules: list, requested_name: Optional[str]) -> dict:
    max_id = max_rule_id(rules)
    auto_name = str(max_id * 2) if max_id > 0 else "2"
    guard = 0
    while find_rule_by_name(rules, auto_name) and guard < 32:
        try:
            n = float(auto_name)
        except ValueError:
            n = float("nan")
        if n == n and abs(n) != float("inf") and n > 0:
            prod = n * 2
            auto_name = str(int(prod)) if prod == int(prod) else str(prod)
        else:
            auto_name = f"{auto_name}_x"
        guard += 1
    if not requested_name:
        return {"name": auto_name, "name_source": "auto_max_id"}
    if find_rule_by_name(rules, requested_name):
        return {"name": auto_name, "name_source": "auto_max_id_conflict"}
    return {"name": requested_name, "name_source": "client"}


def max_rule_id(rules: list) -> int:
    m = 0
    for r in rules or []:
        if r.get("id") is not None and r["id"] > m:
            m = r["id"]
    return m


def pick_auto_delete_victim(rules: list, delauto: int, node_id: int) -> Optional[dict]:
    for item in rules or []:
        if item.get("id") is None:
            continue
        if delauto == 1 and item.get("node_id") != node_id:
            continue
        return item
    return None


def free_quota_by_delete(token: str, rules: list, *, delauto: int, node_id: int, limit: int, used: int) -> dict:
    current = list(rules)
    current_used = used
    deleted_rule = None
    max_passes = max(1, current_used - limit + 1)

    for _ in range(max_passes):
        if current_used < limit:
            break
        victim = pick_auto_delete_victim(current, delauto, node_id)
        if not victim:
            raise ApiError(
                "rule_quota_exceeded",
                f"规则额度不足且找不到可按 delauto={delauto} 删除的规则（已用 {current_used} / 上限 {limit}）",
                409,
                "同节点下没有可删规则，可试 delauto=2" if delauto == 1 else "没有可解析 id 的规则可删",
                {
                    "used": current_used,
                    "limit": limit,
                    "remaining": max(limit - current_used, 0),
                    "delauto": delauto,
                },
            )
        api.cdn("DELETE", f"/rules/{victim['id']}", token=token)
        deleted_rule = summarize_deleted_rule(victim)
        try:
            current = list_rules(token)
            current_used = len(current)
        except Exception:
            current = [r for r in current if r.get("id") != victim["id"]]
            current_used -= 1
        break  # free one slot per request

    if current_used >= limit:
        raise ApiError(
            "rule_quota_exceeded",
            f"自动删除后额度仍不足：已用 {current_used} / 上限 {limit}",
            409,
            "手动清理规则或提高套餐上限",
            {
                "used": current_used,
                "limit": limit,
                "remaining": max(limit - current_used, 0),
                "delauto": delauto,
                "deleted_rule": deleted_rule,
            },
        )
    return {
        "deleted": deleted_rule is not None,
        "deleted_rule": deleted_rule,
        "rules": current,
        "used": current_used,
    }


def _dry_entry_source(existing: Optional[dict], listen_port: int) -> dict:
    """dry-run 用：把已有规则的入口字段挖出来，端口用本次要写的值。"""
    src = {}
    raw = (existing or {}).get("raw")
    if isinstance(raw, dict):
        for key in CONNECT_HOST_KEYS + CONNECT_HOSTS_LIST_KEYS + LEGACY_HOST_KEYS:
            if key in raw:
                src[key] = raw[key]
    src["listen_port"] = listen_port
    return src


def _with_entry(obj: dict, point: Optional[dict]) -> dict:
    """把入口 host/port 挂到响应 rule 上（listen_host + node_ip 同值）。"""
    host = (point or {}).get("host")
    port = (point or {}).get("port")
    if host:
        obj["listen_host"] = host
        obj["node_ip"] = host
    if host and port:
        obj["listen"] = f"{host}:{port}"
        obj["listen_port"] = port
    return obj


def node_by_id(token: str, node_id: Optional[int]) -> Optional[dict]:
    """按 node_id 从 /nodes/available 补一个节点；查不到直接返回 None。"""
    if node_id is None:
        return None
    try:
        for n in list_nodes(token):
            if n["id"] == node_id:
                return n
    except ApiError:
        return None
    return None


def summarize_deleted_rule(item: dict) -> dict:
    return {"id": item.get("id"), "name": item.get("name"), "node_id": item.get("node_id")}


def summarize_rule(item: dict, node: Optional[dict] = None) -> dict:
    out = {
        "id": item.get("id"),
        "name": item.get("name"),
        "node_id": item.get("node_id"),
        "node_name": item.get("node_name"),
        "listen_port": item.get("listen_port"),
        "protocol": item.get("protocol"),
        "proxy_protocol": item.get("proxy_protocol"),
        "receive_proxy_protocol": item.get("receive_proxy_protocol"),
        "enabled": item.get("enabled"),
        "entry_whitelist": rule_whitelist(item) or None,
        "targets": item.get("targets"),
    }
    point = entry_point(item.get("raw") or item, node)
    if point["host"]:
        out["listen_host"] = point["host"]
        out["node_ip"] = point["host"]
    if point["host"] and point["port"]:
        out["listen"] = f"{point['host']}:{point['port']}"
        out["listen_port"] = point["port"]
    return out


def resolve_node(token: str, rule: dict) -> dict:
    nodes = list_nodes(token)
    if rule.get("node_id") is not None:
        hit = next((n for n in nodes if n["id"] == rule["node_id"]), None)
        if not hit:
            raise ApiError(
                "node_not_found",
                f"没有匹配到 node_id={rule['node_id']}",
                404,
                "可选: " + ", ".join(f"{n['id']}:{n['name']}" for n in nodes),
            )
        return hit
    if rule.get("node_name"):
        return match_node(nodes, rule["node_name"])
    defn = next((n for n in nodes if n["id"] == DEFAULT_NODE_ID), None)
    if defn:
        return defn
    raise ApiError(
        "node_not_found",
        f"默认 node_id={DEFAULT_NODE_ID} 不在可用列表中，请在 body 传 node_id 或 node_name",
        404,
        "可选: " + ", ".join(f"{n['id']}:{n['name']}" for n in nodes),
    )


def resolve_port(token: str, node: dict, wanted: Any, existing: Optional[dict]) -> int:
    if isinstance(wanted, int) and not isinstance(wanted, bool):
        bounds = node.get("portBounds")
        if bounds and (wanted < bounds[0] or wanted > bounds[1]):
            raise ApiError(
                "port_out_of_range",
                f"监听端口 {wanted} 不在节点 {node['name']} 范围 {bounds[0]}-{bounds[1]}",
                400,
                '改端口或用 "auto"',
            )
        return wanted
    if existing:
        current = existing.get("listen_port")
        if current is not None and 1 <= current <= 65535:
            return current
    return suggest_port(token, node["id"])


def list_nodes(token: str) -> list:
    payload = api.cdn("GET", "/nodes/available", token=token)
    nodes = []
    for item in extract_list(payload, "nodes"):
        nid = as_int(item.get("id") if item.get("id") is not None else item.get("node_id"))
        name = item.get("name") or item.get("node_name")
        if nid is None or not isinstance(name, str) or not name.strip():
            continue
        low = as_int(
            item.get("port_range_start", item.get("port_range_min", item.get("port_min")))
        )
        high = as_int(item.get("port_range_end", item.get("port_range_max", item.get("port_max"))))
        connect_host = entry_host_from(item)
        nodes.append(
            {
                "id": nid,
                "name": name.strip(),
                "online": item["online"] if isinstance(item.get("online"), bool) else None,
                "connect_host": connect_host,
                "connect_hosts": item.get("connect_hosts") if isinstance(item.get("connect_hosts"), list) else None,
                "ip": connect_host,
                "raw": item,
                "portBounds": [min(low, high), max(low, high)] if low is not None and high is not None else None,
            }
        )
    if not nodes:
        raise ApiError("no_nodes", "/nodes/available 没有返回可用节点", 502)
    return nodes


def match_node(nodes: list, wanted: str) -> dict:
    scored = [(score_node(wanted, n["name"]), n) for n in nodes]
    scored = [(s, n) for s, n in scored if s > 0]
    if not scored:
        raise ApiError(
            "node_not_found",
            f"没有匹配到入口节点: {wanted}",
            404,
            "可选节点: " + ", ".join(n["name"] for n in nodes),
        )
    scored.sort(key=lambda x: (-x[0], -len(x[1]["name"])))
    best_score, best = scored[0]
    ties = [n for s, n in scored if s == best_score and n["id"] != best["id"]]
    if ties:
        options = ", ".join(n["name"] for n in [best, *ties])
        raise ApiError(
            "node_ambiguous",
            f"入口节点名匹配到多个结果: {options}",
            400,
            f"把 node_name 写得更具体（当前: {wanted}）",
        )
    return best


def score_node(wanted: str, candidate: str) -> int:
    target = normalize_name(wanted)
    name = normalize_name(candidate)
    if not target or not name:
        return 0
    if target == name:
        return 1000
    if name.startswith(target):
        return 800 + min(len(target), 99)
    if target in name:
        return 600 + min(len(target), 99)
    if name in target:
        return 400 + min(len(name), 99)
    t_tokens = set(re.findall(r"[0-9a-z]+", unicodedata.normalize("NFKC", wanted).lower()))
    n_tokens = set(re.findall(r"[0-9a-z]+", unicodedata.normalize("NFKC", candidate).lower()))
    if not t_tokens or not n_tokens:
        return 0
    overlap = sum(1 for t in t_tokens if t in n_tokens)
    if not overlap:
        return 0
    ratio = overlap / len(t_tokens)
    return int(200 * ratio) if ratio >= 0.6 else 0


def suggest_port(token: str, node_id: int) -> int:
    import urllib.parse

    payload = api.cdn(
        "GET",
        f"/ports/suggest?node_id={urllib.parse.quote(str(node_id))}",
        token=token,
    )
    data = unwrap(payload)
    port = as_int(data.get("port")) if isinstance(data, dict) else None
    if port is None and isinstance(payload, dict):
        port = as_int(payload.get("port"))
    if port is None or port < 1 or port > 65535:
        raise ApiError("port_suggest_failed", "无法自动分配监听端口", 502, "在 body 显式指定 listen_port")
    return port


def check_subscription(overview: dict) -> dict:
    if overview.get("has_pack") is False:
        raise ApiError(
            "no_pack",
            "账号没有生效中的流量包，拒绝创建规则",
            409,
            "先在 https://cdn.akile.ai/?ref=48521618 购买/激活流量包",
        )
    pack = active_pack(overview)
    if pack is None and overview.get("has_pack") is not True and "has_pack" in overview:
        raise ApiError("no_pack", "当前没有使用中的流量包", 409)
    remaining = remaining_traffic(overview, pack)
    if remaining is not None and remaining <= 0:
        raise ApiError("no_traffic", "流量包剩余流量为 0", 409, "续费或激活下一个流量包")
    return {
        "has_pack": overview["has_pack"] if overview.get("has_pack") is not None else pack is not None,
        "active_pack": pack_label(pack),
        "traffic_remaining": overview["traffic_remaining"]
        if overview.get("traffic_remaining") is not None
        else remaining,
        "rule_limit": overview.get("rule_limit"),
    }


def rule_quota(overview: dict, rules: list) -> dict:
    limit = as_int(overview.get("rule_limit"))
    used = len(rules) if isinstance(rules, list) else None
    if used is None and isinstance(overview.get("rules"), list):
        used = len(overview["rules"])
    if used is None:
        for key in ("rule_count", "rules_count", "rule_used"):
            v = as_int(overview.get(key))
            if v is not None:
                used = v
                break
    return {"limit": limit, "used": used}


def active_pack(overview: dict) -> Optional[dict]:
    for key in ("active_pack", "active_pack_info", "pack", "current_pack"):
        if isinstance(overview.get(key), dict):
            return overview[key]
    if isinstance(overview.get("packs"), list):
        for item in overview["packs"]:
            if not isinstance(item, dict):
                continue
            if item.get("is_active") or item.get("status") in ("active", "in_use", "using"):
                return item
    return None


def remaining_traffic(overview: dict, pack: Optional[dict]) -> Optional[int]:
    for key in ("traffic_remaining", "remaining", "remaining_traffic", "traffic_left"):
        p = parse_traffic(overview.get(key))
        if p is not None:
            return p
    if pack:
        for key in ("traffic_remaining", "remaining", "remaining_bytes", "traffic_left"):
            p = parse_traffic(pack.get(key))
            if p is not None:
                return p
    return None


def pack_label(pack: Optional[dict]) -> Optional[str]:
    if not pack:
        return None
    for key in ("name", "title", "pack_name"):
        if isinstance(pack.get(key), str) and pack[key].strip():
            return pack[key].strip()
    return None


# 入口可连地址：Akile 权威字段 connect_host / connect_hosts。
CONNECT_HOST_KEYS = ("connect_host", "connect_hostname", "connect_ip")
CONNECT_HOSTS_LIST_KEYS = ("connect_hosts", "connect_ips")
# 旧版/兼容候选键（connect_host 缺失时才用）。
LEGACY_HOST_KEYS = (
    "listen_host",
    "listen_ip",
    "entry_host",
    "entry_ip",
    "node_ip",
    "server",
    "ip",
    "host",
    "address",
)


def _host_str(value: Any) -> Optional[str]:
    """把单个候选值收敛成 host 字符串；不合法返回 None。"""
    if isinstance(value, str):
        text = value.strip().strip("[]")
        if not text:
            return None
        if "," in text:  # "1.2.3.4, 5.6.7.8" → 取第一个
            text = text.split(",", 1)[0].strip()
        return text or None
    if isinstance(value, dict):
        for key in CONNECT_HOST_KEYS + CONNECT_HOSTS_LIST_KEYS + LEGACY_HOST_KEYS:
            if key in value:
                host = _host_str(value[key])
                if host:
                    return host
    elif isinstance(value, (list, tuple)):
        for item in value:
            host = _host_str(item)
            if host:
                return host
    return None


def entry_host_from(obj: Any) -> Optional[str]:
    """从 node / rule / raw 对象里取入口 IP：connect_host 优先，旧键兜底。"""
    if not isinstance(obj, dict):
        return None
    for key in CONNECT_HOST_KEYS:
        if key in obj:
            host = _host_str(obj[key])
            if host:
                return host
    for key in CONNECT_HOSTS_LIST_KEYS:
        if key in obj:
            host = _host_str(obj[key])
            if host:
                return host
    for key in LEGACY_HOST_KEYS:
        if key in obj:
            host = _host_str(obj[key])
            if host:
                return host
    return None


def split_host_port(value: str) -> tuple[Optional[str], Optional[int]]:
    """"1.2.3.4:20001" / "[::1]:20001" → (host, port)。"""
    if not isinstance(value, str) or ":" not in value:
        return None, None
    idx = value.rfind(":")
    host_part = value[:idx].strip().strip("[]")
    port = as_int(value[idx + 1 :])
    if not host_part or port is None:
        return None, None
    return host_part, port


def entry_point(rule: Any, node: Optional[dict] = None) -> dict:
    """解析规则/节点的入口地址：{"host", "port"}，缺省项为 None。"""
    if not isinstance(rule, dict):
        rule = {}
    port = as_int(rule.get("listen_port"))
    for key in ("listen_address", "entry_address", "endpoint"):
        host_part, parsed = split_host_port(rule.get(key))
        if host_part and parsed:
            return {"host": host_part, "port": port or parsed}
    host = entry_host_from(rule)
    if not host and isinstance(rule.get("node"), dict):
        host = entry_host_from(rule["node"])
    if not host and isinstance(node, dict):
        raw = node.get("raw") if isinstance(node.get("raw"), dict) else node
        host = entry_host_from(raw) or entry_host_from(node)
    if host and port is None:
        host_part, parsed = split_host_port(host)
        if host_part and parsed:
            host, port = host_part, parsed
    return {"host": host or None, "port": port}


def listen_address(rule: dict, node: Optional[dict]) -> Optional[dict]:
    """host+port 齐全时返回 {host, port}，否则 None（保持旧契约）。"""
    point = entry_point(rule, node)
    if point["host"] and point["port"]:
        return point
    return None
