"""Shared helpers."""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any, Callable, Iterable, Optional

from .errors import ApiError


def unwrap(payload: Any) -> Any:
    if isinstance(payload, dict) and "data" in payload:
        return payload["data"]
    return payload


def extract_list(payload: Any, key: str) -> list:
    candidates: list = [payload, unwrap(payload)]
    data = unwrap(payload)
    if isinstance(data, dict):
        for k in (key, "list", "items", "records", "rows", "data"):
            candidates.append(data.get(k))
            inner = data.get(k)
            if isinstance(inner, dict) and not isinstance(inner, list):
                for ik in ("list", "items", "records", "rows", "data"):
                    candidates.append(inner.get(ik))
    for cand in candidates:
        if isinstance(cand, list):
            return [x for x in cand if isinstance(x, dict)]
    return []


def api_message(payload: Any) -> Optional[str]:
    if not isinstance(payload, dict):
        return None
    for container in (payload, unwrap(payload)):
        if not isinstance(container, dict):
            continue
        for key in ("status_msg", "error", "message", "msg", "detail"):
            value = container.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
            if isinstance(value, dict):
                inner = value.get("message") or value.get("msg")
                if isinstance(inner, str) and inner.strip():
                    return inner.strip()
    return None


def status_code(payload: Any) -> Optional[int]:
    if not isinstance(payload, dict):
        return None
    value = payload.get("status_code")
    if isinstance(value, (int, float)) and value == value:  # not NaN
        return int(value)
    if isinstance(value, str) and re.match(r"^-?\d+$", value.strip()):
        return int(value.strip())
    return None


def as_int(value: Any) -> Optional[int]:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        m = re.search(r"-?\d+", value)
        if m:
            return int(m.group(0))
    return None


def id_of(rule: Any) -> Optional[int]:
    if not isinstance(rule, dict):
        return None
    for key in ("id", "rule_id"):
        v = as_int(rule.get(key))
        if v is not None:
            return v
    return None


def node_id_of(item: Any) -> Optional[int]:
    if not isinstance(item, dict):
        return None
    direct = as_int(item.get("node_id"))
    if direct is not None:
        return direct
    node = item.get("node")
    if isinstance(node, dict):
        return as_int(node.get("id", node.get("node_id")))
    return None


def req_str(obj: dict, key: str, where: Optional[str] = None) -> str:
    label = f"{where}.{key}" if where else key
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ApiError("config_invalid", f"缺少字段或值为空: {label}", 400)
    return value.strip()


def req_bool(obj: dict, key: str, default: bool) -> bool:
    value = default if obj.get(key) is None else obj.get(key)
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    if value is None:
        return default
    raise ApiError("config_invalid", f"rule.{key} 必须是布尔值", 400)



def normalize_whitelist(value: str) -> str:
    text = value.strip()
    if text.lower() in ("none", "off", "null"):
        return ""
    if "/" in text:
        host, mask = text.split("/", 1)
    else:
        host, mask = text, "32"
    octets = host.split(".")
    if len(octets) != 4 or not all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
        raise ApiError(
            "config_invalid",
            f"rule.entry_whitelist 不是合法 IPv4: {value}",
            400,
            "示例: 203.0.113.10/32",
        )
    if str(mask).strip() != "32":
        raise ApiError(
            "config_invalid",
            f"rule.entry_whitelist 只支持 /32，收到 /{mask}",
            400,
        )
    return f"{host}/32"


def sanitize(payload: Any) -> Any:
    if isinstance(payload, list):
        return [sanitize(x) for x in payload]
    if isinstance(payload, dict):
        out = {}
        for k, v in payload.items():
            if str(k).lower() in (
                "token",
                "password",
                "access_token",
                "refresh_token",
                "authorization",
                "api_key",
                "apikey",
                "bearer",
                "sign",
                "code",
                "uuid",
                "akcdn_api_key",
                "akile_password",
            ):
                out[k] = "***"
            else:
                out[k] = sanitize(v)
        return out
    return payload


def pick(obj: dict, pred: Callable[[str], bool]) -> dict:
    return {k: v for k, v in obj.items() if pred(k)}



def classify_login_failure(message: Optional[str]) -> str:
    """Map Akile login error text → ApiError code (used by auth login_error)."""
    if not message:
        return "login_failed"
    lowered = message.lower()
    if re.search(r"二次|两步|双因素|动态码|totp|2fa", message) or "2fa" in lowered:
        return "two_factor_required"
    if ("验证码" in message) or ("captcha" in message) or ("captcha" in lowered):
        return "captcha_required"
    if any(x in message for x in ("密码", "邮箱")) or any(
        x in lowered for x in ("password", "email")
    ):
        return "bad_credentials"
    return "login_failed"


def join_hints(parts: Iterable[Optional[str]]) -> Optional[str]:
    cleaned = [p.strip() for p in parts if isinstance(p, str) and p.strip()]
    return "；".join(cleaned) if cleaned else None


def normalize_name(value: str) -> str:
    text = unicodedata.normalize("NFKC", value or "")
    # strip leading regional-indicator emoji / whitespace
    text = re.sub(r"^[\U0001F1E6-\U0001F1FF\s]+", "", text)
    return re.sub(r"[^0-9a-z]+", "", text.lower())


def parse_traffic(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if not isinstance(value, str):
        return None
    text = value.strip().replace(",", "")
    m = re.match(r"^(-?\d+(?:\.\d+)?)\s*([KMGTP]?B)?$", text, re.I)
    if not m:
        return None
    units = {
        "B": 1,
        "KB": 1024,
        "MB": 1024**2,
        "GB": 1024**3,
        "TB": 1024**4,
        "PB": 1024**5,
    }
    unit = (m.group(2) or "B").upper()
    return int(float(m.group(1)) * (units.get(unit) or 1))
