"""Login, oauth, CDN session, file-backed session cache."""

from __future__ import annotations

import json
import time
import urllib.parse
from pathlib import Path
from typing import Any, Optional

import requests

from . import (
    AKILE_API,
    AKILE_LOGIN_PAGE,
    AKILE_ORIGIN,
    APP_ID,
    BROWSER_UA,
    REDIRECT_URL,
    SESSION_SOFT_EXPIRE_SEC,
    USER_AGENT,
)
from .config import Settings, get_settings
from .errors import ApiError
from . import http_client as api
from .http_client import parse_response_json, raise_for_http_error
from .util import (
    api_message,
    classify_login_failure,
    join_hints,
    sanitize,
    status_code,
    unwrap,
)


# ---------- session file ----------

def _session_path(settings: Optional[Settings] = None) -> Path:
    return (settings or get_settings()).session_file


def session_get(settings: Optional[Settings] = None) -> Optional[str]:
    path = _session_path(settings)
    try:
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        token = data.get("token")
        if not isinstance(token, str) or not token.strip():
            return None
        now = time.time()
        expires_at = data.get("expires_at")
        if not isinstance(expires_at, (int, float)):
            # Legacy files may only have saved_at — soft expire from that
            saved = data.get("saved_at")
            if isinstance(saved, (int, float)):
                expires_at = float(saved) + SESSION_SOFT_EXPIRE_SEC
            else:
                expires_at = None
        if isinstance(expires_at, (int, float)) and now > float(expires_at):
            session_del(settings)
            return None
        return token.strip()
    except Exception:
        return None


def session_put(token: str, settings: Optional[Settings] = None) -> None:
    """Atomically write session JSON (tmp + fsync + replace). Never logs the token."""
    path = _session_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    now = time.time()
    payload = {
        "token": token,
        "expires_at": now + SESSION_SOFT_EXPIRE_SEC,
        "saved_at": now,
    }
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, separators=(",", ":"))
            f.flush()
            try:
                import os

                os.fsync(f.fileno())
            except OSError:
                pass
        tmp.replace(path)
    except OSError:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def session_del(settings: Optional[Settings] = None) -> None:
    path = _session_path(settings)
    try:
        if path.is_file():
            path.unlink()
    except OSError:
        pass


# ---------- token resolve ----------

def resolve_token(settings: Optional[Settings] = None) -> dict:
    """Use cached CDN session if still valid; otherwise password-login and refresh file.

    Soft-expired or overview-invalid sessions are deleted and replaced automatically.
    """
    s = settings or get_settings()

    cached = session_get(s)
    if cached:
        if token_works(cached):
            return {"token": cached, "login_performed": False}
        session_del(s)

    email = (s.akile_email or "").strip()
    password = (s.akile_password or "").strip()
    if not email or not password:
        raise ApiError(
            "credentials_missing",
            "缺少环境变量 AKILE_EMAIL / AKILE_PASSWORD",
            503,
            "在 .env 或 systemd Environment 中配置邮箱与密码",
        )

    session = full_login(email, password)
    if not token_works(session["token"]):
        raise ApiError(
            "session_invalid",
            "新登录拿到的 AKCDN token 立即失效",
            502,
            "可能需浏览器先登录一次 https://cdn.akile.ai/?ref=48521618 完成 OAuth 授权",
        )
    session_put(session["token"], s)
    return {"token": session["token"], "login_performed": True}



def full_login(email: str, password: str) -> dict:
    return session_from_akile_token(akile_login(email, password))


def session_from_akile_token(akile_token: str) -> dict:
    app_payload = api.akile(
        "GET",
        f"/v1/oauth/app?appid={urllib.parse.quote(APP_ID)}",
        token=akile_token,
    )
    code = status_code(app_payload)
    if code is not None and code != 0:
        raise ApiError(
            "oauth_app_failed",
            api_message(app_payload) or "查询 OAuth 应用失败",
            502,
            None,
            sanitize(app_payload),
        )
    app = unwrap(app_payload)
    if not isinstance(app, dict):
        raise ApiError("oauth_app_failed", "OAuth 应用响应异常", 502, None, sanitize(app_payload))
    app_name = app["name"] if isinstance(app.get("name"), str) else "AKCDN"
    params = oauth_authorize(akile_token, app_name)
    return akcdn_session(params)


def akile_login(email: str, password: str) -> str:
    last_err: Optional[Exception] = None
    for mode in ("browserlike", "warmup", "baseline"):
        try:
            payload = akile_login_raw(email, password, mode=mode)
            code = status_code(payload)
            if code is not None and code != 0:
                last_err = login_error(api_message(payload) or "AkileCloud 登录失败", payload)
                continue
            data = unwrap(payload)
            token = data.get("token") if isinstance(data, dict) else None
            if not isinstance(token, str) or not token.strip():
                raise ApiError(
                    "login_failed",
                    "登录响应里没有 data.token",
                    502,
                    None,
                    sanitize(payload),
                )
            return token.strip()
        except Exception as err:
            last_err = err
    if isinstance(last_err, ApiError):
        last_err.hint = join_hints(
            [
                last_err.hint,
                "核对 AKILE_EMAIL / AKILE_PASSWORD；暂不支持 2FA / 验证码账号",
            ]
        )
        raise last_err
    raise last_err or ApiError("login_failed", "AkileCloud 登录失败", 502)


def login_body(email: str, password: str, *, extras: bool = False) -> dict:
    e = "".join(email.split())
    p = password.strip()
    if extras:
        return {
            "email": e,
            "password": p,
            "token": "",
            "email_code": "",
            "new_password": "",
            "confirm": "",
            "verifyCode": "",
        }
    return {"email": e, "password": p}


def akile_login_raw(email: str, password: str, *, mode: str = "browserlike") -> Any:
    """POST /v1/user/login. Modes used by akile_login: browserlike, warmup, baseline."""
    url = AKILE_API + "/v1/user/login"
    if mode == "baseline":
        ua, content_type, with_origin, extras, do_warmup = (
            USER_AGENT,
            "application/json",
            False,
            False,
            False,
        )
    elif mode == "warmup":
        ua, content_type, with_origin, extras, do_warmup = (
            BROWSER_UA,
            "application/json;charset=UTF-8",
            True,
            True,
            True,
        )
    else:  # browserlike (default)
        ua, content_type, with_origin, extras, do_warmup = (
            BROWSER_UA,
            "application/json;charset=UTF-8",
            True,
            True,
            False,
        )

    body_text = json.dumps(
        login_body(email, password, extras=extras),
        ensure_ascii=True,
        separators=(",", ":"),
    )
    headers = {
        "Accept": "application/json",
        "Content-Type": content_type,
        "User-Agent": ua,
    }
    if with_origin:
        headers["Origin"] = AKILE_ORIGIN
        headers["Referer"] = AKILE_LOGIN_PAGE
    if do_warmup:
        cookie = warmup_akile_cookies()
        if cookie:
            headers["Cookie"] = cookie

    try:
        resp = requests.post(url, headers=headers, data=body_text.encode("utf-8"), timeout=30)
    except requests.RequestException as e:
        raise ApiError("network_error", f"POST 登录失败: {e}", 502) from e

    payload, text = parse_response_json(resp)
    raise_for_http_error(resp, payload, text)
    if payload is None:
        raise ApiError("bad_response", "登录返回的不是 JSON", 502, None, text[:500])
    return payload


def warmup_akile_cookies() -> Optional[str]:
    """GET login page; return Cookie header value or None."""
    try:
        resp = requests.get(
            AKILE_LOGIN_PAGE,
            headers={"Accept": "text/html,application/xhtml+xml", "User-Agent": BROWSER_UA},
            timeout=20,
        )
        pairs = [f"{c.name}={c.value}" for c in resp.cookies]
        if not pairs:
            one = resp.headers.get("Set-Cookie")
            if one:
                pair = str(one).split(";")[0].strip()
                if pair and "=" in pair:
                    pairs.append(pair)
        return "; ".join(pairs) if pairs else None
    except Exception:
        return None



def login_error(message: str, payload: Any) -> ApiError:
    code = classify_login_failure(message)
    if code == "two_factor_required":
        return ApiError(
            code,
            "账号开启了两步验证，本服务暂不支持",
            503,
            "请改用未开启两步验证的账号（建议单独注册仅用于 CDN 的新号）",
            sanitize(payload),
        )
    if code == "captcha_required":
        return ApiError(
            code,
            "登录需要验证码，无法纯 API 完成",
            503,
            "先在浏览器登录 AkileCloud",
            sanitize(payload),
        )
    if code == "bad_credentials":
        return ApiError(
            code,
            "AkileCloud 返回密码/邮箱错误",
            401,
            "核对 AKILE_EMAIL / AKILE_PASSWORD；若账号开了 2FA 或验证码则本服务暂不支持",
            sanitize(payload),
        )
    return ApiError("login_failed", message, 502, None, sanitize(payload))


def oauth_authorize(akile_token: str, app_name: str) -> dict:
    payload = api.akile(
        "POST",
        "/v1/oauth/login",
        token=akile_token,
        body={"app_id": APP_ID, "redirect_url": REDIRECT_URL, "state": f"Login {app_name}"},
    )
    code = status_code(payload)
    if code is not None and code != 0:
        message = api_message(payload) or "OAuth 授权失败"
        if any(x in message for x in ("确认", "授权", "confirm", "approve")):
            raise ApiError(
                "confirmation_required",
                f"OAuth 需要人工确认: {message}",
                503,
                "浏览器打开 https://akile.ai/oauth?appid=akcdn-prod 点确认授权",
                sanitize(payload),
            )
        raise ApiError("oauth_failed", message, 502, None, sanitize(payload))
    data = unwrap(payload)
    if not isinstance(data, dict):
        raise ApiError("oauth_failed", "OAuth 授权响应异常", 502, None, sanitize(payload))
    if data.get("need_confirm") or data.get("requires_confirmation") or data.get("confirm_url"):
        raise ApiError(
            "confirmation_required",
            "AkileCloud 要求手动点击「确认授权」",
            503,
            "用浏览器确认一次后再调 API",
            sanitize(data),
        )
    missing = [k for k in ("code", "uuid", "state", "timestamp", "sign") if not data.get(k)]
    if missing:
        raise ApiError(
            "oauth_failed",
            "OAuth 回调参数不完整: 缺少 " + ", ".join(missing),
            502,
            None,
            sanitize(data),
        )
    return {
        "code": data["code"],
        "uuid": data["uuid"],
        "state": data["state"],
        "timestamp": data["timestamp"],
        "sign": data["sign"],
    }


def akcdn_session(params: dict) -> dict:
    payload = api.cdn(
        "POST",
        "/oauth/session",
        body={
            "code": params["code"],
            "uuid": params["uuid"],
            "state": params["state"],
            "timestamp": params["timestamp"],
            "sign": params["sign"],
            "invite_code": "",
        },
    )
    data = unwrap(payload)
    if not isinstance(data, dict):
        raise ApiError(
            "session_failed",
            api_message(payload) or "AKCDN 会话创建失败",
            502,
            None,
            sanitize(payload),
        )
    token = data.get("token")
    if not isinstance(token, str) or not token.strip():
        raise ApiError("session_failed", "AKCDN 会话响应里没有 token", 502, None, sanitize(payload))
    return {"token": token.strip(), "user": data.get("user")}


def token_works(token: str) -> bool:
    try:
        data = unwrap(api.cdn("GET", "/overview", token=token))
        return isinstance(data, dict)
    except Exception:
        return False
