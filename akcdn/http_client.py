"""Upstream HTTP client (Akile + AKCDN)."""

from __future__ import annotations

from typing import Any, Optional, Tuple

import requests

from . import AKCDN_API, AKILE_API, USER_AGENT
from .errors import ApiError
from .util import api_message


def parse_response_json(resp: requests.Response) -> Tuple[Any, str]:
    text = resp.text or ""
    if not text.strip():
        return None, text
    try:
        return resp.json(), text
    except Exception:
        return None, text


def raise_for_http_error(resp: requests.Response, payload: Any, text: str) -> None:
    if resp.status_code < 400:
        return
    code = "unauthorized" if resp.status_code == 401 else "http_error"
    raise ApiError(
        code,
        api_message(payload) or text[:200] or f"HTTP {resp.status_code}",
        502 if resp.status_code >= 500 else resp.status_code,
        None,
        payload,
    )


def http_json(
    method: str,
    url: str,
    *,
    token: Optional[str] = None,
    bearer: bool = True,
    body: Any = None,
    timeout: float = 30.0,
    extra_headers: Optional[dict] = None,
) -> Any:
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}" if bearer else token
    if body is not None:
        headers["Content-Type"] = "application/json;charset=UTF-8"
    if extra_headers:
        headers.update(extra_headers)

    try:
        resp = requests.request(
            method,
            url,
            headers=headers,
            json=body if body is not None else None,
            timeout=timeout,
        )
    except requests.RequestException as e:
        raise ApiError("network_error", f"{method} 请求失败: {e}", 502) from e

    payload, text = parse_response_json(resp)
    raise_for_http_error(resp, payload, text)
    if payload is None:
        raise ApiError("bad_response", f"{method} 返回的不是 JSON", 502, None, text[:500])
    return payload


def akile(method: str, path: str, **opts: Any) -> Any:
    return http_json(method, AKILE_API + path, bearer=False, **opts)


def cdn(method: str, path: str, **opts: Any) -> Any:
    return http_json(method, AKCDN_API + path, bearer=True, **opts)
