#!/usr/bin/env python3
"""AKCDN API — Python HTTP service (ThreadingHTTPServer)."""

from __future__ import annotations

import hmac
import json
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from akcdn import VERSION
from akcdn.config import get_settings, require_valid_settings
from akcdn.errors import ApiError
from akcdn.rules import upsert_rule


def ok_body(data: Any) -> bytes:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = f"akcdn-api/{VERSION}"

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, status: int, body: Any) -> None:
        raw = ok_body(body) if not isinstance(body, (bytes, bytearray)) else body
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _fail(self, err: BaseException) -> None:
        if isinstance(err, ApiError):
            body: dict = {"ok": False, "error": err.to_json()}
            if isinstance(err.login_performed, bool):
                body["login_performed"] = err.login_performed
            self._send(err.http, body)
            return
        self._send(
            500,
            {
                "ok": False,
                "error": {
                    "code": "internal_error",
                    "message": str(err) if err else "unknown error",
                },
            },
        )

    def _read_body_bytes(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return b""
        return self.rfile.read(length)

    def _read_json(self, *, required: bool) -> Any:
        raw = self._read_body_bytes()
        text = raw.decode("utf-8", errors="replace")
        if not text.strip():
            if required:
                raise ApiError("config_invalid", "请求体为空", 400)
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            if required:
                raise ApiError("config_invalid", "请求体不是合法 JSON", 400)
            return None



    def _assert_api_key(self) -> None:
        settings = get_settings()
        expected = (settings.api_key or "").strip()
        if not expected:
            raise ApiError(
                "api_key_unconfigured",
                "未配置环境变量 AKCDN_API_KEY",
                503,
                "在 .env 或 systemd Environment 中设置 AKCDN_API_KEY",
            )
        provided = self._extract_key() or ""
        # Constant-time compare (length mismatch → False; never log the key)
        try:
            match = hmac.compare_digest(provided, expected)
        except (TypeError, ValueError):
            match = False
        if not match:
            raise ApiError("unauthorized", "缺少或错误的 API Key", 401)

    def _extract_key(self) -> Optional[str]:
        auth = self.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            t = auth[7:].strip()
            return t or None
        key = (self.headers.get("X-API-Key") or "").strip()
        return key or None

    def _path(self) -> str:
        path = urlparse(self.path).path
        return path.rstrip("/") or "/"

    def do_GET(self) -> None:  # noqa: N802
        try:
            path = self._path()
            if path in ("/healthz", "/"):
                self._send(200, {"ok": True, "version": VERSION})
                return
            self._send(
                404,
                {
                    "ok": False,
                    "error": {"code": "not_found", "message": f"no route GET {path}"},
                },
            )
        except Exception as err:
            if not isinstance(err, ApiError):
                traceback.print_exc()
            self._fail(err)

    def do_POST(self) -> None:  # noqa: N802
        try:
            path = self._path()
            if path == "/v1/rules":
                self._assert_api_key()
                body = self._read_json(required=True)
                result = upsert_rule(body)
                self._send(200, result)
                return
            # drain unused body
            try:
                self._read_body_bytes()
            except Exception:
                pass
            self._send(
                404,
                {
                    "ok": False,
                    "error": {"code": "not_found", "message": f"no route POST {path}"},
                },
            )
        except Exception as err:
            if not isinstance(err, ApiError):
                traceback.print_exc()
            self._fail(err)


def main() -> None:
    settings = require_valid_settings()
    try:
        server = ThreadingHTTPServer((settings.host, settings.port), Handler)
    except OSError as e:
        print(
            f"akcdn-api failed to bind {settings.host}:{settings.port}: {e}",
            file=sys.stderr,
            flush=True,
        )
        raise SystemExit(1) from e
    print(
        f"akcdn-api {VERSION} listening on http://{settings.host}:{settings.port}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down", flush=True)
        server.shutdown()


if __name__ == "__main__":
    main()
