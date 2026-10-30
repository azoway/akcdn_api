"""Load configuration from environment / optional .env file."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import List, Optional

# project root = parent of akcdn/
ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """Simple KEY=VAL loader (no extra dependency). Does not override existing env."""
    if not path.is_file():
        return
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
            val = val[1:-1]
        if key and key not in os.environ:
            os.environ[key] = val


def load_env() -> None:
    _load_dotenv(ROOT / ".env")


def getenv(*keys: str, default: Optional[str] = None) -> Optional[str]:
    for key in keys:
        v = os.environ.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return default


class Settings:
    def __init__(self) -> None:
        load_env()
        self.host = getenv("HOST", default="127.0.0.1") or "127.0.0.1"
        port_raw = getenv("PORT", default="8787") or "8787"
        self._port_raw = port_raw
        try:
            self.port = int(port_raw)
        except ValueError:
            self.port = -1
        self.api_key = getenv("AKCDN_API_KEY") or ""
        self.akile_email = getenv("AKILE_EMAIL") or ""
        self.akile_password = getenv("AKILE_PASSWORD") or ""
        session = getenv("SESSION_FILE", default=".akcdn_session.json") or ".akcdn_session.json"
        p = Path(session)
        self.session_file = p if p.is_absolute() else (ROOT / p)

    def validation_errors(self) -> List[str]:
        errs: List[str] = []
        if self.port < 1 or self.port > 65535:
            errs.append(
                f"PORT 非法: {self._port_raw!r}（需要 1-65535）。"
                "请在 .env 或环境变量中设置 PORT=8787"
            )
        if not self.host.strip():
            errs.append("HOST 为空；请设置 HOST=127.0.0.1 或 0.0.0.0")
        parent = self.session_file.parent
        if not parent.exists():
            errs.append(f"SESSION_FILE 目录不存在: {parent}")
        return errs

    def warnings(self) -> List[str]:
        warns: List[str] = []
        if not self.api_key:
            warns.append(
                "未配置 AKCDN_API_KEY：/v1/rules 将返回 503。"
                "请在 .env 中设置 AKCDN_API_KEY。"
            )
        if not (self.akile_email and self.akile_password):
            warns.append(
                "未配置 AKILE_EMAIL / AKILE_PASSWORD；调用 /v1/rules 时将无法登录上游。"
            )
        return warns


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings




def require_valid_settings(settings: Optional[Settings] = None) -> Settings:
    """Validate bind settings; print warnings; exit on hard errors."""
    s = settings or get_settings()
    errs = s.validation_errors()
    if errs:
        for e in errs:
            print(f"akcdn-api config error: {e}", file=sys.stderr, flush=True)
        raise SystemExit(2)
    for w in s.warnings():
        print(f"akcdn-api warning: {w}", file=sys.stderr, flush=True)
    return s
