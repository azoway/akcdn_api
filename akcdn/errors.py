"""API errors."""

from __future__ import annotations

from typing import Any, Optional


class ApiError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        http: int = 502,
        hint: Optional[str] = None,
        detail: Any = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http = http
        self.hint = hint
        self.detail = detail
        self.login_performed: Optional[bool] = None

    def to_json(self) -> dict:
        out: dict = {"code": self.code, "message": self.message}
        if self.hint:
            out["hint"] = self.hint
        if self.detail is not None:
            if self.code == "rule_quota_exceeded" and isinstance(self.detail, dict):
                out.update(self.detail)
            else:
                out["detail"] = self.detail
        return out
