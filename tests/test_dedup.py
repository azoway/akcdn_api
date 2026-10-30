"""去重判断单测：targets 单键 vs targets + entry_whitelist 组合键。全程离线。"""

from __future__ import annotations

import pytest

import akcdn.rules as rules_mod
from akcdn.rules import (
    find_rule_by_targets,
    normalize_rule,
    parse_rule,
    rule_whitelist,
    targets_key,
    whitelist_key,
)

TARGETS = [{"host": "203.0.113.10", "port": 443, "weight": 1}]
WL_A = "198.51.100.7/32"
WL_B = "198.51.100.8/32"


def existing_rule(whitelist: str | None = None, *, raw_only: bool = False) -> dict:
    """构造一条已有规则（形态与 list_rules → normalize_rule 一致）。"""
    payload = {
        "id": 11,
        "name": "22",
        "node_id": 5,
        "listen_port": 20001,
        "protocol": "tcp+udp",
        "targets": [dict(t) for t in TARGETS],
    }
    if whitelist is not None and raw_only:
        payload["entry_whitelist"] = whitelist
        return normalize_rule(payload)
    if whitelist is not None:
        payload["entry_whitelist"] = whitelist
    rule = normalize_rule(payload)
    if whitelist is not None:
        rule["entry_whitelist"] = whitelist
    return rule


# --- 纯函数层 ---------------------------------------------------------


def test_no_whitelist_same_targets_is_dup():
    """未传 whitelist → 同 targets 即命中（保持旧默认行为）。"""
    rules = [existing_rule(WL_A)]
    hit = find_rule_by_targets(rules, TARGETS)
    assert hit is not None
    assert hit["id"] == 11

    # 空串 / None 显式传入也等价于"未传"
    assert find_rule_by_targets(rules, TARGETS, "") is not None
    assert find_rule_by_targets(rules, TARGETS, None) is not None


def test_same_whitelist_same_targets_is_dup():
    rules = [existing_rule(WL_A)]
    hit = find_rule_by_targets(rules, TARGETS, WL_A)
    assert hit is not None
    assert hit["id"] == 11


def test_same_whitelist_normalized_form_is_dup():
    """无掩码写法 198.51.100.7 与 198.51.100.7/32 视为同一值。"""
    rules = [existing_rule(WL_A)]
    assert find_rule_by_targets(rules, TARGETS, "198.51.100.7") is not None
    assert find_rule_by_targets(rules, TARGETS, "  198.51.100.7/32  ") is not None


def test_different_whitelist_same_targets_is_not_dup():
    rules = [existing_rule(WL_A)]
    assert find_rule_by_targets(rules, TARGETS, WL_B) is None


def test_whitelist_vs_no_whitelist_on_existing_is_not_dup():
    """已有规则没有 whitelist，请求带了 → 不算重复。"""
    rules = [existing_rule(None)]
    assert find_rule_by_targets(rules, TARGETS, WL_A) is None


def test_different_targets_never_dup():
    rules = [existing_rule(WL_A)]
    other = [{"host": "203.0.113.10", "port": 8443, "weight": 1}]
    assert find_rule_by_targets(rules, other) is None
    assert find_rule_by_targets(rules, other, WL_A) is None


def test_empty_targets_never_dup():
    assert find_rule_by_targets([existing_rule(WL_A)], []) is None
    assert find_rule_by_targets([existing_rule(WL_A)], [], WL_A) is None


def test_whitelist_key_normalizes():
    assert whitelist_key(None) == ""
    assert whitelist_key("") == ""
    assert whitelist_key("auto") == ""
    assert whitelist_key("none") == ""
    assert whitelist_key(WL_A) == WL_A
    assert whitelist_key(" 198.51.100.7 ") == WL_A


def test_normalize_rule_exposes_entry_whitelist():
    rule = existing_rule(WL_A)
    assert rule["entry_whitelist"] == WL_A
    assert rule_whitelist(rule) == WL_A

    bare = existing_rule(None)
    assert bare["entry_whitelist"] == ""
    assert rule_whitelist(bare) == ""


def test_rule_whitelist_reads_raw_object():
    """原始 API 形态（未经 normalize_rule 赋值）也能读到 whitelist。"""
    raw = {"id": 3, "entry_whitelist": WL_A, "targets": [dict(t) for t in TARGETS]}
    assert rule_whitelist(raw) == WL_A
    normalized = normalize_rule(raw)
    assert normalized["entry_whitelist"] == WL_A
    assert find_rule_by_targets([normalized], TARGETS, WL_A) is not None
    assert find_rule_by_targets([normalized], TARGETS, WL_B) is None


# --- upsert_rule 层（stub 掉网络）-------------------------------------


class FakeUpstream:
    def __init__(self, rules: list[dict]):
        self.rules = rules
        self.calls: list[tuple] = []

    def __call__(self, method: str, path: str, token=None, body=None):
        self.calls.append((method, path))
        if path == "/overview":
            return {
                "data": {
                    "has_pack": True,
                    "traffic_remaining": 1024**3,
                    "rule_limit": 10,
                }
            }
        if path == "/rules" and method == "GET":
            return {"data": {"list": self.rules}}
        if path == "/nodes/available":
            return {"data": {"list": [{"id": 5, "name": "SH-HK", "online": True}]}}
        if path.startswith("/ports/suggest"):
            return {"data": {"port": 20001}}
        if path == "/rules" and method == "POST":
            return {"data": {"id": 77, "listen_host": "10.0.0.1", "listen_port": 20001}}
        raise AssertionError(f"unexpected upstream call: {method} {path}")


@pytest.fixture
def stub_upstream(monkeypatch):
    def _install(rules: list[dict]) -> FakeUpstream:
        fake = FakeUpstream(rules)
        monkeypatch.setattr(rules_mod.api, "cdn", fake)
        monkeypatch.setattr(
            rules_mod, "resolve_token", lambda *a, **k: {"token": "t", "login_performed": False}
        )
        return fake

    return _install


def body_for(whitelist: str | None) -> dict:
    body = {
        "delauto": 0,
        "listen_port": "auto",
        "protocol": "tcp+udp",
        "targets": [dict(t) for t in TARGETS],
    }
    if whitelist is not None:
        body["entry_whitelist"] = whitelist
    return body


def test_upsert_exists_without_whitelist(stub_upstream):
    fake = stub_upstream([existing_rule(WL_A, raw_only=True)])
    out = rules_mod.upsert_rule(body_for(None))
    assert out["action"] == "exists"
    assert out["matched_by"] == "targets"
    assert out["deleted"] is False
    assert ("POST", "/rules") not in fake.calls


def test_upsert_exists_with_same_whitelist(stub_upstream):
    fake = stub_upstream([existing_rule(WL_A, raw_only=True)])
    out = rules_mod.upsert_rule(body_for(WL_A))
    assert out["action"] == "exists"
    assert out["matched_by"] == "targets+whitelist"
    assert out["rule"]["entry_whitelist"] == WL_A
    assert "entry_whitelist" in out["message"]
    assert ("POST", "/rules") not in fake.calls
    assert not any(m == "PUT" for m, _ in fake.calls)


def test_upsert_creates_when_whitelist_differs(stub_upstream):
    fake = stub_upstream([existing_rule(WL_A, raw_only=True)])
    out = rules_mod.upsert_rule(body_for(WL_B))
    assert out["action"] == "create"
    assert out["rule"]["entry_whitelist"] == WL_B
    assert ("POST", "/rules") in fake.calls


def test_upsert_dry_run_when_whitelist_differs(stub_upstream):
    stub_upstream([existing_rule(WL_A, raw_only=True)])
    body = body_for(WL_B)
    body["dry_run"] = True
    out = rules_mod.upsert_rule(body)
    assert out["action"] == "dry-run"
    assert out["would"] == "create"
    assert out["payload"]["entry_whitelist"] == WL_B
