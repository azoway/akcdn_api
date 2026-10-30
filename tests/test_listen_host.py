"""入口 IP 暴露单测：Akile 的 connect_host / connect_hosts 优先，旧键兜底。全程离线。"""

from __future__ import annotations

import pytest

import akcdn.rules as rules_mod
from akcdn.rules import (
    entry_host_from,
    listen_address,
    normalize_rule,
    summarize_rule,
    upsert_rule,
)

NODE_RAW = {
    "id": 5,
    "name": "SH-HK",
    "online": True,
    "connect_host": "198.51.100.11",
    "connect_hosts": ["198.51.100.11"],
    "port_range_start": 20000,
    "port_range_end": 30000,
}
NODE = {"id": 5, "name": "SH-HK", "online": True, "raw": NODE_RAW, "portBounds": [20000, 30000]}

TARGETS = [{"host": "203.0.113.10", "port": 443, "weight": 1}]


# --- 纯函数层 ---------------------------------------------------------


def test_entry_host_prefers_connect_host():
    assert entry_host_from({"connect_host": "198.51.100.11"}) == "198.51.100.11"


def test_entry_host_falls_back_to_connect_hosts_list():
    assert entry_host_from({"connect_hosts": ["198.51.100.12"]}) == "198.51.100.12"


def test_entry_host_keeps_legacy_keys():
    assert entry_host_from({"listen_host": "198.51.100.13"}) == "198.51.100.13"
    assert entry_host_from({"entry_ip": "198.51.100.14"}) == "198.51.100.14"
    assert entry_host_from({"ip": "198.51.100.15"}) == "198.51.100.15"


def test_entry_host_missing_returns_none():
    assert entry_host_from({"name": "no-host-here"}) is None
    assert entry_host_from(None) is None


def test_listen_address_reads_rule_connect_host():
    rule = {"connect_host": "198.51.100.11", "listen_port": 20001}
    assert listen_address(rule, None) == {"host": "198.51.100.11", "port": 20001}


def test_listen_address_reads_node_raw_connect_host():
    rule = {"listen_port": 20001}
    assert listen_address(rule, NODE) == {"host": "198.51.100.11", "port": 20001}


def test_normalize_rule_exposes_listen_host_and_node_ip():
    norm = normalize_rule(
        {
            "id": 11,
            "name": "22",
            "node_id": 5,
            "listen_port": 20001,
            "connect_host": "198.51.100.11",
            "targets": [dict(TARGETS[0])],
        }
    )
    assert norm["listen_host"] == "198.51.100.11"
    assert norm["node_ip"] == "198.51.100.11"
    assert norm["listen"] == "198.51.100.11:20001"


def test_normalize_rule_without_host_stays_null():
    norm = normalize_rule({"id": 11, "name": "22", "node_id": 5, "listen_port": 20001})
    assert norm["listen_host"] is None
    assert norm["node_ip"] is None
    assert norm["listen"] is None


def test_summarize_rule_exposes_entry_ip():
    norm = normalize_rule(
        {
            "id": 11,
            "name": "22",
            "node_id": 5,
            "listen_port": 20001,
            "connect_hosts": ["198.51.100.12"],
            "targets": [dict(TARGETS[0])],
        }
    )
    out = summarize_rule(norm)
    assert out["listen_host"] == "198.51.100.12"
    assert out["node_ip"] == "198.51.100.12"
    assert out["listen"] == "198.51.100.12:20001"


def test_summarize_rule_can_fill_host_from_node():
    norm = normalize_rule(
        {"id": 11, "name": "22", "node_id": 5, "listen_port": 20001, "targets": [dict(TARGETS[0])]}
    )
    out = summarize_rule(norm, NODE)
    assert out["listen_host"] == "198.51.100.11"
    assert out["node_ip"] == "198.51.100.11"


# --- upsert_rule 全链路（api.cdn stub） ---------------------------------


@pytest.fixture

def stub_api(monkeypatch):
    state = {"rules": [], "posted": [], "suggested": 20001}

    def fake_cdn(method, path, **opts):
        if path == "/overview":
            return {"data": {"has_pack": True, "traffic_remaining": "100GB", "rule_limit": 10}}
        if path == "/rules" and method == "GET":
            return {"data": {"rules": list(state["rules"])}}
        if path == "/nodes/available":
            return {"data": {"nodes": [dict(NODE_RAW)]}}
        if path.startswith("/ports/suggest"):
            return {"data": {"port": state["suggested"]}}
        if path == "/rules" and method == "POST":
            state["posted"].append(opts.get("body"))
            return {"data": {"id": 42}}
        raise AssertionError(f"unexpected upstream call: {method} {path}")

    monkeypatch.setattr(rules_mod.api, "cdn", fake_cdn)
    monkeypatch.setattr(
        rules_mod, "resolve_token", lambda: {"token": "t", "login_performed": False}
    )
    return state


def test_create_response_carries_listen_host_and_node_ip(stub_api):
    out = upsert_rule(
        {"name": "t1", "node_id": 5, "listen_port": 20001, "targets": [dict(TARGETS[0])]}
    )
    assert out["action"] == "create"
    rule = out["rule"]
    assert rule["listen_port"] == 20001
    assert rule["listen_host"] == "198.51.100.11"
    assert rule["node_ip"] == "198.51.100.11"
    assert rule["listen"] == "198.51.100.11:20001"


def test_dry_run_rule_carries_listen_host(stub_api):
    out = upsert_rule(
        {"name": "t1", "node_id": 5, "dry_run": True, "targets": [dict(TARGETS[0])]}
    )
    assert out["action"] == "dry-run"
    assert out["rule"]["listen_host"] == "198.51.100.11"
    assert out["rule"]["node_ip"] == "198.51.100.11"


def test_exists_response_carries_listen_host(stub_api):
    stub_api["rules"] = [
        {
            "id": 11,
            "name": "22",
            "node_id": 5,
            "listen_port": 20001,
            "connect_host": "198.51.100.11",
            "targets": [dict(TARGETS[0])],
        }
    ]
    out = upsert_rule({"targets": [dict(TARGETS[0])]})
    assert out["action"] == "exists"
    assert out["rule"]["listen_host"] == "198.51.100.11"
    assert out["rule"]["node_ip"] == "198.51.100.11"
    assert out["rule"]["listen"] == "198.51.100.11:20001"


def test_exists_fills_host_from_nodes_when_rule_lacks_it(stub_api):
    stub_api["rules"] = [
        {
            "id": 11,
            "name": "22",
            "node_id": 5,
            "listen_port": 20001,
            "targets": [dict(TARGETS[0])],
        }
    ]
    out = upsert_rule({"targets": [dict(TARGETS[0])]})
    assert out["action"] == "exists"
    assert out["rule"]["listen_host"] == "198.51.100.11"
    assert out["rule"]["listen"] == "198.51.100.11:20001"
