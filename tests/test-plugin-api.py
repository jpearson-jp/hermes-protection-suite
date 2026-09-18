#!/usr/bin/env python3
"""The Protection Suite dashboard's own checks — the ones that need no browser and no live estate.

Run with the dashboard's venv, because the module imports ``hermes_cli``:
    /home/hermes/.hermes/hermes-agent/venv/bin/python tests/test-plugin-api.py

Every fixture is a temp dir: ``HERMES_HOME`` points at it and ``PSEC_ARTIFACT_ROOT`` at a path that
does not exist, so a run can never silently read the live registry, the live lake config or the live
artifacts and call that a pass.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

PLUGIN = Path(__file__).resolve().parent.parent
TASK_COLUMNS = (
    "id", "title", "body", "assignee", "status", "created_by", "created_at", "completed_at",
    "block_kind", "last_heartbeat_at", "result", "worker_started_at",
)


def _load(home: Path, artifact_root: Path):
    os.environ["HERMES_HOME"] = str(home)
    os.environ["PSEC_ARTIFACT_ROOT"] = str(artifact_root)
    for stale in ("psec_api", "hermes_cli.kanban_db"):
        sys.modules.pop(stale, None)
    spec = importlib.util.spec_from_file_location("psec_api", PLUGIN / "dashboard" / "plugin_api.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["psec_api"] = mod
    spec.loader.exec_module(mod)
    return mod


def _make_board(home: Path, slug: str, rows: list[dict]) -> Path:
    d = home / "kanban" / "boards" / slug
    d.mkdir(parents=True, exist_ok=True)
    db = d / "kanban.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "create table tasks (id text primary key, title text, body text, assignee text, status text,"
        " created_by text, created_at integer, completed_at integer, block_kind text,"
        " last_heartbeat_at integer, result text, worker_started_at text)"
    )
    for r in rows:
        conn.execute(
            "insert into tasks values (?,?,?,?,?,?,?,?,?,?,?,?)",
            tuple(r.get(c) for c in TASK_COLUMNS),
        )
    conn.commit()
    conn.close()
    return db


def _registry_record(platform: str) -> str:
    return json.dumps({
        "platform": platform,
        "display_name": platform.upper(),
        "status": "active",
        "products": ["a", "b"],
        "clouds": [{"cloud": "azure", "account": "acct-1", "account_verified": True,
                    "credential_ref": "secret://x", "sources": ["activity_log"], "access": "read-only"}],
        "assets": [{"match": {"resource_id_contains": f"/subscriptions/{platform}-sub/"}}],
        "detections": {"enabled": [f"{platform}_rule_a"], "waivers": []},
        "routing": {"security": {"primary": "dashboard"}},
    }, indent=1)


class ProtectionSuiteApi(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "hermes"
        (self.home / "scripts").mkdir(parents=True)
        self.artifact = Path(self.tmp.name) / "no-such-artifacts"

    def tearDown(self):
        self.tmp.cleanup()
        os.environ.pop("PSEC_ARTIFACT_ROOT", None)

    # --- fail-closed ---------------------------------------------------------

    def test_absent_registry_is_unmeasured_not_zero(self):
        m = _load(self.home, self.artifact)
        reg = m._load_registry()
        self.assertEqual(reg["tenants"], [])
        self.assertTrue(any("no registry record found" in u for u in reg["unmeasured"]),
                        f"an absent registry must name the absence: {reg['unmeasured']}")
        t = m.tenants()
        self.assertEqual(t["count"], 0)
        self.assertTrue(t["unmeasured"])

    def test_tenant_is_required_and_has_no_default(self):
        m = _load(self.home, self.artifact)
        with self.assertRaises(Exception) as ctx:
            m.health(tenant=None)
        self.assertIn("tenant is required", str(ctx.exception))
        with self.assertRaises(Exception) as ctx:
            m.findings(tenant="", state=None, limit=10, sort="created_at")
        self.assertIn("tenant is required", str(ctx.exception))

    def test_unknown_tenant_refuses(self):
        m = _load(self.home, self.artifact)
        (self.home / "scripts" / "platform-registry").mkdir()
        (self.home / "scripts" / "platform-registry" / "alpha.json").write_text(_registry_record("alpha"))
        with self.assertRaises(Exception) as ctx:
            m.health(tenant="beta")
        self.assertIn("not registered", str(ctx.exception))

    def test_query_defaults_are_coerced(self):
        m = _load(self.home, self.artifact)
        from fastapi import Query

        self.assertEqual(m._clamp_int(Query(50), 50, 1, 200), 50)
        self.assertEqual(m._clamp_int("not-a-number", 50, 1, 200), 50)
        self.assertEqual(m._clamp_int(10_000, 50, 1, 200), 200)

    # --- the ledger ----------------------------------------------------------

    def test_lifecycle_mapping_and_cap_echo(self):
        m = _load(self.home, self.artifact)
        body = ("Detection: `alpha_rule_a`\nSeverity: high\n"
                "Subject: device_x : HKLM\\Run\\bad\n\nFiled automatically by `siem-detect.py`\n")
        _make_board(self.home, "b1", [
            {"id": "t_1", "title": "SIEM [high] a", "body": body, "assignee": "x", "status": "todo",
             "created_by": "siem-detect", "created_at": 1_700_000_000},
            {"id": "t_2", "title": "SIEM [high] b", "body": body, "assignee": "x", "status": "done",
             "created_by": "siem-detect", "created_at": 1_700_000_100, "completed_at": 1_700_000_500},
            {"id": "t_3", "title": "PSEC [low] c", "body": body, "assignee": "x", "status": "weird",
             "created_by": "siem-detect", "created_at": 1_700_000_200},
        ])
        out = m._read_findings(limit=2)
        self.assertEqual(out["total_before_cap"], 3)
        self.assertEqual(out["count"], 2)
        self.assertTrue(out["cap_hit"], "a capped read must say it was capped")
        full = m._read_findings(limit=50)
        by_id = {r["id"]: r for r in full["rows"]}
        self.assertEqual(by_id["t_1"]["lifecycle"], "new")
        self.assertEqual(by_id["t_2"]["lifecycle"], "resolved")
        self.assertEqual(by_id["t_3"]["lifecycle"], "unrecognised_status",
                         "an unknown status must be visible, never dropped")
        self.assertEqual(full["unrecognised_status_count"], 1)
        self.assertEqual(by_id["t_1"]["rule_id"], "alpha_rule_a")
        self.assertEqual(by_id["t_1"]["severity"], "high")
        self.assertEqual(by_id["t_2"]["mttr_seconds"], 400)

    def test_unattributed_is_its_own_row_and_all_is_not_the_sum(self):
        m = _load(self.home, self.artifact)
        (self.home / "scripts" / "platform-registry").mkdir()
        (self.home / "scripts" / "platform-registry" / "alpha.json").write_text(_registry_record("alpha"))
        body = "Detection: `alpha_rule_a`\nSeverity: high\nSubject: device_x : y\n"
        rows = [{"id": f"t_{i}", "title": "SIEM [high] x", "body": body, "assignee": "x",
                 "status": "todo", "created_by": "siem-detect", "created_at": 1_700_000_000 + i}
                for i in range(3)]
        # one of them carries alpha's own subscription id, so exactly one attributes
        rows[0]["body"] = "Detection: `alpha_rule_a`\nSeverity: high\nSubject: /subscriptions/alpha-sub/vm\n"
        _make_board(self.home, "b1", rows)
        x = m.cross()
        plats = {r["platform"]: r for r in x["rows"]}
        self.assertEqual(plats["alpha"]["open"], 1)
        self.assertEqual(plats["_unattributed"]["open"], 2)
        self.assertEqual(x["all"]["open"], 3, "all counts OPEN cases, not every case")
        self.assertEqual(x["sum_of_rows_open"], 3)
        self.assertTrue(x["all_equals_sum"], "every open case is on a row")
        self.assertFalse(x["tenant_rows_equal_all"],
                         "_unattributed is kept OUT of the tenant sum — folding it in would be a "
                         "cross-tenant write")

    # --- retirement ----------------------------------------------------------

    def test_proof_state_is_never_assumed_green(self):
        m = _load(self.home, self.artifact)
        posture = {
            "log_analytics_workspaces": [{"name": "ws1"}],
            "sentinel": {"ws1": {"alert_rules": {"value": [{"name": "BuiltInFusion", "kind": "Fusion"}]},
                                 "automation_rules": {"value": []},
                                 "data_connectors": {"value": [{"name": "c1"}]},
                                 "incidents": {"value": [{"properties": {"status": "New",
                                                                        "severity": "High"}}]}}},
            "defender_pricings": {"value": [
                {"name": "Storage", "properties": {"pricingTier": "Standard"}},
                {"name": "VM", "properties": {"pricingTier": "Free"}}]},
            "defender_contacts": [{"properties": {}}],
            "defender_automations": {"value": []},
        }
        art = Path(self.tmp.name) / "artifacts"
        art.mkdir()
        (art / "azure-posture.json").write_text(json.dumps(posture))
        m2 = _load(self.home, art)
        r = m2.retirement()
        self.assertEqual(r["items_proven"], 0, "no gate artifact => nothing may render green")
        for item in r["items"]:
            self.assertEqual(item["proof"]["state"], "unproven")
        self.assertEqual(r["sentinel"]["custom_alert_rules"], 0)
        self.assertEqual(r["sentinel"]["builtin_alert_rules"], ["BuiltInFusion"])
        self.assertEqual(r["sentinel"]["connectors"], 1)
        self.assertEqual(r["defender"]["standard_count"], 1)

    # --- parsing -------------------------------------------------------------

    def test_worker_started_at_style_values_never_become_ages(self):
        m = _load(self.home, self.artifact)
        self.assertIsNone(m._int_or_none("5edae10e-c40b-4149-b267-4c2e7b2f2e7c:60|30722068"))
        self.assertIsNone(m._int_or_none(None))
        self.assertEqual(m._int_or_none("1789710809"), 1789710809)


if __name__ == "__main__":
    unittest.main(verbosity=2)
