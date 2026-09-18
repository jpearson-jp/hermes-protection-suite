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
        pop = m._read_findings()          # the population read is never capped or filtered
        self.assertEqual(pop["population_total"], 3)
        self.assertEqual(len(pop["rows"]), 3)
        out = m.findings(tenant="all", state=None, limit=2, sort="created_at")
        self.assertEqual(out["population_total"], 3)
        self.assertEqual(out["in_scope_total"], 3)
        self.assertEqual(out["count"], 2)
        self.assertTrue(out["cap_hit"], "a capped page must say it was capped")
        self.assertEqual(out["lifecycle_counts"]["resolved"], 1,
                         "lifecycle counts describe the SCOPE, not the page")
        self.assertEqual(out["lifecycle_counts"]["unrecognised_status"], 1)
        full = m.findings(tenant="all", state=None, limit=50, sort="created_at")
        by_id = {r["id"]: r for r in full["rows"]}
        self.assertEqual(by_id["t_1"]["lifecycle"], "new")
        self.assertEqual(by_id["t_2"]["lifecycle"], "resolved")
        self.assertEqual(by_id["t_3"]["lifecycle"], "unrecognised_status",
                         "an unknown status must be visible, never dropped")
        self.assertEqual(full["unrecognised_status_count"], 1)
        self.assertEqual(by_id["t_1"]["rule_id"], "alpha_rule_a")
        self.assertEqual(by_id["t_1"]["severity"], "high")
        self.assertEqual(by_id["t_2"]["mttr_seconds"], 400)

    # --- the cap is scoped, not global (round-1 review defect) ----------------

    def _three_findings_one_of_them_alpha(self):
        """One board: 3 findings, exactly ONE attributable to alpha (by its asset rule)."""
        (self.home / "scripts" / "platform-registry").mkdir(exist_ok=True)
        (self.home / "scripts" / "platform-registry" / "alpha.json").write_text(_registry_record("alpha"))
        body = "Detection: `alpha_rule_a`\nSeverity: high\nSubject: device_x : y\n"
        rows = [{"id": f"t_{i}", "title": "SIEM [high] x", "body": body, "assignee": "x",
                 "status": "todo", "created_by": "siem-detect", "created_at": 1_700_000_000 + i}
                for i in range(3)]
        rows[0]["body"] = ("Detection: `alpha_rule_a`\nSeverity: high\n"
                           "Subject: /subscriptions/alpha-sub/vm\n")
        _make_board(self.home, "b1", rows)
        return rows

    def test_a_tenant_scope_is_filtered_before_the_cap(self):
        """A tenant's rows may NOT be dropped by an estate-wide cap and render as a zero.

        Measured on the shipped module before this fix: tenant=alpha with 3 real rows and cap=10
        returned count=0 with cap_hit while limit=200 returned all 3.
        """
        m = _load(self.home, self.artifact)
        self._three_findings_one_of_them_alpha()
        small = m.findings(tenant="alpha", state=None, limit=10, sort="created_at")
        self.assertEqual(small["count"], 1, "alpha's own row must survive a cap it does not exceed")
        self.assertEqual(small["in_scope_total"], 1)
        self.assertFalse(small["cap_hit"], "alpha is in scope with 1 row: no cap was hit here")
        self.assertEqual([r["platform"] for r in small["rows"]], ["alpha"])
        self.assertEqual(small["population_total"], 3, "the population is still the whole read")
        self.assertEqual(small["scope_predicate"], "tenant=alpha")
        big = m.findings(tenant="alpha", state=None, limit=200, sort="created_at")
        self.assertEqual(big["count"], 1, "the scope's count does not depend on the page size")
        self.assertEqual(big["in_scope_total"], 1)

    def test_state_filter_is_scoped_and_scoped_counts_are_not_mixed(self):
        m = _load(self.home, self.artifact)
        self._three_findings_one_of_them_alpha()
        out = m.findings(tenant="all", state="new", limit=5, sort="created_at")
        self.assertEqual(out["in_scope_total"], 3, "all three are `new` (todo)")
        self.assertEqual(out["count"], 3)
        self.assertEqual(out["population_total"], 3)
        self.assertEqual(out["lifecycle_counts"]["resolved"], 0)
        self.assertIn("state=new", out["scope_predicate"])
        with self.assertRaises(Exception) as ctx:
            m.findings(tenant="all", state="resloved", limit=5, sort="created_at")
        self.assertIn("state must be one of", str(ctx.exception),
                      "a misspelled state is refused, not rendered as an empty queue")

    def test_ties_are_broken_by_id_so_a_page_is_deterministic(self):
        m = _load(self.home, self.artifact)
        _make_board(self.home, "b1", [
            {"id": f"t_{i}", "title": "SIEM [high] x", "body": "", "assignee": "x", "status": "todo",
             "created_by": "siem-detect", "created_at": 1_700_000_000}      # every row ties exactly
            for i in range(5)
        ])
        first = [r["id"] for r in m.findings(tenant="all", state=None, limit=3, sort="created_at")["rows"]]
        second = [r["id"] for r in m.findings(tenant="all", state=None, limit=3, sort="created_at")["rows"]]
        self.assertEqual(first, second, "a page over a tie must not move between reads")
        self.assertEqual(first, ["t_4", "t_3", "t_2"], "the documented `id DESC` tiebreaker applies")

    def test_cross_aggregates_uncapped_and_says_so(self):
        """A KPI over a capped read is not a KPI: 250 open findings must not render as 200."""
        m = _load(self.home, self.artifact)
        _make_board(self.home, "b1", [
            {"id": f"t_{i}", "title": "SIEM [high] x", "body": "", "assignee": "x", "status": "todo",
             "created_by": "siem-detect", "created_at": 1_700_000_000 + i}
            for i in range(250)
        ])
        x = m.cross()
        self.assertEqual(x["all"]["open"], 250, "the aggregate counts every open case")
        self.assertEqual(x["population_total"], 250)
        self.assertFalse(x["cap_hit"])
        self.assertFalse(x["capped"])
        self.assertIsNone(x["cap"])
        self.assertIn("no LIMIT applied", x["aggregate_scope"])
        self.assertTrue(x["all_equals_sum"], "every open case is on a row")
        self.assertFalse(x["tenant_rows_equal_all"],
                         "with no tenant claiming them, the tenant sum is 0 and all is 250")
        unattr = [r for r in x["rows"] if r["platform"] == "_unattributed"][0]
        self.assertEqual(unattr["open"], 250)

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

    def test_the_shadow_proof_key_is_read_under_both_its_names(self):
        """The gate's key contract: item id, with `sentinel.shadow.7d` accepted as an alias.

        Without the alias a producer writing the obvious `sentinel.shadow` key left the item
        `unproven` forever, silently — the failure this contract removes.
        """
        m = _load(self.home, self.artifact)
        posture = {"log_analytics_workspaces": [], "sentinel": {}, "defender_pricings": {"value": []}}
        art = Path(self.tmp.name) / "artifacts2"
        art.mkdir()
        (art / "azure-posture.json").write_text(json.dumps(posture))
        (art / "psec-exit-gate.json").write_text(json.dumps(
            {"shadow": {"sentinel.shadow.7d": {"green": True, "evidence": "window receipt 2026-09-18"}}}))
        m2 = _load(self.home, art)
        r = m2.retirement()
        by_id = {i["id"]: i for i in r["items"]}
        self.assertEqual(by_id["sentinel.shadow"]["proof"]["state"], "green",
                         "the 7d spelling must green the sentinel.shadow item")
        self.assertEqual(by_id["sentinel.shadow"]["proof"]["key"], "sentinel.shadow.7d",
                         "the key that answered is echoed back")
        self.assertEqual(by_id["sentinel.connectors"]["proof"]["state"], "unproven")
        self.assertEqual(r["items_proven"], 1)
        self.assertTrue(any("proof key" in u for u in r["unmeasured"]),
                        "the key contract is named when the gate artifact is read")

    # --- detections catalog ---------------------------------------------------

    PSEC_THREE = {
        "_comment": ["fixture"],
        "rules": {
            "identity_signin_failure_burst": {"stream": "auth_events", "maturity": "enforcing",
                                              "suppression_key": ["subject"]},
            "cloud_privileged_change": {"stream": "cloud_audit", "maturity": "enforcing",
                                        "suppression_key": ["subject"]},
            "device_auth_failure_burst": {"stream": "auth_events", "maturity": "enforcing",
                                          "suppression_key": ["subject"]},
        },
    }
    # The eight live `edr.*` ids, read off the installed siem-detections.json (its container shape
    # is a LIST, the frozen index's is a DICT — the reader must take both).
    EDR_EIGHT = ["edr.agent_local_detection", "edr.lolbin_process", "edr.encoded_command",
                 "edr.run_key_persistence", "edr.defender_tamper", "edr.dns_tunnel",
                 "edr.script_host_spawn", "edr.device_silent"]

    def _write_catalogs(self, psec=None, siem=None) -> None:
        d = self.home / "scripts"
        d.mkdir(parents=True, exist_ok=True)
        for name, payload in (("psec-detections.json", psec), ("siem-detections.json", siem)):
            if payload is None:
                continue
            (d / name).write_text(payload if isinstance(payload, str) else json.dumps(payload))

    @staticmethod
    def _siem_eight() -> dict:
        return {"file_cards": True, "card_assignee": "hermes-smith",
                "rules": [{"name": n, "title": n, "severity": "high", "window_min": 1440,
                           "suppression_key": "subject", "sql": "SELECT 1"} for n in
                          ProtectionSuiteApi.EDR_EIGHT]}

    def test_both_catalogs_present_shadows_are_named_not_dropped(self):
        """The defect: the frozen §5 index is resolved, and the eight LIVE `edr.*` rules vanish.

        First-readable-candidate is the right resolution order, but a second catalog that a cron
        job reads every five minutes is not thereby unread — and it is certainly not zero. It is
        SHADOWED, and the panel must be able to say so.
        """
        m = _load(self.home, self.artifact)
        self._write_catalogs(psec=self.PSEC_THREE, siem=self._siem_eight())
        d = m._detections()
        self.assertEqual(d["provenance"], "scripts-store",
                         "the frozen §5 index is still the resolved catalog")
        self.assertEqual(sorted(r["rule"] for r in d["rules"]), sorted(self.PSEC_THREE["rules"]))
        self.assertEqual(len(d["shadowed"]), 1, f"the second catalog is a shadow: {d['shadowed']}")
        s = d["shadowed"][0]
        self.assertTrue(s["path"].endswith("siem-detections.json"))
        self.assertEqual(s["provenance"], "legacy-live")
        self.assertEqual(s["count"], 8)
        self.assertEqual(sorted(s["rules"]), sorted(self.EDR_EIGHT))
        note = [u for u in d["unmeasured"] if "SHADOWED" in u]
        self.assertTrue(note, f"a shadow must be an unmeasured entry, never a silence: {d['unmeasured']}")
        for rid in self.EDR_EIGHT:
            self.assertIn(rid, note[0], "every shadowed rule id is named, not summarised away")
        self.assertFalse([r for r in d["rules"] if r["rule"] in self.EDR_EIGHT],
                         "a shadowed rule must not be silently folded into the resolved catalog")

    def test_only_the_predecessor_present_is_labelled_legacy_and_shadows_nothing(self):
        m = _load(self.home, self.artifact)
        self._write_catalogs(siem=self._siem_eight())
        d = m._detections()
        self.assertEqual(d["provenance"], "legacy-live")
        self.assertEqual(len(d["rules"]), 8)
        self.assertTrue(all(r["maturity"] == "unmeasured" for r in d["rules"]),
                        "the predecessor carries no maturity field — that is unmeasured, not enforcing")
        self.assertEqual(d["shadowed"], [])
        self.assertTrue(any("is not installed" in u for u in d["unmeasured"]))

    def test_a_broken_frozen_index_names_the_live_predecessors_rules_not_zero(self):
        """A read failure of the FIRST candidate must not render the estate as having no rules."""
        m = _load(self.home, self.artifact)
        self._write_catalogs(psec="{ this is not json", siem=self._siem_eight())
        d = m._detections()
        self.assertEqual(d["rules"], [])
        self.assertTrue(d["errors"], "the read failure names itself")
        self.assertEqual(len(d["shadowed"]), 1)
        self.assertEqual(d["shadowed"][0]["count"], 8)
        self.assertTrue(any("unreadable" in u for u in d["unmeasured"]))
        self.assertTrue(any("SHADOWED" in u for u in d["unmeasured"]),
                        "the live rules are still named while the frozen index is unreadable")

    def test_the_reader_accepts_both_container_shapes(self):
        """MEASURED: the frozen index is `rules: {id: {...}}`, the predecessor `rules: [{name: …}]`.

        Neither shape may be read as empty — that is the same defect as the shadow, one layer down.
        """
        m = _load(self.home, self.artifact)
        self._write_catalogs(psec=self.PSEC_THREE)
        dict_shaped = m._detections()
        self.assertEqual(len(dict_shaped["rules"]), 3)
        self._write_catalogs(psec={"rules": [{"name": r, "title": r, "stream": "cloud_audit"}
                                             for r in self.PSEC_THREE["rules"]]})
        m2 = _load(self.home, self.artifact)
        list_shaped = m2._detections()
        self.assertEqual(len(list_shaped["rules"]), 3)
        self.assertEqual(sorted(r["rule"] for r in dict_shaped["rules"]),
                         sorted(r["rule"] for r in list_shaped["rules"]))
        self.assertEqual(sorted(dict_shaped["rules"][0].keys()), sorted(list_shaped["rules"][0].keys()),
                         "both shapes normalise to the same record")

    def test_both_catalogs_absent_is_unknown_not_zero(self):
        m = _load(self.home, self.artifact)
        d = m._detections()
        self.assertEqual(d["rules"], [])
        self.assertEqual(d["shadowed"], [])
        self.assertTrue(any("unknown, not zero" in u for u in d["unmeasured"]), d["unmeasured"])

    # --- parsing -------------------------------------------------------------
    def test_worker_started_at_style_values_never_become_ages(self):
        m = _load(self.home, self.artifact)
        self.assertIsNone(m._int_or_none("5edae10e-c40b-4149-b267-4c2e7b2f2e7c:60|30722068"))
        self.assertIsNone(m._int_or_none(None))
        self.assertEqual(m._int_or_none("1789710809"), 1789710809)


if __name__ == "__main__":
    unittest.main(verbosity=2)
