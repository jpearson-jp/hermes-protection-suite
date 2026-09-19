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

    # --- detections catalogs (two NAMED catalogs, never one substituted for the other) ---------

    # The PLATFORM catalog's shape and its four live rule ids (contract §5's index; `rules` is a
    # DICT). MEASURED 2026-09-18 on the installed blob.
    PSEC_FOUR = {
        "_comment": ["fixture"],
        "rules": {
            "identity_signin_failure_burst": {"stream": "auth_events", "maturity": "enforcing",
                                              "suppression_key": ["subject"]},
            "cloud_privileged_change": {"stream": "cloud_audit", "maturity": "enforcing",
                                        "suppression_key": ["subject"]},
            "device_auth_failure_burst": {"stream": "auth_events", "maturity": "enforcing",
                                          "suppression_key": ["subject"]},
            # the `view`-dialect rule (t_0f80e9ed): the frozen interface's own `events` /
            # `tenant_params` relations, not the `{rel}` substitution.
            "agent_endpoint_broken": {"stream": "endpoint_metrics", "maturity": "enforcing",
                                      "suppression_key": ["subject"]},
        },
    }
    # The ENDPOINT catalog's shape: `rules` is a LIST with inline SQL (its container shape is NOT
    # the platform index's — the reader must take both). These are the eight `edr.*` ids the ruling
    # (t_0e78bcf9) counts as the `R` side for the MDE class; the LIVE blob gained three
    # `edr.linux_*` rules at 13:51Z (commit 848b146) and is therefore 11 today. The fixture pins the
    # RULING's shape, and `test_the_endpoint_count_is_measured_not_hardcoded` pins the real
    # requirement: the panel counts whatever the blob holds.
    EDR_EIGHT = ["edr.agent_local_detection", "edr.lolbin_process", "edr.encoded_command",
                 "edr.run_key_persistence", "edr.defender_tamper", "edr.dns_tunnel",
                 "edr.script_host_spawn", "edr.device_silent"]

    def _write_catalogs(self, psec=None, siem=None, psec_lake="/mnt/lake-platform",
                        siem_lake="/home/hermes/siem-lake") -> None:
        d = self.home / "scripts"
        d.mkdir(parents=True, exist_ok=True)
        for name, payload in (("psec-detections.json", psec), ("siem-detections.json", siem)):
            if payload is None:
                continue
            (d / name).write_text(payload if isinstance(payload, str) else json.dumps(payload))
        if psec_lake:
            (d / "psec-sources.json").write_text(json.dumps({"lake_root": psec_lake}))
        if siem_lake:
            (d / "siem-lake-sources.json").write_text(json.dumps({"lake_root": siem_lake}))

    @staticmethod
    def _siem_eight() -> dict:
        return {"file_cards": True, "card_assignee": "hermes-smith",
                "rules": [{"name": n, "title": n, "severity": "high", "window_min": 1440,
                           "suppression_key": "subject", "sql": "SELECT 1"} for n in
                          ProtectionSuiteApi.EDR_EIGHT]}

    def test_two_named_catalogs_each_with_its_own_rule_ids(self):
        """THE ACCEPTANCE: platform 4 + endpoint 8, each NAMED with its provenance, union readable
        as 12, and no rule id in both.

        The endpoint catalog is a SECOND NAMED CATALOG of the suite (ruling t_0e78bcf9 §1.5), read
        by siem-detect.py every 5 minutes against the endpoint lake — not a `legacy` fallback and
        not a `shadowed` name-list.
        """
        m = _load(self.home, self.artifact)
        self._write_catalogs(psec=self.PSEC_FOUR, siem=self._siem_eight())
        d = m._detections()

        plat, endp = d["platform_catalog"], d["endpoint_catalog"]
        self.assertEqual(plat["role"], "platform")
        self.assertEqual(endp["role"], "endpoint")
        self.assertEqual(plat["count"], 4, f"the platform catalog is 4 rules: {plat}")
        self.assertEqual(sorted(plat["rules"]), sorted(self.PSEC_FOUR["rules"]))
        self.assertEqual(endp["count"], 8, f"the endpoint catalog is 8 rules: {endp}")
        self.assertEqual(sorted(endp["rules"]), sorted(self.EDR_EIGHT))

        # Provenance is NAMED for each: which store, which engine, which lake, from which config.
        self.assertEqual(plat["provenance"], "scripts-store")
        self.assertEqual(endp["provenance"], "live-endpoint")
        self.assertIn("siem-detect.py", endp["engine"])
        self.assertIn("every 5 min", endp["engine"])
        self.assertIn("psec-gaps-detect.py", plat["engine"])
        self.assertEqual(plat["lake"], "/mnt/lake-platform")
        self.assertEqual(plat["lake_source"], str(self.home / "scripts" / "psec-sources.json"))
        self.assertEqual(endp["lake"], "/home/hermes/siem-lake")
        self.assertEqual(endp["lake_source"],
                         str(self.home / "scripts" / "siem-lake-sources.json"))
        self.assertTrue(plat["readable"] and endp["readable"])

        # The endpoint ids are NEVER folded into the platform index's resolved rule list...
        self.assertEqual(sorted(r["rule"] for r in d["rules"]), sorted(self.PSEC_FOUR["rules"]))
        self.assertFalse([r for r in d["rules"] if r["rule"] in self.EDR_EIGHT],
                         "an endpoint rule must never be recorded as a platform-index rule")
        # ...and the union is readable as 12, with nothing counted twice.
        self.assertEqual(d["catalogs_rules_total"], 12)
        self.assertEqual(d["rule_ids_shared"], [])
        self.assertEqual(d["catalogs"], [plat, endp])
        self.assertIn("NOT comparable rule-for-rule", d["comparability"])

    def test_the_endpoint_count_is_measured_not_hardcoded(self):
        """The panel counts what the blob HOLDS. The live blob grew 8 -> 11 at 13:51Z (848b146); a
        panel that reported 8 because the ruling said eight would be wrong the same day it shipped.
        """
        m = _load(self.home, self.artifact)
        nine = dict(self._siem_eight())
        nine["rules"] = list(self._siem_eight()["rules"]) + [
            {"name": "edr.linux_exec_from_shm", "title": "x", "severity": "high",
             "window_min": 30, "suppression_key": "subject", "sql": "SELECT 1"}]
        self._write_catalogs(psec=self.PSEC_FOUR, siem=nine)
        d = m._detections()
        self.assertEqual(d["endpoint_catalog"]["count"], 9)
        self.assertEqual(d["catalogs_rules_total"], 13)

    def test_an_absent_platform_index_is_unmeasured_and_the_endpoint_is_not_its_substitute(self):
        """THE CONTROL (ruling §1.5): the old reader resolved the first readable candidate and fell
        back to siem-detections.json labelled `legacy`, so eight endpoint rules rendered as THE
        platform index. Under the ruling that is wrong: an absent platform index is UNMEASURED for
        platform detection, named as such, and the endpoint catalog stays its own entry.
        """
        m = _load(self.home, self.artifact)
        self._write_catalogs(siem=self._siem_eight())      # psec-detections.json ABSENT
        d = m._detections()
        self.assertEqual(d["rules"], [], "eight endpoint rules are NOT the platform index's rules")
        self.assertEqual(d["rules_total"], 0)
        self.assertIsNone(d["provenance"], "an absent platform index has no provenance to report")
        self.assertIsNone(d["kind"])
        self.assertFalse(d["platform_catalog"]["readable"])
        self.assertFalse(d["platform_catalog"]["present"])
        self.assertEqual(d["platform_catalog"]["count"], 0)
        note = [u for u in d["unmeasured"] if "PLATFORM DETECTION IS UNMEASURED" in u]
        self.assertTrue(note, f"the absence must be named: {d['unmeasured']}")
        self.assertIn(str(self.home / "scripts" / "psec-detections.json"), note[0])
        self.assertTrue(any("NOT covered by the endpoint catalog" in u for u in d["unmeasured"]),
                        "the substitution refusal must be stated, not implied")
        # ...and the endpoint catalog is still reported AS ITSELF.
        self.assertEqual(d["endpoint_catalog"]["readable"], True)
        self.assertEqual(d["endpoint_catalog"]["count"], 8)
        self.assertEqual(sorted(d["endpoint_catalog"]["rules"]), sorted(self.EDR_EIGHT))
        self.assertEqual(d["catalogs_rules_total"], 8)

    def test_an_unreadable_platform_index_is_unmeasured_not_a_platform_zero(self):
        """'Could not read' must not render as 'no platform rules', nor as eight others' rules."""
        m = _load(self.home, self.artifact)
        self._write_catalogs(psec="{ this is not json", siem=self._siem_eight())
        d = m._detections()
        self.assertEqual(d["rules"], [])
        self.assertEqual(d["endpoint_catalog"]["count"], 8)
        self.assertTrue(d["platform_catalog"]["present"])
        self.assertFalse(d["platform_catalog"]["readable"])
        self.assertTrue(d["errors"], "the read failure names itself")
        self.assertTrue(any("PLATFORM DETECTION IS UNMEASURED" in u for u in d["unmeasured"]),
                        d["unmeasured"])
        self.assertTrue(any("present but UNREADABLE" in u for u in d["unmeasured"]), d["unmeasured"])

    def test_a_genuine_third_catalog_is_shadowed(self):
        """The `shadowed` mechanism survives for a THIRD live catalog — one that is neither of the
        two named ones. Its ids are named, and it is never folded into either catalog."""
        m = _load(self.home, self.artifact)
        self._write_catalogs(psec=self.PSEC_FOUR, siem=self._siem_eight())
        third = {"rules": [{"name": "opl.something", "title": "x", "stream": "auth_events"}]}
        (self.home / "scripts" / "opl-detections.json").write_text(json.dumps(third))
        d = m._detections()
        self.assertEqual(d["platform_catalog"]["count"], 4)
        self.assertEqual(d["endpoint_catalog"]["count"], 8)
        self.assertEqual(len(d["shadowed"]), 1, f"a third live catalog is a shadow: {d['shadowed']}")
        s = d["shadowed"][0]
        self.assertTrue(s["path"].endswith("opl-detections.json"))
        self.assertEqual(s["kind"], "shadowed")
        self.assertEqual(s["rules"], ["opl.something"])
        self.assertTrue(any("SHADOWED" in u for u in d["unmeasured"]), d["unmeasured"])
        self.assertEqual(d["catalogs_rules_total"], 12, "a shadowed catalog is not counted as one of "
                                                        "the suite's catalogs")

    def test_the_staging_file_is_in_no_census_and_not_a_shadow(self):
        """siem-detections-la.json is the LA lane's STAGING file (46 KQL rules, no cron): not a
        catalog of the suite (ruling §1.6). It is counted by nothing and reported as nothing — and it
        is NOT a `shadowed` entry either, which would claim a live catalog this panel is declining
        to resolve."""
        m = _load(self.home, self.artifact)
        self._write_catalogs(psec=self.PSEC_FOUR, siem=self._siem_eight())
        la = {"file_cards": False, "rules": [{"name": f"theone-rule-{i}", "title": "x",
                                              "kql": "dependencies | take 1"} for i in range(46)]}
        (self.home / "scripts" / "siem-detections-la.json").write_text(json.dumps(la))
        d = m._detections()
        self.assertEqual(d["shadowed"], [], "the staging file is not a shadowed live catalog")
        self.assertEqual(d["catalogs_rules_total"], 12)
        self.assertEqual([c["role"] for c in d["catalogs"]], ["platform", "endpoint"])
        self.assertEqual(sum(c["count"] for c in d["catalogs"]), 12, "46 is in no census")
        self.assertFalse([u for u in d["unmeasured"] if "siem-detections-la" in u and "excluded" not in u
                          and "staging" not in u.lower() and "not a catalog" not in u.lower()],
                         f"the staging file may only be mentioned as excluded: {d['unmeasured']}")

    def test_the_reader_accepts_both_container_shapes(self):
        """MEASURED: the platform index is `rules: {id: {...}}`, the endpoint catalog `rules: [{name: …}]`.

        Neither shape may be read as empty — that is the same defect as the substitution, one layer
        down.
        """
        m = _load(self.home, self.artifact)
        self._write_catalogs(psec=self.PSEC_FOUR)
        dict_shaped = m._detections()
        self.assertEqual(dict_shaped["platform_catalog"]["count"], 4)
        self._write_catalogs(psec={"rules": [{"name": r, "title": r, "stream": "cloud_audit"}
                                             for r in self.PSEC_FOUR["rules"]]})
        m2 = _load(self.home, self.artifact)
        list_shaped = m2._detections()
        self.assertEqual(list_shaped["platform_catalog"]["count"], 4)
        self.assertEqual(sorted(r["rule"] for r in dict_shaped["rules"]),
                         sorted(r["rule"] for r in list_shaped["rules"]))
        self.assertEqual(sorted(dict_shaped["rules"][0].keys()), sorted(list_shaped["rules"][0].keys()),
                         "both shapes normalise to the same record")

    def test_no_catalog_at_all_is_unknown_not_zero(self):
        m = _load(self.home, self.artifact)
        d = m._detections()
        self.assertEqual(d["rules"], [])
        self.assertEqual(d["shadowed"], [])
        self.assertEqual(d["catalogs_rules_total"], 0)
        self.assertEqual([c["readable"] for c in d["catalogs"]], [False, False])
        self.assertTrue(any("ABSENT" in u for u in d["unmeasured"]), d["unmeasured"])
        self.assertTrue(any("UNMEASURED, not zero" in u for u in d["unmeasured"]), d["unmeasured"])
        self.assertNotIn("legacy", json.dumps(d).lower(),
                         "no catalog is called `legacy` any more: they are two named catalogs")

    def test_coverage_returns_the_endpoint_catalog_beside_the_matrix(self):
        """The matrix is the platform catalog's; the panel says so, and carries the endpoint
        catalog's own entry, engine, lake and count beside it."""
        m = _load(self.home, self.artifact)
        (self.home / "scripts" / "platform-registry").mkdir(parents=True, exist_ok=True)
        (self.home / "scripts" / "platform-registry" / "alpha.json").write_text(
            _registry_record("alpha"))
        self._write_catalogs(psec=self.PSEC_FOUR, siem=self._siem_eight())
        out = m.coverage(tenant="all")
        self.assertEqual(out["rules_total"], 4, "rules_total is the platform catalog")
        self.assertEqual(out["platform_catalog"]["count"], 4)
        self.assertEqual(out["endpoint_catalog"]["count"], 8)
        self.assertEqual(out["endpoint_catalog"]["lake"], "/home/hermes/siem-lake")
        self.assertEqual(out["catalogs_rules_total"], 12)
        self.assertIn("NOT comparable rule-for-rule", out["comparability"])
        note = [u for u in out["unmeasured"] if "counts the PLATFORM catalog only" in u]
        self.assertTrue(note, f"the matrix's scope must be named: {out['unmeasured']}")
        self.assertIn("8 rule(s)", note[0])
        self.assertIn("12 distinct rule id(s)", note[0])
        self.assertFalse([r for r in out["rows"] if r["rule"] in self.EDR_EIGHT],
                         "an endpoint rule must never appear in the platform matrix")

    def test_meta_carries_both_catalogs(self):
        m = _load(self.home, self.artifact)
        self._write_catalogs(psec=self.PSEC_FOUR, siem=self._siem_eight())
        meta = m.meta()
        cats = meta["detections"]["catalogs"]
        self.assertEqual([c["role"] for c in cats], ["platform", "endpoint"])
        self.assertEqual([c["count"] for c in cats], [4, 8])
        self.assertEqual(meta["detections"]["catalogs_rules_total"], 12)
        self.assertEqual(meta["detections"]["rules"], 4, "the headline count is the platform index's")
        self.assertIn("siem-detect.py", cats[1]["engine"])
        self.assertEqual(cats[1]["lake"], "/home/hermes/siem-lake")

    # --- the capability floor (t_527e3f35) ------------------------------------

    def test_capability_floor_names_host_prevention_and_rollback_as_out_of_scope(self):
        """The two capabilities this suite does NOT have must be P0-visible, not inferred.

        If either of these ever renders `shipped`, the dashboard is claiming a prevention and a
        rollback the estate does not have — the exact misreading this panel exists to prevent.
        """
        m = _load(self.home, self.artifact)
        out = m.capability()
        by_id = {r["id"]: r for r in out["rows"]}
        for gap in ("prevent.host", "rollback.host"):
            self.assertIn(gap, by_id, f"{gap} must be on the capability floor")
            self.assertEqual(by_id[gap]["state"], "out_of_scope",
                             f"{gap} is not built and must never render as available")
            self.assertTrue(by_id[gap]["statement"], "an out-of-scope row must say what it means")
            self.assertTrue(by_id[gap]["promise"], "an out-of-scope row must state what is NOT claimed")
        self.assertEqual(by_id["tamper.host"]["state"], "partial")
        self.assertGreaterEqual(out["out_of_scope_count"], 2)
        self.assertEqual(out["provenance"], "plugin", "the versioned record is the source of truth")
        self.assertEqual(out["decision_card"], "t_527e3f35")
        self.assertTrue(out["decision"], "the panel must be able to print the decision itself")
        self.assertTrue(out["reason"], "a decision without its reason is not a recorded decision")
        self.assertEqual(out["unmeasured"], [], "a readable record leaves nothing unmeasured")
        for r in out["rows"]:
            self.assertTrue(r["statement"], f"every capability row says what it means: {r['id']}")

    def test_an_unreadable_capability_record_still_names_the_gaps(self):
        """'I could not read the record' may never render as 'the suite does everything'."""
        m = _load(self.home, self.artifact)
        m.CAPABILITY_FILE = "no-such-capability.json"
        out = m.capability()
        self.assertEqual(out["provenance"], "compiled-in")
        self.assertTrue(out["unmeasured"], "the failed read names itself")
        self.assertIn("no-such-capability.json", out["unmeasured"][0])
        ids = {r["id"]: r["state"] for r in out["rows"]}
        self.assertEqual(ids.get("prevent.host"), "out_of_scope",
                         "the compiled-in floor still reports the gap, it does not go silent")
        self.assertEqual(ids.get("rollback.host"), "out_of_scope")
        self.assertGreaterEqual(out["out_of_scope_count"], 2)

    def test_meta_carries_the_capability_provenance(self):
        """The 'sources this page is reading' panel is only complete if the floor is one of them."""
        m = _load(self.home, self.artifact)
        meta = m.meta()
        self.assertIn("capability", meta)
        self.assertEqual(meta["capability"]["provenance"], "plugin")
        self.assertGreaterEqual(meta["capability"]["out_of_scope"], 2)

    # --- parsing -------------------------------------------------------------
    def test_worker_started_at_style_values_never_become_ages(self):
        m = _load(self.home, self.artifact)
        self.assertIsNone(m._int_or_none("5edae10e-c40b-4149-b267-4c2e7b2f2e7c:60|30722068"))
        self.assertIsNone(m._int_or_none(None))
        self.assertEqual(m._int_or_none("1789710809"), 1789710809)


if __name__ == "__main__":
    unittest.main(verbosity=2)
