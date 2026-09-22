#!/usr/bin/env python3
"""The Protection Suite dashboard's own checks — the ones that need no browser and no live estate.

Run with the dashboard's venv, because the module imports ``hermes_cli``:
    /home/hermes/.hermes/hermes-agent/venv/bin/python tests/test-plugin-api.py

Every fixture is a temp dir: ``HERMES_HOME`` points at it and ``PSEC_ARTIFACT_ROOT`` at a path that
does not exist, so a run can never silently read the live registry, the live lake config or the live
artifacts and call that a pass.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import re
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


def _state_target(node: ast.AST) -> bool:
    """True for a target that NAMES the state field: the bare name ``state`` OR an attribute
    ``X.state``.

    The old assignment regex was ``\\bstate(?:\\s*,\\s*reason)?\\s*=\\s*"..."`` — a word boundary
    sits before ``state`` in ``obj.state``, so it matched an ATTRIBUTE target too. The first AST
    walk checked only ``isinstance(target, ast.Name)`` and silently dropped ``obj.state = "x"``
    (t_1824e291). An attribute target must be recognised here or the walk is not a superset of the
    regex it replaced.
    """
    if isinstance(node, ast.Name):
        return node.id == "state"
    if isinstance(node, ast.Attribute):
        return node.attr == "state"
    return False


def _aws_states_emitted_in(aws_source: str) -> set[str]:
    """Every state token the AWS code can put in a ``state`` field — read off the MODULE SOURCE.

    The first census (t_e8d5e7e1) used two regexes and could not see two emission forms the module
    already uses, so a new token in either form shipped with the suite green (t_c36b5510):

      * ``_aws_row(<id>, <surface>, <calls>, "<state>", ...)`` — the 4th positional argument. A
        regex keyed on ``[^,]+`` for ``<calls>`` stops at the first comma when ``<calls>`` is a
        multi-element list literal (the CloudTrail fallback row at ``_aws_account_entry``), so it
        never reaches the state argument.
      * ``"state": "<x>"`` — a dict literal (the no-clouds early return in ``_aws_panel``). Neither
        regex covered this form.

    An AST walk sees STRUCTURE, not text, so both close at once: it takes the 4th positional
    argument of every ``_aws_row`` call whatever the ``calls`` argument looks like, and the
    ``"state"`` value of every dict literal.

    The first walk then NARROWED two shapes the regexes had caught — ``obj.state = "x"`` (an
    attribute assignment target) and ``mod._aws_row(...)`` (an attribute callee, which the old
    ``_aws_row\\(`` regex matched behind the dot) — so it was not a superset of what it replaced
    (t_1824e291). That is closed here: the walk now recognises an ATTRIBUTE target or callee as
    well as a bare name.

    Shapes this covers: ``_aws_row`` positional state (name or attribute callee, any ``calls``
    argument); ``state=`` keyword on any call (fail-closed); a ``"state"`` dict value;
    ``state = "x"`` and ``obj.state = "x"``; the tuple form ``state, reason = "x", None`` (either
    element a name or an attribute); and a function/lambda parameter default named ``state``.

    Shapes it does NOT cover (pre-existing, wider than this card): ``state: str = "x"``
    (``ast.AnnAssign``) and ``d["state"] = "x"`` (a Subscript target) — neither the old regexes nor
    this walk sees them. The slice itself is still textual (see the arm's own comment).
    """
    emitted: set[str] = set()

    def literal(node):
        return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

    def add(node):
        s = literal(node)
        if s is not None:
            emitted.add(s)

    def is_aws_row(func) -> bool:
        # `_aws_row(...)`; the callee may be a bare name OR an attribute (`mod._aws_row(...)`).
        return ((isinstance(func, ast.Name) and func.id == "_aws_row")
                or (isinstance(func, ast.Attribute) and func.attr == "_aws_row"))

    for node in ast.walk(ast.parse(aws_source)):
        if isinstance(node, ast.Call):
            if is_aws_row(node.func) and len(node.args) >= 4:
                add(node.args[3])                    # sid, surface, calls, state — position 3
            for kw in node.keywords:
                if kw.arg == "state":                # f(state="x") — any call, fail-closed
                    add(kw.value)
        elif isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if isinstance(k, ast.Constant) and k.value == "state":
                    add(v)                           # {"state": "x", "state_label": ...}
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if _state_target(target):
                    add(node.value)                  # state = "x"  /  obj.state = "x"
                elif (isinstance(target, ast.Tuple) and isinstance(node.value, ast.Tuple)
                      and len(target.elts) == len(node.value.elts)):
                    for tgt, val in zip(target.elts, node.value.elts):
                        if _state_target(tgt):       # state, reason = "x", None
                            add(val)
        elif isinstance(node, ast.arguments):
            pos = list(node.posonlyargs) + list(node.args)   # defaults align to the tail
            for a, d in zip(pos[len(pos) - len(node.defaults):], node.defaults):
                if a.arg == "state":
                    add(d)                           # def f(state="x") — the regex saw this too
            for a, d in zip(node.kwonlyargs, node.kw_defaults):
                if a.arg == "state" and d is not None:
                    add(d)
    return emitted


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


def _add_runs(db: Path, runs: list[dict]) -> None:
    """A board's run history — the table the reader falls back to for a card's verdict.

    Only the columns the reader's query touches: `id` (latest = highest), `task_id`, `summary`.
    """
    conn = sqlite3.connect(db)
    conn.execute("create table task_runs (id integer primary key autoincrement, task_id text,"
                 " summary text)")
    for r in runs:
        conn.execute("insert into task_runs (task_id, summary) values (?,?)",
                     (r.get("task_id"), r.get("summary")))
    conn.commit()
    conn.close()


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

    # --- the card body is the READER's shape (t_91659f39) ----------------------

    # The pre-`t_6af9c689` PSEC shape, verbatim from a live card (`t_0dec9ce0`).
    LEGACY_PSEC_BODY = (
        "rule: cloud_privileged_change\n"
        "severity: high\n"
        "subject: eceb0f73-329b-4515-9e7b-f11bd4c2f950\n"
        "n: 2\n"
        "detail: Microsoft.Authorization/roleAssignments/write by eceb0f73 on /subscriptions/048d\n"
        "\n"
        "Filed by psec-gaps-detect.py. Coverage-gap stream (kanban t_540ce4c5).\n"
    )

    def test_the_legacy_psec_body_is_parsed_and_the_widening_is_what_parses_it(self):
        """152 cards already on the boards carry the old shape; the reader repairs them.

        MEASURED before the widening, through this reader over the live boards: 0 of 134
        `psec-gaps-detect` rows parsed a `rule_id` or a `subject`.

        The second half is the MUTATION CONTROL: with the legacy arms disabled the SAME fixture
        stops parsing, so the arm proves the widening and not the fixture.
        """
        m = _load(self.home, self.artifact)
        got = m._parse_finding(self.LEGACY_PSEC_BODY)
        self.assertEqual(got["rule_id"], "cloud_privileged_change")
        self.assertEqual(got["severity"], "high")
        self.assertEqual(got["subject"], "eceb0f73-329b-4515-9e7b-f11bd4c2f950")
        self.assertEqual(got["device_id"], "eceb0f73-329b-4515-9e7b-f11bd4c2f950")
        self.assertEqual(got["detail"], "Microsoft.Authorization/roleAssignments/write by eceb0f73"
                                        " on /subscriptions/048d")
        never = re.compile("(?!)")
        m._LEGACY_RULE_RE = m._LEGACY_SEVERITY_RE = never
        m._LEGACY_SUBJECT_RE = m._LEGACY_DETAIL_RE = never
        blind = m._parse_finding(self.LEGACY_PSEC_BODY)
        self.assertIsNone(blind["rule_id"], "reverting the widening must stop parsing the old shape")
        self.assertIsNone(blind["subject"])
        self.assertIsNone(blind["severity"])

    def test_the_modern_shape_is_unchanged_and_a_new_body_keeps_its_detail_block(self):
        """Both shapes are read; adding the legacy arm must not disturb the one that worked."""
        m = _load(self.home, self.artifact)
        body = ("Detection: `alpha_rule_a`\nSeverity: high\nSubject: device_x : HKLM\\Run\\bad\n\n"
                "Detail:\n```\nfirst line\ndetail: a lowercase line inside the block\n```\n")
        got = m._parse_finding(body)
        self.assertEqual(got["rule_id"], "alpha_rule_a")
        self.assertEqual(got["severity"], "high")
        self.assertEqual(got["subject"], "device_x : HKLM\\Run\\bad")
        self.assertEqual(got["device_id"], "device_x")
        self.assertEqual(got["detail"], "first line",
                         "the new shape's `Detail:` block wins; a `detail:` line inside it is prose")

    # --- the disposition, and where it lives (t_91659f39) ----------------------

    def _board_with_one_finding(self, **card) -> Path:
        m = _make_board(self.home, "b1", [{
            "id": "t_1", "title": "PSEC [high] cloud_privileged_change: s1", "body": self.LEGACY_PSEC_BODY,
            "assignee": "x", "status": "done", "created_by": "psec-gaps-detect",
            "created_at": 1_700_000_000, "completed_at": 1_700_000_500, **card}])
        return m

    def test_a_verdict_in_the_run_summary_is_read_and_result_still_wins(self):
        """414 of 583 `done` finding cards carry their verdict ONLY in the run summary."""
        m = _load(self.home, self.artifact)
        db = self._board_with_one_finding()
        _add_runs(db, [{"task_id": "t_1", "summary": "an older run"},
                       {"task_id": "t_1", "summary": "Triage verdict: FALSE POSITIVE, no incident."}])
        pop = m._read_findings()
        self.assertEqual(pop["rows"][0]["disposition"], "false_positive")
        # `result` is the disposition's HOME: a non-empty result is read and the summary ignored.
        b1 = self.home / "kanban" / "boards" / "b1" / "kanban.db"
        b1.unlink()
        _make_board(self.home, "b1", [{
            "id": "t_1", "title": "PSEC [high] x", "body": "", "assignee": "x", "status": "done",
            "created_by": "psec-gaps-detect", "created_at": 1_700_000_000, "completed_at": 1_700_000_500,
            "result": "contained via firewall block"}])
        _add_runs(b1, [{"task_id": "t_1", "summary": "FALSE POSITIVE"}])
        self.assertEqual(m._read_findings()["rows"][0]["disposition"], "contained")

    def test_benign_expected_is_its_own_disposition_not_a_false_positive(self):
        """`BENIGN / EXPECTED — no incident, detector CORRECT` is not a detector defect.

        MEASURED 2026-09-19 over the 414 fallback summaries: ~400 say benign/expected, 14 say
        `false positive`. Folding the 400 into `false_positive` would tell rule-tuning to retune a
        rule that is working.
        """
        m = _load(self.home, self.artifact)
        db = self._board_with_one_finding()
        _add_runs(db, [{"task_id": "t_1",
                        "summary": "VERDICT: BENIGN / EXPECTED — a true positive of a correctly-"
                                   "designed rule, no incident."}])
        self.assertEqual(m._read_findings()["rows"][0]["disposition"], "benign")
        for text, want in (("FALSE POSITIVE, benign", "false_positive"),
                           ("the write was benign, detector correct", "benign"),
                           ("labelled positive control — no host is compromised", "benign"),
                           ("nothing recorded here at all", "resolved (disposition unrecorded)"),
                           ("a write", "resolved (disposition unrecorded)")):
            self.assertEqual(m._disposition(text, None, "resolved"), want, f"result={text!r}")

    def test_block_kind_is_a_park_reason_and_never_a_disposition(self):
        """§7's `typed block kinds` half: the reader surfaces the kind, it does not decide on it.

        MEASURED 2026-09-19: the only blocked finding card on the boards parks with
        `block_kind=capability` and no verdict — mapping a park reason onto a disposition would
        invent a meaning the enum does not carry.
        """
        m = _load(self.home, self.artifact)
        self._board_with_one_finding(status="blocked", block_kind="capability")
        row = m._read_findings()["rows"][0]
        self.assertEqual(row["block_kind"], "capability", "the kind is still CARRIED to the page")
        self.assertEqual(row["lifecycle"], "triaging")
        self.assertIsNone(row["disposition"], "a park reason is not a disposition")

    # --- the archived state (t_009c278c) --------------------------------------

    def test_an_archived_finding_keeps_its_row_and_is_flagged(self):
        """`archived` is a SILENCING state for a FINDING, not a closure (contract §7).

        The read used to filter ``status != 'archived'``, so an archived finding was counted NOWHERE:
        no row, no disposition, no MTTR, and `_attribution` never ran for it. MEASURED
        2026-09-19T01:20:57–01:21:02Z: seven fixture-artefact `psec-gaps-detect` cards were archived
        by their adjudicating lane (card `t_2a666fa6`, "harness artefact, not a finding") and the
        queue's PSEC population fell 134 -> 127, none of the seven carrying a disposition anywhere.
        The adjudications were sound; the STATE was the defect.

        The second half is the MUTATION CONTROL: the OLD filter is re-inserted in a COPY of the
        module and the same fixture leaves the queue again, so the arm proves the widening and not
        the fixture.
        """
        m = _load(self.home, self.artifact)
        _make_board(self.home, "b1", [
            {"id": "t_done", "title": "PSEC [high] x", "body": "", "assignee": "x", "status": "done",
             "created_by": "psec-gaps-detect", "created_at": 1_700_000_000,
             "completed_at": 1_700_000_500, "result": "false positive — fixture"},
            {"id": "t_arch", "title": "PSEC [high] y", "body": "", "assignee": "x",
             "status": "archived", "created_by": "psec-gaps-detect", "created_at": 1_700_000_100},
        ])
        rows = {r["id"]: r for r in m._read_findings()["rows"]}
        self.assertIn("t_arch", rows, "an archived finding must stay in the record")
        self.assertEqual(rows["t_arch"]["lifecycle"], "resolved", "CARD_TO_SOC already maps it")
        self.assertIs(rows["t_arch"]["archived"], True)
        self.assertEqual(rows["t_arch"]["disposition"], "resolved (disposition unrecorded)")
        self.assertIs(rows["t_done"]["archived"], False, "a `done` row is not archived")

        source = (PLUGIN / "dashboard" / "plugin_api.py").read_text()
        mutant = source.replace(
            "                    WHERE (created_by IN ({placeholders}) OR title LIKE 'SIEM [%'"
            " OR title LIKE 'PSEC [%')\n",
            "                    WHERE (created_by IN ({placeholders}) OR title LIKE 'SIEM [%'"
            " OR title LIKE 'PSEC [%')\n                      AND status != 'archived'\n", 1)
        self.assertNotEqual(mutant, source, "the mutation control could not re-insert the old filter")
        mut_path = Path(self.tmp.name) / "plugin_api_mutant.py"
        mut_path.write_text(mutant)
        for stale in ("psec_api", "hermes_cli.kanban_db"):
            sys.modules.pop(stale, None)
        spec = importlib.util.spec_from_file_location("psec_api", mut_path)
        mut = importlib.util.module_from_spec(spec)
        sys.modules["psec_api"] = mut
        spec.loader.exec_module(mut)
        ids = {r["id"] for r in mut._read_findings()["rows"]}
        self.assertNotIn("t_arch", ids, "reverting the read must drop the archived finding again")
        self.assertIn("t_done", ids, "the mutation control must not drop anything else")

    # --- parsing -------------------------------------------------------------
    def test_worker_started_at_style_values_never_become_ages(self):
        m = _load(self.home, self.artifact)
        self.assertIsNone(m._int_or_none("5edae10e-c40b-4149-b267-4c2e7b2f2e7c:60|30722068"))
        self.assertIsNone(m._int_or_none(None))
        self.assertEqual(m._int_or_none("1789710809"), 1789710809)


    # --- AWS: a LIVE probe in three states, never a config claim, never a zero (t_7c560aaf) ------
    #
    # The panel's content is decided by the probe. Every fixture below stubs the TWO seams that
    # touch the outside world (`_aws_probe_live` and `_aws_lake_counts`), so the arms are hermetic
    # and the estate is never read — while the code under test is the SHIPPED code path, from
    # `_aws_panel` down through the state machine.

    AWS_ACCOUNT = "912632857388"

    def _aws_fixture(self, *, guardduty_error=None) -> dict:
        """The MEASURED 2026-09-19 shape: ONE multi-region trail in every region, detectors in six
        regions and EMPTY in two, Security Hub not subscribed, no account password policy."""
        trail = {"Name": "jpthegeek-multiregion", "HomeRegion": "us-east-1",
                 "IsMultiRegionTrail": True, "LogFileValidationEnabled": True,
                 "S3BucketName": "jpthegeek-cloudtrail-912632857388", "IsLogging": True,
                 "IsLogging_error": None}
        detectors = {"us-east-1": ["d0d05a6e"], "us-east-2": ["2ad05a6e"], "us-west-2": ["ccd05a6e"],
                     "eu-central-1": ["c0d05a6e"], "eu-west-1": ["26d05a6e"], "us-west-1": ["96d05a6e"],
                     "ap-southeast-2": [], "eu-west-2": []}
        if guardduty_error is not None:
            detectors = {k: {"error": "InvalidSignatureException", "reason": guardduty_error}
                         for k in detectors}
        return {
            "identity": {"account": self.AWS_ACCOUNT,
                         "arn": f"arn:aws:iam::{self.AWS_ACCOUNT}:user/hermes-protection-audit"},
            "region": "us-east-1",
            "regions": ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1",
                        "eu-central-1", "ap-southeast-2", "eu-west-2"],
            "regions_error": None,
            "cloudtrail": {"regions": {r: [dict(trail)] for r in
                                       ("us-east-1", "us-east-2", "us-west-2", "eu-west-1",
                                        "ap-southeast-2", "eu-west-2")} | {"ap-southeast-1": []},
                           "error": None},
            "guardduty": {"regions": detectors, "error": None},
            "securityhub": {"status": "not_subscribed",
                            "reason": "An error occurred (InvalidAccessException) ... is not "
                                      "subscribed to AWS Security Hub"},
            "password_policy": {"status": "absent",
                                "reason": "An error occurred (NoSuchEntity) when calling the "
                                          "GetAccountPasswordPolicy operation"},
            "iam_users": 69,
        }

    def _aws_tenant(self, platform: str = "alpha", *, account: str | None = None) -> None:
        """A registry record whose ONLY cloud is AWS — exactly the shape onestack.yaml carries."""
        d = self.home / "scripts" / "platform-registry"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{platform}.json").write_text(json.dumps({
            "platform": platform, "display_name": platform.upper(), "status": "active",
            "maturity": "enforcing", "products": ["a"],
            "clouds": [{"cloud": "aws", "account": account or self.AWS_ACCOUNT,
                        "account_verified": True,
                        "credential_ref": "secret://env/AWS_PROTECTION_AUDIT_ACCESS_KEY_ID",
                        "sources": ["cloudtrail_lookup_events"], "access": "read-only"}],
            "assets": [], "detections": {"enabled": [], "waivers": []}, "routing": {},
        }))

    def _aws_credential_file(self, platform: str = "alpha") -> Path:
        """The secret store the registry names — the same file the connector resolves. Its VALUES
        are never used by these arms (the probe is stubbed), which is the point."""
        d = self.home / ".secrets" / platform / "aws"
        d.mkdir(parents=True, exist_ok=True)
        p = d / "estate.json"
        p.write_text(json.dumps({"access_key_id": "AKIAFIXTURE", "secret_access_key": "fixture-only",
                                 "region": "us-east-1"}))
        return p

    def _aws_lake_root(self) -> None:
        (self.home / "scripts" / "psec-sources.json").write_text(
            json.dumps({"lake_root": "/mnt/lake-platform"}))

    def _stub_aws(self, m, *, lake_rows=2327, lake_ok=True, probe_error=None, fixture=None):
        def fake_probe(cred, timeout):
            if probe_error:
                raise RuntimeError(probe_error)
            return json.loads(json.dumps(fixture if fixture is not None else self._aws_fixture()))

        def fake_lake(root, platform, source, producer):
            return {"producer": producer, "source": source, "root": root,
                    "rows": lake_rows if lake_ok else None,
                    "last_event": "2026-09-19 16:50:10" if lake_ok else None,
                    "ok": lake_ok,
                    "reason": None if lake_ok else "lake probe exited 1: no duckdb"}
        m._aws_probe_live = fake_probe
        m._aws_lake_counts = fake_lake

    def _aws_panel_stubbed(self, **kw):
        m = _load(self.home, self.artifact)
        self._aws_tenant()
        self._aws_credential_file()
        self._aws_lake_root()
        self._stub_aws(m, **kw)
        return m

    def test_aws_probe_present_and_rows_is_enabled_and_producing(self):
        """THE ACCEPTANCE: a live probe answers, the lake holds rows -> `enabled and producing`,
        and the answer comes from the PROBE, not from what the registry declares.

        The positive control is the second half: the same probe result with an EMPTY registry
        declaration (no `sources` at all) renders the SAME state, so the state provably came from
        the measurement and not from the claim.
        """
        m = self._aws_panel_stubbed(lake_rows=2327)
        out = m.aws(tenant="alpha")
        self.assertEqual(out["state"], "enabled_producing")
        self.assertEqual(out["count"], 1)
        a = out["accounts"][0]
        self.assertEqual(a["probe"]["status"], "ok")
        self.assertEqual(a["identity"]["account"], self.AWS_ACCOUNT)
        self.assertEqual(a["identity"]["arn"],
                         f"arn:aws:iam::{self.AWS_ACCOUNT}:user/hermes-protection-audit")
        self.assertEqual(len(a["probe"]["regions_probed"]), 8)
        self.assertTrue(a["probe"]["credential_source"].endswith("/.secrets/alpha/aws/estate.json"))
        rows = {r["id"]: r for r in a["surfaces"]}
        self.assertEqual(rows["cloudtrail"]["state"], "enabled_producing")
        self.assertEqual(rows["cloudtrail"]["lake_rows"], 2327)
        self.assertIn("aws-cloudtrail", rows["cloudtrail"]["finding"])
        # ⛔ presence and INGESTION are different facts: no source reads the trail's S3 bucket.
        self.assertIn("NOT from the trail", rows["cloudtrail"]["details"]["trail_s3_ingest"])
        self.assertEqual(rows["cloudtrail"]["details"]["trails"][0]["IsLogging"], True)
        # GuardDuty is present and NOT ingested — a missing SOURCE, not silence.
        self.assertEqual(rows["guardduty"]["state"], "no_source")
        self.assertEqual(rows["guardduty"]["lake_rows"], None)
        self.assertIn("ap-southeast-2", rows["guardduty"]["regions_empty"])
        self.assertIn("that asymmetry is a finding", rows["guardduty"]["finding"])
        # The registry's own row is carried as a CLAIM and labelled as one.
        self.assertEqual(a["declared"]["account"], self.AWS_ACCOUNT)
        self.assertIn("CLAIM", a["declared"]["note"])

        # POSITIVE CONTROL: strip the declaration; the measured state must not move.
        m2 = self._aws_panel_stubbed(lake_rows=2327)
        reg = json.loads((self.home / "scripts" / "platform-registry" / "alpha.json").read_text())
        reg["clouds"][0]["sources"] = []
        reg["clouds"][0]["account_verified"] = False
        (self.home / "scripts" / "platform-registry" / "alpha.json").write_text(json.dumps(reg))
        r2 = m2.aws(tenant="alpha")
        self.assertEqual(r2["state"], "enabled_producing",
                         "the state must come from the probe, never from the registry's claim")
        self.assertEqual(r2["accounts"][0]["surfaces"][0]["state"], "enabled_producing")

    def test_aws_probe_present_but_no_rows_is_enabled_but_silent(self):
        """Present and NOT producing is its own state — never an absence, never a zero."""
        m = self._aws_panel_stubbed(lake_rows=0)
        out = m.aws(tenant="alpha")
        rows = {r["id"]: r for r in out["accounts"][0]["surfaces"]}
        self.assertEqual(rows["cloudtrail"]["state"], "enabled_silent")
        self.assertEqual(rows["cloudtrail"]["state_label"], "enabled but silent")
        self.assertEqual(rows["cloudtrail"]["lake_rows"], 0)
        self.assertIn("ENABLED BUT SILENT", rows["cloudtrail"]["finding"])
        self.assertNotEqual(out["state"], "enabled_producing")
        # ...and the page has a worded branch for it: a measured 0 is rendered WITH its meaning.
        bundle = (PLUGIN / "dashboard" / "dist" / "index.js").read_text()
        self.assertIn("0 rows — silent", bundle,
                      "a measured zero must render with its meaning, never as a bare number")

    def test_aws_no_state_reaches_the_page_as_a_raw_machine_token(self):
        """THE LABEL CENSUS (t_e8d5e7e1). `present_no_ingest` was emitted by TWO branches
        (`_aws_account_entry`'s per-account machine and `_aws_panel`'s per-scope machine) and had no
        `AWS_STATE_LABELS` entry, so `AWS_STATE_LABELS.get(state, state)` handed the raw token to the
        page, which renders `state_label || state` — an operator read `present_no_ingest` verbatim.

        A spot fix would be one more dictionary entry. This is the census that would have caught it:
        every state token the AWS code can put in a `state` field has a human label, and the label is
        never the token. It is read off the MODULE SOURCE with an AST WALK (t_c36b5510 widened it
        from two regexes, which were blind to `_aws_row` rows whose `calls` argument is a
        multi-element list literal and to `"state": "x"` dict literals — both forms the module
        already uses), so a new state added in ANY of those forms without a label fails here.
        """
        source = (PLUGIN / "dashboard" / "plugin_api.py").read_text()
        aws = source[source.index("AWS_STATE_LABELS = {"):source.index('@router.get("/capability")')]
        emitted = _aws_states_emitted_in(aws)
        # POSITIVE CONTROL: the extraction itself must find the states the AWS code emits today — a
        # widened extractor that silently found nothing must not pass vacuously.
        self.assertGreaterEqual(
            emitted, {"enabled_producing", "enabled_silent", "no_source", "present_no_ingest",
                      "configured", "absent", "unmeasurable"},
            f"the census did not find the states the AWS code emits: {sorted(emitted)} — the "
            "extraction, not the module, is what is wrong here")
        m = _load(self.home, self.artifact)
        for state in sorted(emitted):
            self.assertIn(state, m.AWS_STATE_LABELS,
                          f"`{state}` can be emitted but has no AWS_STATE_LABELS entry — it would "
                          "reach the page as a raw machine token")
            self.assertNotEqual(m.AWS_STATE_LABELS[state], state, f"`{state}` renders as a raw token")

    def test_aws_a_present_no_ingest_account_has_a_label_at_every_scope(self):
        """The POSITIVE CONTROL for the census: drive the state machine into `present_no_ingest` and
        assert no `state`/`state_label` pair anywhere in the payload renders the token. GuardDuty is
        present (nothing ingests its findings) and the lake could not be read, so CloudTrail is
        unmeasurable: the account lands on `present_no_ingest`, the scope too."""
        m = self._aws_panel_stubbed(lake_rows=None, lake_ok=False)
        out = m.aws(tenant="alpha")
        self.assertEqual(out["state"], "present_no_ingest")
        self.assertNotEqual(out["state_label"], out["state"])

        def pairs(node, found):
            if isinstance(node, dict):
                if isinstance(node.get("state"), str):
                    found.append((node["state"], node.get("state_label")))
                for v in node.values():
                    pairs(v, found)
            elif isinstance(node, list):
                for v in node:
                    pairs(v, found)
            return found

        found = pairs(out, [])
        self.assertEqual(len(found), 6,
                         "the account, the scope and the four surfaces each state themselves")
        for state, label in found:
            self.assertIn(state, m.AWS_STATE_LABELS, state)
            self.assertNotEqual(label, state, f"`{state}` reaches the page as a raw token")
        self.assertIn(("present_no_ingest", m.AWS_STATE_LABELS["present_no_ingest"]), found)

    def test_the_account_lake_line_goes_through_the_same_count_rule_as_the_surface_rows(self):
        """ONE RULE, ONE FUNCTION (t_e8d5e7e1). The ACCOUNT lake line rendered a measured 0 as
        `— rows 0` — a bare zero — while the surface row three lines below carried `0 rows — silent`.
        The JSON was right both times; the account line was a SECOND rendering path. This arm is the
        regression guard on the shipped bundle: the account count must go through `lakeCell` (which
        both sites share) and the old bare-number form must be gone.

        It is a lexical check on purpose — it is exact, and the render itself is exercised against
        these same bytes by `tests/render-web-aws.mjs` (which loads `dist/index.js` and asserts the
        rendered account line, character for character, for a measured 0 and for `null`).
        """
        bundle = (PLUGIN / "dashboard" / "dist" / "index.js").read_text()
        self.assertIn("var lakeCell = function (rows, reason, lastEvent)", bundle,
                      "the one-rule function must be in the built bundle — re-run build.sh")
        self.assertIn("lakeCell(a.lake.rows, a.lake.reason, a.lake.last_event)", bundle,
                      "the ACCOUNT lake line must render its count through lakeCell")
        self.assertNotIn("num(a.lake.rows)", bundle,
                         "a bare account count is the defect this arm exists for")

    def test_aws_probe_refusal_renders_unmeasurable_not_an_empty_panel(self):
        """THE ACCEPTANCE: a refused/timed-out probe renders `UNMEASURABLE: <reason>` — the four
        surfaces are all present and all say so, and no count is a zero."""
        m = self._aws_panel_stubbed(probe_error="RuntimeError: the probe did not finish within 90s")
        out = m.aws(tenant="alpha")
        self.assertEqual(out["state"], "unmeasurable")
        self.assertIn("did not finish within 90s", out["reason"])
        a = out["accounts"][0]
        self.assertEqual(a["probe"]["status"], "unmeasurable")
        self.assertEqual(len(a["surfaces"]), 4, "the panel is NOT empty: every surface states itself")
        for r in a["surfaces"]:
            self.assertEqual(r["state"], "unmeasurable")
            self.assertTrue(r["finding"].startswith("UNMEASURABLE: "), r["finding"])
            self.assertIsNone(r["lake_rows"], "an unmeasured count is None, never 0")
        # The account's lake read is a SEPARATE measurement from the probe, so it is still reported
        # (and is only ever a number or None — never a bare zero standing in for a state).

    def test_aws_an_unreadable_lake_is_unmeasurable_and_not_silent(self):
        """`could not read the lake` is the THIRD state: it must not render as `enabled but silent`."""
        m = self._aws_panel_stubbed(lake_rows=None, lake_ok=False)
        out = m.aws(tenant="alpha")
        rows = {r["id"]: r for r in out["accounts"][0]["surfaces"]}
        self.assertEqual(rows["cloudtrail"]["state"], "unmeasurable")
        self.assertIsNone(rows["cloudtrail"]["lake_rows"],
                          "an unread lake is None — 0 would claim the source ran and landed nothing")
        self.assertIn("presence alone is NOT the producing state", rows["cloudtrail"]["finding"])
        self.assertNotEqual(rows["cloudtrail"]["state"], "enabled_silent")

    def test_aws_absent_surfaces_are_stated_absences_not_zeros(self):
        """Security Hub not subscribed and no account password policy: BOTH are stated absences."""
        m = self._aws_panel_stubbed(lake_rows=2327)
        rows = {r["id"]: r for r in m.aws(tenant="alpha")["accounts"][0]["surfaces"]}
        self.assertEqual(rows["securityhub"]["state"], "absent")
        self.assertEqual(rows["securityhub"]["state_label"], "ABSENT — a stated absence, not a zero")
        self.assertIn("NOT subscribed", rows["securityhub"]["finding"])
        self.assertEqual(rows["password_policy"]["state"], "absent")
        self.assertIn("NoSuchEntity", rows["password_policy"]["finding"])
        self.assertIn("69 IAM user(s)", rows["password_policy"]["finding"])
        self.assertIs(rows["securityhub"]["present"], False)
        self.assertIs(rows["password_policy"]["present"], False)

    def test_aws_a_password_policy_that_exists_is_configured(self):
        m = self._aws_panel_stubbed()
        fix = self._aws_fixture()
        fix["password_policy"] = {"status": "present",
                                  "policy": {"MinimumPasswordLength": 14,
                                             "PasswordReusePrevention": 24}}
        m._aws_probe_live = lambda cred, timeout: fix
        rows = {r["id"]: r for r in m.aws(tenant="alpha")["accounts"][0]["surfaces"]}
        self.assertEqual(rows["password_policy"]["state"], "configured")
        self.assertIn("MinimumPasswordLength=14", rows["password_policy"]["finding"])

    def test_aws_a_signing_error_is_never_reported_as_a_permission_error(self):
        """MEASURED 2026-09-18: GuardDuty is REST-JSON; the JSON-1.1 `x-amz-target` form answers
        *Unable to determine service/operation name to be authorized* — a SIGNING error, not an
        IAM refusal. Reporting it as a permission error files a false finding on the identity."""
        m = _load(self.home, self.artifact)
        kind, why = m._aws_classify_error(
            "An error occurred (InvalidSignatureException) ... Unable to determine "
            "service/operation name to be authorized")
        self.assertEqual(kind, "signing_error")
        self.assertIn("NOT a permission error", why)
        self.assertEqual(m._aws_classify_error("AccessDenied: User is not authorized")[0], "refused")
        self.assertEqual(m._aws_classify_error("... is not subscribed to AWS Security Hub")[0],
                         "not_subscribed")
        self.assertEqual(m._aws_classify_error("NoSuchEntity")[0], "absent")

        m = self._aws_panel_stubbed(
            fixture=self._aws_fixture(guardduty_error="Unable to determine service/operation name "
                                                     "to be authorized"))
        a = m.aws(tenant="alpha")["accounts"][0]
        gd = {r["id"]: r for r in a["surfaces"]}["guardduty"]
        self.assertEqual(gd["state"], "unmeasurable")
        self.assertTrue(any("SIGNING error" in u for u in gd["unmeasured"]),
                        f"the classifier must name the signing error: {gd['unmeasured']}")

    def test_aws_a_refused_identity_makes_the_account_unmeasurable(self):
        """sts:GetCallerIdentity refused => the panel cannot say WHICH account it read: unmeasured."""
        fix = self._aws_fixture()
        fix["identity"] = {"error": "AccessDenied", "reason": "not authorized to perform sts:GetCallerIdentity"}
        fix["regions"] = []
        m = self._aws_panel_stubbed(fixture=fix)
        out = m.aws(tenant="alpha")
        self.assertEqual(out["state"], "unmeasurable")
        self.assertIn("sts:GetCallerIdentity was refused", out["reason"])

    def test_aws_a_missing_credential_is_unmeasured_not_healthy(self):
        m = _load(self.home, self.artifact)
        self._aws_tenant()
        saved = {n: os.environ.pop(n, None) for n in
                 ("AWS_PROTECTION_AUDIT_ACCESS_KEY_ID", "AWS_PROTECTION_AUDIT_SECRET_ACCESS_KEY",
                  "AWS_PROTECTION_AUDIT_REGION")}
        try:
            m._aws_probe_live = lambda cred, timeout: self.fail("the probe must not run without a credential")
            out = m.aws(tenant="alpha")
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v
        self.assertEqual(out["state"], "unmeasurable")
        self.assertIn("no read-only AWS credential", out["reason"])
        self.assertTrue(all(r["state"] == "unmeasurable" for r in out["accounts"][0]["surfaces"]))

    def test_aws_no_declared_aws_cloud_is_a_stated_absence(self):
        m = _load(self.home, self.artifact)
        (self.home / "scripts" / "platform-registry").mkdir(parents=True, exist_ok=True)
        (self.home / "scripts" / "platform-registry" / "alpha.json").write_text(_registry_record("alpha"))
        m._aws_probe_live = lambda cred, timeout: self.fail("no AWS declaration => no probe")
        out = m.aws(tenant="alpha")
        self.assertEqual(out["state"], "absent")
        self.assertEqual(out["count"], 0)
        self.assertIn("NO `cloud: aws`", out["reason"])

    def test_aws_tenant_is_required_like_every_other_read(self):
        m = _load(self.home, self.artifact)
        with self.assertRaises(Exception) as ctx:
            m.aws(tenant=None)
        self.assertIn("tenant is required", str(ctx.exception))

    def test_aws_meta_names_the_probe_without_running_it(self):
        """/meta is read on every page load; it must NOT wait on ~35 AWS calls."""
        m = _load(self.home, self.artifact)
        m._aws_probe_live = lambda cred, timeout: self.fail("/meta must not run the AWS probe")
        meta = m.meta()
        self.assertIn("aws", meta)
        self.assertEqual(meta["aws"]["endpoint"], "/aws?tenant=<slug>")
        self.assertIn("cloudtrail:DescribeTrails(includeShadowTrails=True)", meta["aws"]["calls"])
        self.assertIn("does not run the probe", meta["aws"]["note"])

    # --- the built bundle is the sources (acceptance 4) ----------------------

    def test_the_built_bundle_matches_the_sources_it_was_built_from(self):
        """`dist/` is what the browser loads; a source edit that was never rebuilt ships nothing.

        build.sh CONCATENATES src/core.js + src/pages/suite.js into dist/index.js verbatim, so the
        arm is exact: every source's bytes must appear in the bundle, and the CSS must be identical.
        """
        bundle = (PLUGIN / "dashboard" / "dist" / "index.js").read_text()
        for src in [PLUGIN / "src" / "core.js"] + sorted((PLUGIN / "src" / "pages").glob("*.js")):
            self.assertIn(src.read_text(), bundle, f"{src.name} is missing from the built bundle — "
                                                   "re-run build.sh")
        self.assertEqual((PLUGIN / "src" / "style.css").read_text(),
                         (PLUGIN / "dashboard" / "dist" / "style.css").read_text(),
                         "dist/style.css must be the source CSS")
        self.assertIn("AWS control plane — a LIVE probe", bundle)


if __name__ == "__main__":
    unittest.main(verbosity=2)
