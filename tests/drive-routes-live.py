#!/usr/bin/env python3
"""Drive the DELIVERED route handlers over the LIVE home: the acceptance, on real data.

Read-only: it imports the shipped plugin_api.py, points HERMES_HOME at the machine home and calls
`_detections()`, `coverage()` and `meta()` exactly as the mounted routes do. Nothing is written to
the live tree; no board is touched.
"""
import importlib.util
import json
import os
import sys

os.environ["HERMES_HOME"] = "/home/hermes/.hermes"
os.environ.pop("PSEC_ARTIFACT_ROOT", None)
PLUGIN = "/home/hermes/.hermes/plugins/protection-suite/dashboard/plugin_api.py"

for stale in ("psec_api", "hermes_cli.kanban_db"):
    sys.modules.pop(stale, None)
spec = importlib.util.spec_from_file_location("psec_api", PLUGIN)
m = importlib.util.module_from_spec(spec)
sys.modules["psec_api"] = m
spec.loader.exec_module(m)

print("module file:", m.__file__)

d = m._detections()
p, e = d["platform_catalog"], d["endpoint_catalog"]
print("\n--- /coverage handlers, live data")
out = m.coverage(tenant="all")
print("rules_total (platform):", out["rules_total"], "| matrix rows:", out["count"])
print("platform catalog:", p["count"], "rules,", p["provenance"], "| engine:", p["engine"])
print("                  lake:", p["lake"], "from", p["lake_source"])
print("endpoint catalog:", e["count"], "rules,", e["provenance"], "| engine:", e["engine"])
print("                  lake:", e["lake"], "from", e["lake_source"])
print("union:", out["catalogs_rules_total"], "| shared ids:", d["rule_ids_shared"])
print("endpoint ids:", ", ".join(e["rules"]))
print("shadowed:", json.dumps(out["shadowed"]))
print("comparability:", out["comparability"][:90], "...")
print("errors (from _detections):", d["errors"])
print("unmeasured:")
for u in out["unmeasured"]:
    print("  -", u)

meta = m.meta()
print("\n--- /meta handlers, live data")
for c in meta["detections"]["catalogs"]:
    print(f"  {c['role']:9s} {c['count']:>3} rules  readable={c['readable']}  {c['path']}")
print("  catalogs_rules_total:", meta["detections"]["catalogs_rules_total"])
print("  unmeasured entries:", len(meta["unmeasured"]))
for u in meta["unmeasured"]:
    print("    -", u)
