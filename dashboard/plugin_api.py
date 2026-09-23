"""Protection Suite — backend routes, mounted at ``/api/plugins/protection-suite/``.

The operator surface for the multi-tenant protection suite (umbrella kanban ``t_2c5fb09a``,
this card ``t_4806df6b``). Design is frozen by
``/home/hermes/hermes-outbox/2026-09-18-protection-suite/PROTECTION-SUITE-CONTRACT.md`` §8 and
``04-soc-dashboards-automations.md`` §3-§4. What that means for this module:

* **Every panel reports its own provenance, its own ``as_of``, and — when a source could not be
  read — an ``unmeasured`` entry naming what is missing.** A failed measurement must never render
  as a zero (contract §3.4). There is no code path here that turns "could not read" into ``0``.
* **A KPI over a capped read is not a KPI** (§3.1): every list response echoes the cap it applied
  and whether the cap was hit, so the page can print ``<n> of >=<n>`` instead of implying a total.
* **``_unattributed`` is a first-class row** (§3.3, §4.2 r9) that can never be folded into a
  tenant's counts, and ``all`` is computed as its own query so ``all != sum(rows)`` is visible.
* **Tenant is a required argument with no default on every per-tenant read** (§4.2 r2): omitting it
  refuses. The cross-tenant view is a different function with ``all`` as its explicit value.
* **No composite risk score** — deliberately not built (§3.4).
* **Reads only, except the two owner write actions** (§3: the live app is the console, not the
  on-call surface): POST /answer and POST /comment, both routed through ``hermes_cli.kanban_db``,
  the same code path the CLI and the bundled kanban plugin use. The estate's human ask-inbox is
  Mission Control's Waiting-on-me tab; these routes exist for the automation tiers and for a
  tenant-scoped answer, and are not a second inbox (04 §3.4 rule 4).

Sources, each with its own name (a source that is absent is reported, never guessed):

    registry      <hermes home>/scripts/platform-registry/*.yaml|*.json   (frozen, contract §3)
                  fallback: the foundation card's own artifact dir, labelled ``wip-outbox``
    detections    TWO CATALOGS OF RECORD, read by two engines against two lakes (contract §5, as
                  amended by the ruling on ``t_0e78bcf9``). They are NAMED, never resolved in
                  candidate order:
                    platform catalog  <hermes home>/scripts/psec-detections.json  (the frozen §5
                                      index) — engine ``psec-gaps-detect.py`` (cron 8065d45ca251,
                                      every 15 min) + ``psec-detect.py``; lake from
                                      ``psec-sources.json`` -> ``lake_root``
                    endpoint catalog  <hermes home>/scripts/siem-detections.json — the suite's
                                      SECOND NAMED INDEX: engine ``siem-detect.py`` (cron
                                      f1ed861d4b6f, EVERY 5 MIN, ``file_cards: true``); lake from
                                      ``siem-lake-sources.json`` -> ``lake_root``, stream ``rmm-edr``
                  ⛔ An absent or unreadable platform index is **UNMEASURED for platform
                  detection**, named as such. The endpoint catalog is a different engine on a
                  different lake and is NEVER its substitute. A genuine THIRD live catalog is
                  still reported as ``shadowed`` (file + every rule id) — see ``_shadow_report``;
                  ``siem-detections-la.json`` is the LA lane's STAGING file and is in no census at
                  all (see ``STAGING_CATALOGS``).
    lake          <hermes home>/scripts/psec-sources.json -> lake_root      (frozen, contract §1)
                  the existing endpoint feed (siem-lake-sources.json) is read as a ``legacy``
                  feed with its own schema, labelled as such
    retirement    azure-posture.json (Sentinel + Defender measured facts, written by the exit
                  measurement) + the OWNER SPEND kanban card + the shadow-proof artifact if present
    capability    dashboard/capability.json — the recorded SCOPE decision (kanban ``t_527e3f35``):
                  what this suite does, and explicitly what it does NOT do (no host prevention, no
                  host rollback). A decision is not a measurement, so it is versioned with the
                  module and never inferred; see ``_capability``.
    aws           a LIVE read-only probe of the AWS account's control plane
                  (``cloudtrail:DescribeTrails`` + ``GetTrailStatus``, ``guardduty:ListDetectors``,
                  ``securityhub:DescribeHub``, ``iam:GetAccountPasswordPolicy``) under the registry's
                  read-only identity, CACHED with an explicit age, plus the lake's own rows for
                  ``producer=aws-cloudtrail``. What the registry DECLARES is carried and labelled
                  ``declared`` and is never the answer; see ``_aws_panel``.

The plugin dir is un-versioned live config: ``git init`` lives inside it. Keep the module
importable at all times — a syntax error here is a tab that answers 500 for every profile.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from hermes_cli import kanban_db
from hermes_cli import kanban_db_connect as kbc

log = logging.getLogger(__name__)

router = APIRouter()

# --- frozen vocabulary -------------------------------------------------------

FIVE_STREAMS = ("auth_events", "endpoint_metrics", "cloud_audit", "host_health", "findings")

# Non-terminal = "open case" (04 §3.1: one status list, one definition, one place).
SOC_STATES = ("new", "triaging", "contained", "false_positive", "resolved", "archived")
OPEN_STATES = ("new", "triaging")
# A SILENCING state carries NO verdict (contract §7). `archived` is one: a card taken off the board
# was not adjudicated, so it is neither open nor closed. MEASURED 2026-09-23 (card t_be4443f9, arms
# ARCH/ARCH2 against this file): mapping `archived -> resolved` rendered an archived card
# `lifecycle: "resolved"` with `disposition: "resolved (disposition unrecorded)"`, incremented
# `lifecycle_counts.resolved` and `cross.*.resolved` — a SILENCING act incrementing a CLOSURE KPI —
# and read an archived card's free-text `result` as a disposition ("contained"), i.e. an
# un-adjudicated card rendered as a contained incident. A silencing state is its OWN lifecycle value.
SILENCED_STATES = ("archived",)
# What an archived row's disposition reads: explicitly UNRECORDED, and deliberately NOT a string a
# consumer matching `resolved` matches on (arm CMT measured that `resolved (disposition unrecorded)`
# reads as RESOLVED to a substring consumer).
SILENCED_DISPOSITION = ("archived (disposition unrecorded — a silencing act carries no verdict, "
                        "contract §7)")

# kanban card status -> SOC lifecycle state. The ledger is the kanban board (contract §7).
CARD_TO_SOC = {
    "todo": "new",
    "triage": "new",
    "scheduled": "new",
    "ready": "triaging",
    "running": "triaging",
    "blocked": "triaging",
    "review": "triaging",
    "done": "resolved",
    "archived": "archived",
}

SEVERITIES = ("critical", "high", "medium", "low", "info")

# Which kanban board rows are findings. The filer (siem-detect.py) sets created_by='siem-detect'
# and titles the card "SIEM [<severity>] <title>"; both are accepted and the union is the queue.
FINDING_CREATORS = ("siem-detect", "psec-detect")
FINDING_TITLE_RE = re.compile(r"^\s*(?:SIEM|PSEC)\s*\[(?P<sev>[a-z]+)\]\s*(?P<title>.*)$")

STALE_OPEN_SECONDS = 24 * 3600
MTTR_EPISODE_NOTE = (
    "MTTR is computed over cards, not reopen-aware episodes: the episodes table the SOC card "
    "(t_638ac914) owns does not exist yet, so a reopened card's window is its current one."
)

MAX_LIST_LIMIT = 200
DEFAULT_LIST_LIMIT = 50

# The two write actions are the only mutations. Both are owner-authored: every write names the owner
# as its author, and the two routes exist for (a) the automation tiers' console actions and (b) any
# surface that wants a tenant-scoped answer. The ESTATE's human ask-inbox is Mission Control's
# Waiting-on-me tab (it renders the same ask rows and posts to its own /answer); this plugin does not
# duplicate it (04 §3.4 rule 4: one query layer, or the surfaces will disagree).
# ``post /answer`` and ``post /comment`` are the routes; there is no anonymous write and no delete.

WORKSPACE_ARTIFACT_DIR = "2026-09-18-protection-suite"
REGISTRY_DIRNAME = "platform-registry"


def _artifact_root() -> Path:
    """The workstream's human-facing artifact directory (``~/hermes-outbox`` on this box).

    ``PSEC_ARTIFACT_ROOT`` overrides it so the tests can prove the "nothing found anywhere"
    behaviour deterministically instead of accidentally reading the live artifacts.
    """
    override = os.environ.get("PSEC_ARTIFACT_ROOT")
    if override:
        return Path(override)
    for cand in (Path.home() / "hermes-outbox", _hermes_home() / "hermes-outbox"):
        if cand.is_dir():
            return cand / WORKSPACE_ARTIFACT_DIR
    return Path.home() / "hermes-outbox" / WORKSPACE_ARTIFACT_DIR


# --- locations ---------------------------------------------------------------

def _hermes_home() -> Path:
    """The MACHINE-level Hermes home — never a profile home.

    This plugin is machine-level: the scripts store, the platform registry and the kanban boards
    all live under ``~/.hermes``. A per-profile backend (the desktop app spawns one per profile)
    answers with ``~/.hermes/profiles/<p>``, and reading the registry from there would silently
    show every tenant as missing in exactly the profiles the owner switched to. So a profile home
    is normalised back to its parent.
    """
    for cand in (os.environ.get("HERMES_HOME"), _constants_home()):
        if not cand:
            continue
        p = Path(cand)
        m = re.match(r"^(?P<root>.+)/profiles/[^/]+/?$", str(p))
        if m:
            return Path(m.group("root"))
        return p
    return Path.home() / ".hermes"


def _constants_home() -> Optional[str]:
    try:
        from hermes_constants import get_hermes_home

        return str(get_hermes_home())
    except Exception:  # noqa: BLE001 — never take the tab down over a home-directory lookup
        return None


def _scripts_dir() -> Path:
    return _hermes_home() / "scripts"


def _now() -> int:
    return int(time.time())


def _as_of() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso(ts: Any) -> Optional[str]:
    if ts is None or ts == "":
        return None
    if isinstance(ts, str):
        return ts
    try:
        return datetime.fromtimestamp(int(ts), timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError):
        return None


def _int_or_none(value: Any) -> Optional[int]:
    """Coerce to int or None.

    ``worker_started_at`` is a PID fingerprint (``"<boot>|<tick>"``), not a timestamp — see the
    dashboard-plugin skill. Never feed it to this and call the result an age.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _clamp_int(value: Any, default: int, lo: int, hi: int) -> int:
    """Query(...) defaults are Query objects when a handler is called directly — coerce first."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    if n != n:  # NaN
        return default
    return max(lo, min(hi, n))


def _read_json(path: Path) -> tuple[Optional[Any], Optional[str]]:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh), None
    except FileNotFoundError:
        return None, None
    except Exception as exc:  # noqa: BLE001 — a corrupt artifact is a finding, not a crash
        return None, f"{type(exc).__name__}: {exc}"


def _read_yaml(path: Path) -> tuple[Optional[Any], Optional[str]]:
    try:
        import yaml  # type: ignore
    except Exception as exc:  # noqa: BLE001
        return None, f"pyyaml unavailable: {exc}"
    try:
        with path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh), None
    except FileNotFoundError:
        return None, None
    except Exception as exc:  # noqa: BLE001
        return None, f"{type(exc).__name__}: {exc}"


def _registry_sources() -> list[tuple[Path, str]]:
    """Where a registry *record* may be found, best first, each labelled with its provenance.

    The frozen home is the scripts store (contract §3). The second entry is the foundation
    card's own artifact directory: the moment ``t_c3fbef90`` installs through the gate, the first
    entry wins and the second is never read again. It exists so this dashboard can show a real
    multi-tenant matrix *today* instead of an honest-but-empty one — and every response that used
    it says ``registry_provenance: wip-outbox`` so nobody mistakes it for the shipped registry.
    """
    return [
        (_scripts_dir() / REGISTRY_DIRNAME, "scripts-store"),
        (_artifact_root() / "registry", "wip-outbox"),
    ]


# --- registry ----------------------------------------------------------------

def _tenant_from_record(rec: dict[str, Any], provenance: str, source_path: str) -> dict[str, Any]:
    platforms = rec.get("products") or []
    clouds = rec.get("clouds") or []
    det = rec.get("detections") or {}
    waivers = det.get("waivers") or []
    assets = rec.get("assets") or []
    sources: list[str] = []
    for c in clouds:
        for s in (c.get("sources") or []):
            if s not in sources:
                sources.append(str(s))
    return {
        "platform": rec.get("platform"),
        "display_name": rec.get("display_name") or rec.get("platform"),
        "status": rec.get("status") or "unknown",
        "maturity": rec.get("maturity") or "unknown",
        "products": [str(p) for p in platforms],
        "products_count": len(platforms),
        "clouds": [
            {
                "cloud": c.get("cloud"),
                "account": c.get("account"),
                "account_verified": bool(c.get("account_verified")),
                "access": c.get("access"),
                "credential_ref": c.get("credential_ref"),
                "sources": c.get("sources") or [],
            }
            for c in clouds
        ],
        "clouds_count": len(clouds),
        "sources_declared": sources,
        "sources_declared_count": len(sources),
        "detections_enabled": [str(x) for x in (det.get("enabled") or [])],
        "detections_enabled_count": len(det.get("enabled") or []),
        "waivers": [
            {"detection": w.get("detection"), "reason": w.get("reason"), "expires": w.get("expires")}
            for w in waivers
        ],
        "waivers_count": len(waivers),
        "assets": assets,
        "assets_count": len(assets),
        "routing": rec.get("routing") or {},
        "thresholds": rec.get("thresholds") or {},
        "registry_provenance": provenance,
        "registry_path": source_path,
    }


def _load_registry() -> dict[str, Any]:
    """Every registered tenant, plus exactly which root answered and what was unreadable."""
    out: dict[str, Any] = {
        "tenants": [],
        "root": None,
        "provenance": None,
        "errors": [],
        "unmeasured": [],
    }
    for root, provenance in _registry_sources():
        if not root.is_dir():
            continue
        files = sorted([p for p in root.glob("*.yaml") if p.is_file()])
        files += sorted([p for p in root.glob("*.json") if p.is_file() and p.name != "platform.schema.json"])
        if not files:
            continue
        records: list[dict[str, Any]] = []
        errors: list[str] = []
        for path in files:
            rec, err = (_read_yaml(path) if path.suffix == ".yaml" else _read_json(path))
            if err:
                errors.append(f"{path.name}: {err}")
                continue
            if not isinstance(rec, dict) or not rec.get("platform"):
                errors.append(f"{path.name}: not a registry record (no `platform`)")
                continue
            records.append(_tenant_from_record(rec, provenance, str(path)))
        if not records:
            continue
        out["tenants"] = sorted(records, key=lambda t: str(t["platform"]))
        out["root"] = str(root)
        out["provenance"] = provenance
        out["errors"] = errors
        unknown = [str(t["platform"]) for t in records if t["maturity"] == "unknown"]
        if unknown:
            out["unmeasured"].append(
                "registry: no `maturity` key for " + ", ".join(unknown)
                + " — learning/enforcing is unmeasured (the contract's default is `learning` "
                  "until 7 days of baseline history)".replace("  ", " ")
            )
        if provenance != "scripts-store":
            out["unmeasured"].append(
                "registry: the scripts-store registry (contract §3) is not installed yet; "
                f"reading the foundation card's artifacts at {root}"
            )
        if errors:
            out["unmeasured"].append(f"registry: {len(errors)} record(s) could not be parsed")
        return out
    out["unmeasured"].append(
        "registry: no registry record found at "
        + " or ".join(str(p) for p, _ in _registry_sources())
        + " — tenants are unknown, not zero"
    )
    return out


def _tenant_or_refuse(tenant: Optional[str], tenants: list[dict[str, Any]]) -> str:
    """Tenant is a required, explicit argument with no default (contract §4.2 r2)."""
    if tenant is None or not str(tenant).strip():
        raise HTTPException(
            status_code=400,
            detail="tenant is required and has no default; pass tenant=<slug> or tenant=all",
        )
    value = str(tenant).strip()
    if value == "all":
        return value
    known = {str(t["platform"]) for t in tenants}
    if value not in known:
        raise HTTPException(
            status_code=404,
            detail=f"tenant {value!r} is not registered (known: {sorted(known) or 'none'})",
        )
    return value


def _states_or_refuse(state: Optional[str]) -> set[str]:
    """The lifecycle predicate, allowlisted like ``sort`` (04 §3.1).

    An unrecognised state is REFUSED, not silently matched: a filter that matches nothing because it
    was misspelled renders as an empty queue, which is the same false-zero class as a dropped read.
    A comma-separated list is accepted (``state=triaging,contained``).
    """
    if state is None or not str(state).strip():
        return set()
    wanted = {s.strip() for s in str(state).split(",") if s.strip()}
    unknown = sorted(wanted - set(SOC_STATES))
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=f"state must be one of {list(SOC_STATES)} (got {unknown})",
        )
    return wanted


# --- detections catalogs -----------------------------------------------------
#
# THE SUITE HAS TWO CATALOGS OF RECORD, and they are NAMED — never resolved in candidate order
# (contract §5, as amended by the ruling on t_0e78bcf9). Each is read by its OWN engine against its
# OWN lake, and this panel renders BOTH. Neither is a predecessor of the other; neither is "legacy".
#
#   1. PLATFORM catalog — ``psec-detections.json``, the frozen §5 index. ``rules`` is a DICT
#      ({id: {...}}). Read by ``psec-gaps-detect.py`` (cron 8065d45ca251, every 15 min) and
#      ``psec-detect.py``, against the PLATFORM lake (``psec-sources.json`` -> ``lake_root``).
#   2. ENDPOINT catalog — ``siem-detections.json``, the suite's SECOND NAMED INDEX. ``rules`` is a
#      LIST with inline SQL and ``window_min``. Read by ``siem-detect.py`` from cron
#      ``f1ed861d4b6f`` EVERY 5 MINUTES with ``file_cards: true``, against the ENDPOINT lake
#      (``siem-lake-sources.json`` -> ``lake_root``, stream ``rmm-edr``).
#
# ⛔ THE ENDPOINT CATALOG IS NEVER A SUBSTITUTE FOR THE PLATFORM ONE. MEASURED 2026-09-18: the
# previous reader resolved the FIRST READABLE candidate and labelled the endpoint catalog
# ``legacy``, so its rules — a different engine, a different lake, a different rule shape —
# rendered as THE platform index whenever ``psec-detections.json`` was absent or unreadable. Under
# the ruling an absent platform index is **UNMEASURED for platform detection** and must say so by
# name, because a rule that runs somewhere else is not a measurement of the index that is missing.

PLATFORM_CATALOG_FILE = "psec-detections.json"
ENDPOINT_CATALOG_FILE = "siem-detections.json"
PLATFORM_LAKE_CONFIG = "psec-sources.json"
ENDPOINT_LAKE_CONFIG = "siem-lake-sources.json"

PLATFORM_CATALOG_PROVENANCE = "scripts-store"
ENDPOINT_CATALOG_PROVENANCE = "live-endpoint"

PLATFORM_CATALOG_ENGINE = "psec-gaps-detect.py (cron 8065d45ca251, every 15 min) + psec-detect.py"
ENDPOINT_CATALOG_ENGINE = "siem-detect.py (cron f1ed861d4b6f, every 5 min, file_cards: true)"

COMPARABILITY = (
    "each catalog is read by its own engine against its own lake, with its own rule shape "
    "(platform: `rules` is a DICT, `{rel}`/`view` SQL over the platform lake; endpoint: `rules` is "
    "a LIST, inline SQL over the endpoint lake). The two are NOT comparable rule-for-rule — only "
    "their rule IDS are counted together, as the two catalogs of one suite."
)

# NOT a catalog of the suite (ruling §1.6): the LA lane's STAGING file — 46 KQL-dialect rules, NO
# cron job, read only via `siem-detect.py --rules`. A rule is promoted out of it into
# siem-detections.json once its hits have been read on real rows. It is excluded from the census BY
# NAME so no future reader counts 46 + the endpoint catalog as the estate's detection coverage — and
# it is deliberately NOT rendered as a ``shadowed`` entry either, because ``shadowed`` says "this
# catalog is live and this panel is not resolving it", which would be a false claim about a file
# nothing schedules.
STAGING_CATALOGS = ("siem-detections-la.json",)

# The catalog files this panel knows BY NAME. Anything else in the scripts store matching
# ``*detections*.json`` — and not a STAGING file — is a genuine THIRD catalog and is reported,
# never silenced (see ``_shadow_report``).
KNOWN_CATALOG_FILES = (PLATFORM_CATALOG_FILE, ENDPOINT_CATALOG_FILE)


def _rule_record(name: str, r: dict[str, Any]) -> dict[str, Any]:
    """One rule, normalised to the fields the matrix and the catalog entries read."""
    return {
        "rule": name,
        "title": r.get("title") or "",
        "severity": r.get("severity") or "",
        "stream": r.get("stream") or "",
        "platforms": r.get("platforms") or "all",
        "maturity": r.get("maturity") or "",
        "suppression_key": r.get("suppression_key") or "",
    }


def _catalog_rules(data: Any) -> list[dict[str, Any]]:
    """The rules a catalog holds, in EITHER container shape.

    MEASURED 2026-09-18: the two live catalogs differ in shape — ``psec-detections.json`` is
    ``rules: {id: {...}}`` and ``siem-detections.json`` is ``rules: [{name: …}, …]``. A reader
    that assumed one shape read the other as empty, which is a failed measurement wearing a
    zero's clothes. Both shapes are therefore read here, and neither is guessed at.
    """
    raw = data.get("rules") if isinstance(data, dict) else None
    out: list[dict[str, Any]] = []
    if isinstance(raw, list):
        for r in raw:
            if not isinstance(r, dict):
                continue
            name = r.get("name") or r.get("rule")
            if name:
                out.append(_rule_record(str(name), r))
    elif isinstance(raw, dict):
        for name, r in raw.items():
            if isinstance(r, dict):
                out.append(_rule_record(str(name), r))
    return out


def _catalog_rule_ids(data: Any) -> list[str]:
    """The rule ids a catalog holds, in either container shape (see ``_catalog_rules``)."""
    return [r["rule"] for r in _catalog_rules(data)]


def _catalog_lake(config_name: str, role: str) -> tuple[Optional[str], Optional[str], list[str]]:
    """The lake a catalog is read against, from the ONE config key that lake has (§1, §4).

    Read from the catalog's OWN config file, never inferred from the other lake: the platform root
    and the endpoint root are two different roots, and a panel that showed one catalog a lake it is
    not read against would be comparing two engines' lakes — the defect this module removes, one
    layer up.
    """
    path = _scripts_dir() / config_name
    data, err = _read_json(path)
    if err:
        return None, str(path), [
            f"detections: the {role} lake config {path} is unreadable ({err}) — the {role} "
            "catalog's lake is unmeasured"]
    if isinstance(data, dict) and data.get("lake_root"):
        return str(data["lake_root"]), str(path), []
    return None, str(path), [
        f"detections: no `lake_root` in {path} — the {role} catalog's lake is unmeasured"]


def _catalog_entry(path: Path, *, role: str, name: str, provenance: str, engine: str,
                   lake: Optional[str], lake_source: Optional[str]) -> dict[str, Any]:
    """One NAMED catalog: what it is, what reads it, the lake it is read against, its own rule ids.

    ``present`` and ``readable`` are separate on purpose: a catalog that exists but cannot be parsed
    is a FAILED measurement (its rules are unmeasured), while one that does not exist is an ABSENCE
    — and neither is a zero. ``rule_records`` is the internal carrier of the full records; only the
    platform catalog's are kept by ``_detections`` (the matrix is the platform catalog's, and the
    endpoint catalog is rendered by its ids — see ``COMPARABILITY``).
    """
    entry: dict[str, Any] = {
        "role": role,
        "name": name,
        "path": str(path),
        "provenance": provenance,
        "engine": engine,
        "lake": lake,
        "lake_source": lake_source,
        "present": path.exists(),
        "readable": False,
        "count": 0,
        "rules": [],
        "errors": [],
        "unmeasured": [],
    }
    data, err = _read_json(path)
    if err:
        entry["errors"].append(err)
        entry["unmeasured"].append(
            f"detections: the {role} catalog {path} is present but UNREADABLE ({err}) — its rules "
            "are UNMEASURED, not zero")
        return entry
    if data is None:
        entry["unmeasured"].append(
            f"detections: the {role} catalog {path} is ABSENT — its rules are UNMEASURED, not zero")
        return entry
    records = _catalog_rules(data)
    entry["readable"] = True
    entry["rule_records"] = records
    entry["rules"] = [r["rule"] for r in records]
    entry["count"] = len(records)
    return entry


def _catalog_summary(c: dict[str, Any]) -> dict[str, Any]:
    """A catalog's identity for the provenance (``/meta``) panel — no rule records."""
    return {
        "role": c["role"],
        "name": c["name"],
        "path": c["path"],
        "provenance": c["provenance"],
        "engine": c["engine"],
        "lake": c["lake"],
        "lake_source": c["lake_source"],
        "present": c["present"],
        "readable": c["readable"],
        "count": c["count"],
        "rules": list(c["rules"]),
    }


def _shadow_report(resolved_ids: set[str]) -> tuple[list[dict], list[str]]:
    """Every OTHER live detection catalog in the scripts store, as a SHADOW entry — never a silence.

    Naming the suite's two catalogs is not a licence to stop looking: a THIRD catalog that something
    on this host reads must not become invisible merely because it is not one of the two named ones.
    MEASURED 2026-09-18 on this host — the defect this function was written for: with only a
    first-candidate rule in place, ``siem-detections.json``, read every five minutes by a cron with
    ``file_cards: true``, was reported as if it were the resolved catalog and its rules vanished
    from the panel. It is now a NAMED catalog of its own (see ``_detections``); this function covers
    what is left — a live catalog that is neither of the two named ones and not a STAGING file.

    A shadowed catalog is named here (file, every rule id). An ABSENT one says nothing (an absence
    is not a finding); an UNREADABLE one gets its own note and is still not a zero.
    """
    shadowed: list[dict] = []
    notes: list[str] = []
    root = _scripts_dir()
    if not root.is_dir():
        return shadowed, notes
    for path in sorted(root.glob("*detections*.json")):
        if not path.is_file() or path.name in KNOWN_CATALOG_FILES:
            continue
        if path.name in STAGING_CATALOGS:
            # A staging file, not a catalog of the suite (see ``STAGING_CATALOGS``): it is not a
            # finding and it is not counted — and it is not a `shadowed` entry either, because that
            # would claim a live catalog this panel is declining to resolve.
            continue
        data, err = _read_json(path)
        if err:
            notes.append(f"detections: the other catalog {path} is present but unreadable ({err}) "
                         "— any rules it holds are unmeasured, never zero")
            continue
        if data is None:
            continue
        ids = _catalog_rule_ids(data)
        if not ids:
            continue
        extra = [i for i in ids if i not in resolved_ids]
        if extra:
            shadowed.append({"path": str(path), "provenance": "unresolved-catalog",
                             "kind": "shadowed", "count": len(extra), "rules": extra})
            notes.append(
                f"detections: {len(extra)} rule(s) are SHADOWED — they live in {path} and NEITHER "
                f"named catalog resolves it. They are neither unread nor zero: "
                f"{', '.join(extra[:10])}" + ("…" if len(extra) > 10 else ""))
        else:
            notes.append(f"detections: {path} carries {len(ids)} rule(s), every one of them also "
                         "in a named catalog — nothing shadowed there")
    return shadowed, notes


def _detections() -> dict[str, Any]:
    """BOTH named catalogs of the suite, each with its own identity and its own rule ids.

    ⛔ There is NO candidate order and NO substitution here. The platform catalog is resolved BY
    NAME (§5's index) and the endpoint catalog is reported beside it as the suite's second named
    catalog; an absent or unreadable platform index is UNMEASURED for platform detection and says
    so. The reader this replaces resolved the first readable candidate and fell back to the endpoint
    catalog under the label ``legacy``, so rules from another engine, another lake and another rule
    shape rendered as THE platform index — the substitution the ruling on ``t_0e78bcf9`` removes.

    ``rules`` is therefore the PLATFORM catalog's records (the matrix's input) and NOTHING else;
    the endpoint catalog is under ``endpoint_catalog`` with its own ids, and ``catalogs`` carries
    both. A genuine third catalog is still reported under ``shadowed``.
    """
    unmeasured: list[str] = []
    plat_path = _scripts_dir() / PLATFORM_CATALOG_FILE
    endp_path = _scripts_dir() / ENDPOINT_CATALOG_FILE

    plat_lake, plat_lake_src, plat_lake_notes = _catalog_lake(PLATFORM_LAKE_CONFIG, "platform")
    endp_lake, endp_lake_src, endp_lake_notes = _catalog_lake(ENDPOINT_LAKE_CONFIG, "endpoint")

    platform = _catalog_entry(
        plat_path, role="platform", name="platform catalog — the frozen §5 index",
        provenance=PLATFORM_CATALOG_PROVENANCE, engine=PLATFORM_CATALOG_ENGINE,
        lake=plat_lake, lake_source=plat_lake_src)
    endpoint = _catalog_entry(
        endp_path, role="endpoint", name="endpoint catalog — the suite's second named index",
        provenance=ENDPOINT_CATALOG_PROVENANCE, engine=ENDPOINT_CATALOG_ENGINE,
        lake=endp_lake, lake_source=endp_lake_src)
    platform["unmeasured"].extend(plat_lake_notes)
    endpoint["unmeasured"].extend(endp_lake_notes)

    rules: list[dict[str, Any]] = list(platform.pop("rule_records", []))
    endpoint.pop("rule_records", None)

    # --- the PLATFORM side, by name. No fallback, no substitution ------------------------------
    if not platform["readable"]:
        why = "present but UNREADABLE" if platform["present"] else "ABSENT"
        platform["unmeasured"].append(
            f"detections: PLATFORM DETECTION IS UNMEASURED — the platform catalog ({plat_path}) is "
            f"{why}, and an absent index is NOT covered by the endpoint catalog: that is a "
            "different engine (siem-detect.py, every 5 min) reading a different lake, and its rules "
            "are not what this index resolved to.")
    unmeasured.extend(platform["unmeasured"])
    unmeasured.extend(endpoint["unmeasured"])

    plat_ids = [r["rule"] for r in rules]
    endp_ids = list(endpoint["rules"])
    overlap = sorted(set(plat_ids) & set(endp_ids))
    union = sorted(set(plat_ids) | set(endp_ids))
    errors: list[str] = list(platform["errors"])
    if overlap:
        errors.append(f"rule id(s) in BOTH catalogs: {', '.join(overlap)}")
        unmeasured.append(
            f"detections: {len(overlap)} rule id(s) appear in BOTH catalogs "
            f"({', '.join(overlap)}) — they are double-counted, and the two catalogs are not "
            "comparable rule-for-rule")

    shadowed, notes = _shadow_report(set(union))
    unmeasured.extend(notes)

    return {
        "rules": rules,
        "rules_total": len(rules),
        "path": str(plat_path) if platform["present"] else None,
        "provenance": PLATFORM_CATALOG_PROVENANCE if platform["readable"] else None,
        "kind": "platform" if platform["readable"] else None,
        "errors": errors,
        "shadowed": shadowed,
        "catalogs": [platform, endpoint],
        "platform_catalog": platform,
        "endpoint_catalog": endpoint,
        "catalogs_rules_total": len(union),
        "rule_ids_shared": overlap,
        "comparability": COMPARABILITY,
        "unmeasured": unmeasured,
    }


# --- lake --------------------------------------------------------------------

# The psec lake layout is frozen (contract §1). The legacy endpoint feed has its OWN schema, so it
# is read by its own accessor and labelled `legacy` rather than bent into the frozen shape.
LAKE_PY_CANDIDATES = ("/home/hermes/.lakevenv/bin/python3",)
_SAFE_IDENT = re.compile(r"^[A-Za-z0-9_.\-]+$")  # feed names are directory names: rmm-edr, defend-linux
_SAFE_GLOB = re.compile(r"^[A-Za-z0-9_./*=\-]+\.parquet$")

_LAKE_PROBE = r"""
import json, sys
import duckdb
req = json.load(sys.stdin)
con = duckdb.connect()
out = []
for feed in req["feeds"]:
    try:
        q = (
            "select count(*) as n, max(%(ts)s) as mx, max(%(ing)s) as ing, "
            "count(distinct %(dev)s) as ndev "
            "from read_parquet('%(glob)s', hive_partitioning=true)"
        ) % feed
        n, mx, ing, ndev = con.execute(q).fetchone()
        out.append({"name": feed["name"], "ok": True, "rows": int(n),
                    "last_event": str(mx) if mx is not None else None,
                    "last_ingest": str(ing) if ing is not None else None,
                    "devices": int(ndev) if ndev is not None else None})
    except Exception as exc:
        out.append({"name": feed["name"], "ok": False,
                    "error": "%s: %s" % (type(exc).__name__,
                                         str(exc).splitlines()[0] if str(exc).splitlines() else "")})
print(json.dumps(out))
"""


def _lake_python() -> Optional[str]:
    for path in LAKE_PY_CANDIDATES:
        if Path(path).is_file():
            return path
    return None


def _feed_glob(name: str) -> str:
    return f"{name}/**/*.parquet"


def _lake_config() -> dict[str, Any]:
    """lake_root and the feeds to probe, from the ONE config key the contract allows (§1, §4)."""
    psec_path = _scripts_dir() / "psec-sources.json"
    legacy_path = _scripts_dir() / "siem-lake-sources.json"
    data, err = _read_json(psec_path)
    if err:
        return {"lake_root": None, "provenance": "unreadable", "path": str(psec_path),
                "feeds": [], "unmeasured": [f"lake: {psec_path.name} unreadable: {err}"]}
    if isinstance(data, dict) and data.get("lake_root"):
        return {
            "lake_root": str(data["lake_root"]),
            "provenance": "scripts-store",
            "path": str(psec_path),
            "feeds": [{"name": s.get("name"), "enabled": bool(s.get("enabled", True)),
                       "quota_gb": s.get("quota_gb")} for s in (data.get("sources") or [])],
            "unmeasured": [],
        }
    legacy, lerr = _read_json(legacy_path)
    if isinstance(legacy, dict) and legacy.get("lake_root"):
        return {
            "lake_root": str(legacy["lake_root"]),
            "provenance": "legacy-live",
            "path": str(legacy_path),
            "feeds": [{"name": s.get("name"), "enabled": bool(s.get("enabled", True)),
                       "quota_gb": s.get("quota_gb")} for s in (legacy.get("sources") or [])],
            "unmeasured": [
                "lake: psec-sources.json (contract §1) is not installed; reading the live endpoint "
                f"feed described by {legacy_path.name}. Its schema is the predecessor's, not the "
                "five-stream schema, so stream-level panels stay unmeasured."
            ],
        }
    return {"lake_root": None, "provenance": None, "path": None, "feeds": [],
            "unmeasured": ["lake: no lake config found (psec-sources.json or siem-lake-sources.json)"]}


def _probe_feeds(lake_root: str, feeds: list[dict[str, Any]], legacy: bool) -> dict[str, Any]:
    """Run the duckdb probe in the lake venv (duckdb is NOT importable in the dashboard venv)."""
    py = _lake_python()
    if not py:
        return {"rows": [], "unmeasured": ["lake: no lake interpreter found (duckdb lives in "
                                           "/home/hermes/.lakevenv)"]}
    ts_col = "timestamp" if legacy else "event_time"
    ing_col = "_ingest_ts" if legacy else "ingested_at"
    dev_col = "device_id" if legacy else "asset_id"
    want = []
    for f in feeds:
        name = f.get("name")
        if not name or not _SAFE_IDENT.match(str(name)) or not f.get("enabled", True):
            continue
        glob = f"{lake_root.rstrip('/')}/{_feed_glob(str(name))}"
        if not _SAFE_GLOB.match(glob):
            continue
        want.append({"name": str(name), "glob": glob, "ts": ts_col, "ing": ing_col, "dev": dev_col})
    if not want:
        return {"rows": [], "unmeasured": ["lake: no enabled feed to probe"]}
    try:
        proc = subprocess.run(
            [py, "-c", _LAKE_PROBE],
            input=json.dumps({"feeds": want}),
            capture_output=True, text=True, timeout=120, check=False,
        )
    except Exception as exc:  # noqa: BLE001
        return {"rows": [], "unmeasured": [f"lake: probe failed to run: {type(exc).__name__}: {exc}"]}
    if proc.returncode != 0:
        return {"rows": [], "unmeasured": [
            f"lake: probe exited {proc.returncode}: {(proc.stderr or '').strip()[:300]}"]}
    try:
        rows = json.loads(proc.stdout.strip().splitlines()[-1])
    except Exception as exc:  # noqa: BLE001
        return {"rows": [], "unmeasured": [f"lake: probe output unparseable: {exc}"]}
    unmeasured: list[str] = []
    for r in rows:
        if not r.get("ok"):
            unmeasured.append(f"lake feed {r.get('name')}: {r.get('error')}")
    return {"rows": rows, "unmeasured": unmeasured}


# --- kanban ------------------------------------------------------------------

def _boards() -> list[dict[str, Any]]:
    """Every board, via the library the CLI uses (a dir scan drops the default board).

    Every accepted ``db_path`` must live INSIDE the resolved hermes home. ``kanban_db``'s board
    metadata can answer with a path from another home (its registry is not fully home-scoped), and a
    read that silently crosses into the live estate from a test's temp home is exactly the class of
    defect this dashboard exists to make visible. A path outside the home is logged and dropped, and
    the directory scan below still finds this home's own boards.
    """
    out: list[dict[str, Any]] = []
    home = _hermes_home().resolve()
    try:
        entries = kanban_db.list_boards(include_archived=False)
    except Exception:  # noqa: BLE001
        log.warning("kanban_db.list_boards failed; falling back to the boards/ scan", exc_info=True)
        entries = []
    for e in entries:
        db = e.get("db_path")
        if not db or not Path(db).is_file():
            continue
        try:
            Path(db).resolve().relative_to(home)
        except ValueError:
            log.warning("kanban: ignoring board %r at %s — outside this hermes home (%s)",
                        e.get("slug"), db, home)
            continue
        out.append({"slug": e["slug"], "title": e.get("name") or e["slug"], "path": str(db)})
    if out:
        return out
    root = home / "kanban" / "boards"
    if root.is_dir():
        for d in sorted(root.iterdir()):
            db = d / "kanban.db"
            if db.is_file():
                out.append({"slug": d.name, "title": d.name, "path": str(db)})
    default_db = home / "kanban.db"
    if default_db.is_file() and not any(b["slug"] == "default" for b in out):
        out.insert(0, {"slug": "default", "title": "default", "path": str(default_db)})
    return out


def _ro(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=8)
    conn.row_factory = sqlite3.Row
    return conn


# --- findings ----------------------------------------------------------------

# The card body is the READER's shape (contract §7), and TWO producers write TWO shapes. Both are
# read here on purpose: `siem-detect.py` writes `Detection: `rule`` / `Severity:` / `Subject:` / a
# `Detail:` block, and the PSEC filers wrote lowercase `rule:` / `severity:` / `subject:` with a
# one-line `detail:` before kanban `t_6af9c689` fixed them AT THE PRODUCER. The cards already on the
# boards keep the old shape and can never be re-bodied — a re-run returns the existing card on its
# identity key and rewrites nothing — so this reader is the only place that can repair them.
# MEASURED 2026-09-19T01:17Z through this reader: 0 of 134 `psec-gaps-detect` rows parsed a rule or a
# subject, so every one rendered with an unmeasured rule, subject and device and could not be
# grouped, and `_attribution()` had nothing to resolve the owning tenant from.
#
# Separate arms, NOT a case-insensitive version of the arms above: a `detail:` line inside the prose
# of a NEW-shape body must not be mistaken for the new shape's `Detail:` block, nor the reverse.
_SUBJECT_RE = re.compile(r"^\s*Subject:\s*(?P<subject>.+?)\s*$", re.M)
_DETECTION_RE = re.compile(r"^\s*Detection:\s*`?(?P<rule>[A-Za-z0-9_.\-]+)`?\s*$", re.M)
_SEVERITY_RE = re.compile(r"^\s*Severity:\s*(?P<sev>[a-z]+)\s*$", re.M)
_LEGACY_RULE_RE = re.compile(r"^\s*rule:\s*`?(?P<rule>[A-Za-z0-9_.\-]+)`?\s*$", re.M)
_LEGACY_SEVERITY_RE = re.compile(r"^\s*severity:\s*(?P<sev>[a-z]+)\s*$", re.M)
_LEGACY_SUBJECT_RE = re.compile(r"^\s*subject:\s*(?P<subject>.+?)\s*$", re.M)
_LEGACY_DETAIL_RE = re.compile(r"^\s*detail:\s*(?P<detail>.+?)\s*$", re.M)


def _parse_finding(body: Optional[str]) -> dict[str, Any]:
    text = body or ""
    rule = _DETECTION_RE.search(text) or _LEGACY_RULE_RE.search(text)
    sev = _SEVERITY_RE.search(text) or _LEGACY_SEVERITY_RE.search(text)
    subj = _SUBJECT_RE.search(text) or _LEGACY_SUBJECT_RE.search(text)
    subject = (subj.group("subject") if subj else "").strip()
    device = ""
    if subject:
        device = subject.split(":", 1)[0].strip()
    detail: list[str] = []
    if "Detail:" in text:
        chunk = text.split("Detail:", 1)[1]
        for line in chunk.splitlines():
            line = line.strip()
            if line.startswith("```"):
                continue
            if line.startswith("Events in window") or line.startswith("Window from"):
                break
            if line:
                detail.append(line)
    else:
        legacy_detail = _LEGACY_DETAIL_RE.search(text)
        if legacy_detail:
            detail.append(legacy_detail.group("detail").strip())
    return {
        "rule_id": rule.group("rule") if rule else None,
        "severity": sev.group("sev").lower() if sev else None,
        "subject": subject or None,
        "device_id": device or None,
        "detail": (detail[0] if detail else None),
    }


def _read_findings() -> dict[str, Any]:
    """The finding queue's POPULATION: rows the detectors filed on the boards, with the SOC lifecycle.

    Read directly from each board's SQLite (read-only), not from an API, so the operator surface
    cannot disagree with the ledger.

    Nothing is filtered or capped HERE, on purpose. No STATUS is excluded either: a finding card that
    is ``archived`` is INCLUDED and carries ``archived: True`` on its row. For a FINDING, `archived`
    is a SILENCING state, not a closure (contract §7) — the read used to filter ``status !=
    'archived'``, so an archived finding was counted NOWHERE: no row, no disposition, no MTTR, and
    ``_attribution`` never ran for it. MEASURED 2026-09-19T01:20:57–01:21:02Z: seven fixture-artefact
    `psec-gaps-detect` cards were archived by their adjudicating lane (card `t_2a666fa6`, "harness
    artefact, not a finding") and the queue's PSEC population fell **134 → 127**, with no disposition
    recorded for any of the seven. The adjudications were sound; the STATE was the defect. What was
    missing was the ROW — and, until 2026-09-23 (card t_be4443f9), the row was then labelled with a
    CLOSURE it never earned: the status→lifecycle map read `archived → resolved`, so restoring the row
    restored it as a resolved case and incremented the resolved KPI. It now reads `archived →
    archived` (see ``SILENCED_STATES``), and an archived row carries no verdict.

    The scope predicate (tenant, lifecycle state)
    belongs to the caller and the row cap belongs AFTER it: a cap applied to the whole-estate read
    makes a scoped read report another scope's numbers, and lets a tenant's rows disappear behind an
    estate-wide cap and render as a false zero (04 §3.1, §3.4 — "a failed measurement must never
    render as a zero"). ``population_total`` is therefore the whole read, and every scope's own
    total is counted by the caller over the filtered rows.
    """
    rows: list[dict[str, Any]] = []
    boards_scanned: list[str] = []
    unmeasured: list[str] = []
    total = 0
    placeholders = ", ".join("?" for _ in FINDING_CREATORS)
    for b in _boards():
        try:
            with closing(_ro(b["path"])) as conn:
                # The verdict's FALLBACK source. `result` is the disposition's home (contract §7),
                # but `kanban_complete(summary=...)` is the tooling's documented handoff and most
                # completers use it: MEASURED 2026-09-19, 414 of 583 `done` finding cards carry
                # their verdict ONLY in the latest run's summary. A board with no `task_runs` table
                # (a synthetic fixture) is read the old way rather than reported unmeasured.
                has_runs = bool(conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='task_runs'").fetchone())
                summary_arm = (", (SELECT r.summary FROM task_runs r WHERE r.task_id = tasks.id"
                               " ORDER BY r.id DESC LIMIT 1) AS run_summary") if has_runs else ", NULL AS run_summary"
                cur = conn.execute(
                    f"""
                    SELECT id, title, status, assignee, created_by, created_at, completed_at,
                           block_kind, last_heartbeat_at, body, result{summary_arm}
                    FROM tasks
                    WHERE (created_by IN ({placeholders}) OR title LIKE 'SIEM [%' OR title LIKE 'PSEC [%')
                    ORDER BY created_at DESC, id DESC
                    """,
                    FINDING_CREATORS,
                )
                found = cur.fetchall()
                boards_scanned.append(b["slug"])
        except Exception as exc:  # noqa: BLE001 — one unreadable board is one unmeasured entry
            unmeasured.append(f"board {b['slug']}: {type(exc).__name__}: {exc}")
            continue
        for r in found:
            total += 1
            parsed = _parse_finding(r["body"])
            m = FINDING_TITLE_RE.match(r["title"] or "")
            soc = CARD_TO_SOC.get(r["status"], "unrecognised_status")
            created = _int_or_none(r["created_at"]) or 0
            age = max(0, _now() - created) if created else None
            last_touch = _int_or_none(r["last_heartbeat_at"]) or _int_or_none(r["completed_at"]) or created
            # `stale` is an OPEN-CASE signal, and the payload now SAYS so instead of leaving it to be
            # inferred from a bare boolean. `stale_applicable` is whether staleness is defined for
            # this row at all: a `done` or `archived` row has no case to go stale, so its
            # `stale: false` reads NOT APPLICABLE, never "fresh". MEASURED 2026-09-23 (card
            # t_be4443f9, arm STALE): the field name promised a property of the row and delivered a
            # property of OPEN rows, with nothing in the payload saying which.
            stale_applicable = soc in OPEN_STATES
            stale = bool(stale_applicable and age is not None and age > STALE_OPEN_SECONDS
                         and (_now() - (last_touch or created)) > STALE_OPEN_SECONDS)
            rows.append({
                "id": r["id"],
                "board": b["slug"],
                "title": r["title"],
                "severity": (parsed["severity"] or (m.group("sev") if m else None) or "unmeasured"),
                "rule_id": parsed["rule_id"],
                "subject": parsed["subject"],
                "device_id": parsed["device_id"],
                "detail": parsed["detail"],
                "card_status": r["status"],
                # `archived` is a SILENCING state for a finding, not a closure (contract §7), so the
                # row is INCLUDED above and the record survives. This flag is the ledger's own status
                # column read back verbatim — never inferred and never defaulted — and since
                # 2026-09-23 (card t_be4443f9) it is no longer the ONLY thing that tells an archived
                # row from a closed one: `lifecycle` now reads `archived` too, and the disposition is
                # unrecorded. A consumer that only ever looked at `archived` still sees it.
                "archived": r["status"] == "archived",
                "lifecycle": soc,
                "block_kind": r["block_kind"],
                "assignee": r["assignee"],
                "filed_by": r["created_by"],
                "created_at": _iso(r["created_at"]),
                "resolved_at": _iso(r["completed_at"]),
                "age_seconds": age,
                "stale": stale,
                # Whether staleness is DEFINED for this row (see the block above). A consumer that
                # reads only `stale` on a closed row is reading "not applicable"; this field is what
                # lets it tell that apart from "fresh".
                "stale_applicable": stale_applicable,
                "disposition": _disposition(r["result"], r["run_summary"], soc),
                "mttr_seconds": ((_int_or_none(r["completed_at"]) - created)
                                 if (_int_or_none(r["completed_at"]) and created) else None),
            })
    rows.sort(key=lambda x: (x["created_at"] or "", x["id"] or ""), reverse=True)
    return {
        "rows": rows,
        "population_total": total,
        "boards_scanned": boards_scanned,
        "unmeasured": unmeasured,
    }


def _disposition(result: Optional[str], summary: Optional[str], soc: str) -> Optional[str]:
    """The finding's disposition — `result` is its HOME, the latest run's `summary` is read too.

    Contract §7 names `tasks.result` as the disposition's home, and that stays true: a non-empty
    `result` is read and the summary is never consulted. The summary is read only where `result` is
    empty, because `kanban_complete(summary=...)` is the tooling's documented handoff and it is where
    the verdict actually is — MEASURED 2026-09-19: 414 of 583 `done` finding cards carry a verdict in
    the run summary with `result` NULL, so all 414 rendered `resolved (disposition unrecorded)`.
    Reading the fallback repairs them with no board write.

    ⛔ A verdict written into a COMMENT is still NOT a disposition: a thread is prose, not a field,
    and reading it would make the queue depend on free text it cannot validate.

    Vocabulary, in order (a summary saying "FALSE POSITIVE, benign" is a false positive):
      * `false_positive` — the detector was wrong.
      * `contained` — a response action bounded it.
      * `benign` — expected, no incident, or a labelled positive control, with the detector CORRECT.
        Its own value deliberately: folding it into `false_positive` would tell rule-tuning to retune
        a rule that is working (MEASURED: ~400 of those 414 fallback summaries say benign/expected,
        only 14 say "false positive" in so many words).

    ⛔ A SILENCED row has no verdict to read. For an `archived` card the free text is NOT a
    disposition and is never consulted for one (contract §7): MEASURED 2026-09-23 (card t_be4443f9,
    arm ARCH2), an archived card carrying `result="contained: …"` rendered as a CONTAINED incident.
    So the gate comes FIRST — a silenced row is answered before `result`/`summary` are looked at.
    """
    if soc in SILENCED_STATES:
        return SILENCED_DISPOSITION
    text = result if (result or "").strip() else (summary or "")
    low = (text or "").lower()
    if "false positive" in low or "false_positive" in low or "false-positive" in low:
        return "false_positive"
    if "contained" in low:
        return "contained"
    if any(k in low for k in ("benign", "no incident", "not an incident", "not a security incident",
                              "positive control")):
        return "benign"
    if soc == "resolved":
        return "resolved (disposition unrecorded)"
    return None


def _attribution(finding: dict[str, Any], tenants: list[dict[str, Any]]) -> tuple[str, Optional[str]]:
    """Resolve a finding's owning tenant from the REGISTRY's own asset rules (contract §3, §4.2 r1).

    Tenant is resolved from our registry, never from anything the producer supplied. A finding that
    matches no registered asset rule lands in ``_unattributed`` — its own row, its own count, never
    folded into a tenant (contract §4.2 r9). When the registry is unreadable the answer is
    ``_unattributed`` (fail-closed), not a guess.
    """
    haystack = " ".join(str(x) for x in (finding.get("subject"), finding.get("detail"),
                                         finding.get("title"), finding.get("device_id")) if x)
    for t in tenants:
        for rule in t.get("assets") or []:
            match = (rule or {}).get("match") or {}
            needle = match.get("resource_id_contains")
            if needle and str(needle) in haystack:
                return str(t["platform"]), f"asset rule resource_id_contains={needle}"
            dev = match.get("device_id")
            if dev and finding.get("device_id") and str(dev) == str(finding["device_id"]):
                return str(t["platform"]), f"asset rule device_id={dev}"
    return "_unattributed", None


def _attribute_all(rows: list[dict[str, Any]], tenants: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for r in rows:
        platform, why = _attribution(r, tenants)
        r = dict(r)
        r["platform"] = platform
        r["attribution_rule"] = why
        out.append(r)
    return out


# --- retirement board --------------------------------------------------------

def _posture() -> dict[str, Any]:
    roots = [(_scripts_dir(), "scripts-store"),
             (_artifact_root(), "wip-outbox")]
    for root, provenance in roots:
        path = root / "azure-posture.json"
        if not path.is_file():
            continue
        data, err = _read_json(path)
        if err:
            return {"data": None, "path": str(path), "provenance": provenance,
                    "unmeasured": [f"retirement: {path} unreadable: {err}"]}
        unmeasured: list[str] = []
        if provenance != "scripts-store":
            unmeasured.append(
                "retirement: azure-posture.json lives in the exit measurement's artifact dir, not "
                "the scripts store — the numbers are a snapshot, not a live ARM read"
            )
        return {"data": data, "path": str(path), "provenance": provenance,
                "unmeasured": unmeasured, "mtime": _iso(path.stat().st_mtime)}
    return {"data": None, "path": None, "provenance": None,
            "unmeasured": ["retirement: no azure-posture.json found — Sentinel/Defender posture "
                           "is unmeasured, not zero"]}


def _sentinel_facts(posture: Optional[dict[str, Any]]) -> dict[str, Any]:
    facts: dict[str, Any] = {"workspaces": [], "enabled_workspaces": [], "incidents": {},
                             "alert_rules": None, "automation_rules": None, "connectors": None}
    if not isinstance(posture, dict):
        return facts
    facts["workspaces"] = [w.get("name") for w in (posture.get("log_analytics_workspaces") or [])]
    sent = posture.get("sentinel") or {}
    for name, ws in sent.items():
        if not isinstance(ws, dict):
            continue
        has = any(isinstance(ws.get(k), dict) and "value" in ws.get(k, {}) for k in
                  ("alert_rules", "automation_rules", "data_connectors", "incidents"))
        if not has:
            continue
        facts["enabled_workspaces"].append(name)
        rules = ws.get("alert_rules") or {}
        customs = []
        builtin_names: list[str] = []
        for r in (rules.get("value") or []):
            name = str(r.get("name") or "")
            kind = str(r.get("kind") or "")
            template = str((r.get("properties") or {}).get("alertRuleTemplateName") or "")
            is_builtin = (kind.lower() == "fusion" or name.lower().startswith("builtin")
                          or template.lower().startswith("builtin"))
            if is_builtin:
                builtin_names.append(name or kind or "builtin")
            else:
                customs.append(name)
        facts["custom_alert_rules"] = len(customs)
        facts["alert_rules_total"] = len(rules.get("value") or [])
        facts["builtin_alert_rules"] = builtin_names
        facts["automation_rules"] = len((ws.get("automation_rules") or {}).get("value") or [])
        facts["connectors"] = len((ws.get("data_connectors") or {}).get("value") or [])
        incs = (ws.get("incidents") or {}).get("value") or []
        by_status: dict[str, int] = {}
        by_sev: dict[str, int] = {}
        newest = None
        for i in incs:
            props = i.get("properties") or {}
            st = str(props.get("status") or "?")
            by_status[st] = by_status.get(st, 0) + 1
            sv = str(props.get("severity") or "?")
            by_sev[sv] = by_sev.get(sv, 0) + 1
            ct = props.get("createdTimeUtc") or i.get("createdTimeUtc")
            if ct and (newest is None or str(ct) > str(newest)):
                newest = ct
        facts["incidents"] = {"total": len(incs), "by_status": by_status, "by_severity": by_sev,
                              "newest": newest}
    return facts


def _defender_facts(posture: Optional[dict[str, Any]]) -> dict[str, Any]:
    facts: dict[str, Any] = {"standard_plans": [], "plans_total": None, "alerts": None, "contacts": None}
    if not isinstance(posture, dict):
        return facts
    plans = (posture.get("defender_pricings") or {}).get("value") or []
    facts["plans_total"] = len(plans)
    standard = []
    for p in plans:
        props = p.get("properties") or {}
        if str(props.get("pricingTier") or "").lower() == "standard":
            standard.append({"name": p.get("name"), "subPlan": props.get("subPlan")})
    facts["standard_plans"] = standard
    facts["standard_count"] = len(standard)
    contacts = posture.get("defender_contacts") or []
    facts["contacts"] = len(contacts)
    facts["automation_rules"] = len((posture.get("defender_automations") or {}).get("value") or [])
    return facts


# Exit-gate items. The measured value comes from the posture artifact; the *proof* state
# (shadow window green?) comes from the artifact the exit card writes, and is `unproven` when
# absent — never assumed green.
#
# THE GATE'S KEY CONTRACT (written down here because it is the consuming side of an artifact whose
# producer, t_eb7d6b90, publishes no schema): ``psec-exit-gate.json`` is either
#   {"items": [ {id, board, item, measured, proof: {state, evidence}}, ... ]}   <- preferred
# or
#   {"shadow": {"<proof key>": {"green": true|false, "evidence": ...}}, ...}
# where a proof key is the item's ``id``. The one alias that exists is deliberate: the shadow item's
# id is ``sentinel.shadow`` and the project has also called that proof ``sentinel.shadow.7d``. A
# producer that writes the obvious key must not leave the item `unproven` forever, so both spellings
# are read, and the key that actually answered is echoed back as ``proof.key``.
# Full schema: /home/hermes/hermes-outbox/2026-09-18-protection-suite/exit-gate.schema.json
PROOF_KEY_ALIASES = {"sentinel.shadow": ("sentinel.shadow.7d", "sentinel.shadow.7")}


def _exit_gate_items(posture_path: Optional[str], gate: Optional[dict[str, Any]],
                     sentinel: dict[str, Any], defender: dict[str, Any]) -> list[dict[str, Any]]:
    gate = gate or {}
    items = gate.get("items") if isinstance(gate.get("items"), list) else None
    if items:
        return items

    def proof(item_id: str) -> dict[str, Any]:
        shadow = gate.get("shadow")
        if not isinstance(shadow, dict):
            shadow = {}
        for key in (item_id,) + tuple(PROOF_KEY_ALIASES.get(item_id, ())):
            entry = shadow.get(key)
            if isinstance(entry, dict) and entry.get("green") is True:
                return {"state": "green", "evidence": entry.get("evidence"), "key": key}
        return {"state": "unproven", "evidence": None, "key": None}

    # The item text carries NO live count: the counts move (they are `measured`), and a sentence that
    # quotes one goes stale on the first new incident (04 §3.4 — a number that reads as live when it
    # is not is worse than no number).
    return [
        {"id": "sentinel.connectors", "board": "sentinel",
         "item": "The Microsoft-product connectors' data sources are ingested or recorded as not-needed",
         "measured": {"connectors": sentinel.get("connectors")},
         "proof": proof("sentinel.connectors")},
        {"id": "sentinel.incidents", "board": "sentinel",
         "item": "The Sentinel incidents are adjudicated (verdict each; stale backlog closed with a reason)",
         "measured": sentinel.get("incidents") or {},
         "proof": proof("sentinel.incidents")},
        {"id": "sentinel.fusion", "board": "sentinel",
         "item": "The built-in fusion rule's behaviour is covered by the multisource catalog rule",
         "measured": {"builtin_alert_rules": sentinel.get("builtin_alert_rules"),
                      "custom_alert_rules": sentinel.get("custom_alert_rules")},
         "proof": proof("sentinel.fusion")},
        {"id": "sentinel.shadow", "board": "sentinel",
         "item": "7-day shadow window vs Sentinel, zero unexplained divergence",
         "measured": {"enabled_workspaces": sentinel.get("enabled_workspaces")},
         "proof": proof("sentinel.shadow")},
        {"id": "defender.substitution", "board": "defender",
         "item": "The distinct Defender alert types are mapped through the substitution matrix",
         "measured": {"distinct_alert_types": gate.get("defender_distinct_alert_types")},
         "proof": proof("defender.substitution")},
        {"id": "defender.slices", "board": "defender",
         "item": "The plans at Standard are retired one slice at a time, each with a shadow-mode proof "
                 "+ 14 days of comparison",
         "measured": {"standard_plans": defender.get("standard_count"),
                      "plans_total": defender.get("plans_total")},
         "proof": proof("defender.slices")},
    ]


def _owner_spend_card() -> dict[str, Any]:
    """The retirement's spend gate is a real card; show its real state."""
    out = {"found": False, "unmeasured": []}
    for b in _boards():
        try:
            with closing(_ro(b["path"])) as conn:
                row = conn.execute(
                    "SELECT id, status, assignee, title, created_at FROM tasks "
                    "WHERE title LIKE '%Sentinel%' AND title LIKE '%Defender%' "
                    "  AND (title LIKE 'OWNER SPEND%' OR title LIKE '%cancel%' OR title LIKE '%Cancel%') "
                    "ORDER BY (title LIKE 'OWNER SPEND%') DESC, created_at DESC LIMIT 1"
                ).fetchone()
        except Exception as exc:  # noqa: BLE001
            out["unmeasured"].append(f"board {b['slug']}: {type(exc).__name__}: {exc}")
            continue
        if row:
            out = {"found": True, "id": row["id"], "board": b["slug"], "status": row["status"],
                   "assignee": row["assignee"], "title": row["title"],
                   "created_at": _iso(row["created_at"]), "unmeasured": out["unmeasured"]}
            return out
    out["unmeasured"].append("owner-spend card: no Sentinel/Defender cancellation card found on any board")
    return out


# --- endpoints: reads --------------------------------------------------------

# --- the capability floor: a recorded DECISION, not a measurement -------------
#
# t_527e3f35 asked whether host prevention and host rollback are in scope. They are not, and the
# answer is load-bearing for how every other panel may be read: a dashboard that renders coverage,
# liveness and a finding queue while declining to say "there is no pre-execution blocking and no
# undo on the host" is a surface that implies a capability the estate does not have.
#
# So the floor is read from a versioned record shipped beside this module, and NEVER inferred. When
# the record cannot be read, the compiled-in floor below is rendered with provenance
# ``compiled-in`` plus an ``unmeasured`` entry: "I could not read the record" may never render as
# "the suite does everything".
CAPABILITY_FILE = "capability.json"

CAPABILITY_FLOOR: dict[str, Any] = {
    "statement_version": 0,
    "decided": None,
    "decided_by": None,
    "decision_card": "t_527e3f35",
    "decision": ("Host prevention and host rollback are OUT of the EDR port and out of this suite; "
                 "control-plane enforcement is IN, and only where the action is reversible with its "
                 "inverse shipped. The suite is detect-and-gated-respond."),
    "reason": ("The versioned capability record could not be read, so this compiled-in floor is "
               "rendered instead. It names the same gaps; the record is authoritative and carries "
               "the measurements."),
    "contract_ref": "PROTECTION-SUITE-CONTRACT.md section 11",
    "capabilities": [
        {"id": "detect", "capability": "Detection -- rules evaluated over the lake", "state": "shipped",
         "promise": "Findings are filed as they are detected.",
         "statement": "Detectors are SQL over the local parquet lake.", "evidence": []},
        {"id": "respond", "capability": "Gated response -- requested -> delivered -> acked",
         "state": "shipped", "promise": "A command that was not acked is not claimed as delivered.",
         "statement": "Signed single-writer command channel with an approval gate.", "evidence": []},
        {"id": "respond.inverse", "capability": "Every control action ships WITH its inverse",
         "state": "shipped", "promise": "An action taken during an incident can be undone.",
         "statement": "isolate/unisolate, block_ip/unblock_ip, dns sinkhole apply/remove.",
         "evidence": []},
        {"id": "enforce.control_plane",
         "capability": "Control-plane enforcement (identity / network / workload)", "state": "shipped",
         "promise": "This is the WHOLE of the suite's prevention story.",
         "statement": "Reversible control-plane actions only; nothing here blocks code on a host.",
         "evidence": []},
        {"id": "prevent.host", "capability": "Host prevention -- blocking execution BEFORE it runs",
         "state": "out_of_scope",
         "promise": "NOT CLAIMED. Do not read any number here as pre-execution blocking.",
         "statement": ("No pre-exec blocking exists on Linux. What exists is post-exec confinement "
                       "(AppArmor, parent-profile eval, disarmed by default); bpf_lsm is dormant and "
                       "no SEC(\"lsm/...\") program exists."),
         "evidence": []},
        {"id": "rollback.host", "capability": "Host rollback -- undo a file write, a process, state",
         "state": "out_of_scope", "promise": "NOT CLAIMED. There is no undo for a host change.",
         "statement": "Rollback does not exist; quarantine can only un-quarantine what it took.",
         "evidence": []},
        {"id": "tamper.host", "capability": "Host tamper resistance / self-protection",
         "state": "partial", "promise": "Userspace-only, and stated as such.",
         "statement": ("Userspace-only: root can kill -9 the sensor and end visibility; no "
                       "kernel-enforced self-protection."),
         "evidence": []},
    ],
}


def _capability() -> dict[str, Any]:
    """Read the recorded capability floor, or fall back to the compiled-in one — never to silence."""
    path = Path(__file__).resolve().parent / CAPABILITY_FILE
    data, err = _read_json(path)
    unmeasured: list[str] = []
    if isinstance(data, dict) and isinstance(data.get("capabilities"), list) and data["capabilities"]:
        provenance = "plugin"
    else:
        data = CAPABILITY_FLOOR
        provenance = "compiled-in"
        unmeasured.append(
            f"capability: {path} "
            + (f"unreadable: {err}" if err else "missing")
            + " — the compiled-in floor is rendered instead of the versioned record; it names the "
              "same host prevention/rollback gaps, but the record is authoritative"
        )
    rows = []
    for c in data.get("capabilities", []):
        rows.append({
            "id": c.get("id"),
            "capability": c.get("capability"),
            "state": c.get("state") or "unmeasured",
            "promise": c.get("promise"),
            "statement": c.get("statement"),
            "evidence": list(c.get("evidence") or []),
        })
    return {
        "path": str(path),
        "provenance": provenance,
        "statement_version": data.get("statement_version"),
        "decided": data.get("decided"),
        "decided_by": data.get("decided_by"),
        "decision_card": data.get("decision_card"),
        "decision": data.get("decision"),
        "reason": data.get("reason"),
        "contract_ref": data.get("contract_ref"),
        "rows": rows,
        "unmeasured": unmeasured,
    }


# --- the AWS control-plane panel ---------------------------------------------
#
# WHY THIS PANEL EXISTS. MEASURED 2026-09-19 (cards t_6dc8c120 + t_31c93028): AWS account
# 912632857388 has a real multi-region CloudTrail and GuardDuty detectors in six regions, and this
# dashboard rendered NONE of it — the string `aws` did not occur in this module or in suite.js. A
# surface a reader would expect to be covered and cannot see is one half of the defect class this
# suite exists to remove; a FALSE ZERO is the other half. So:
#
#   * the panel's content is decided by a LIVE PROBE, never by what the registry DECLARES. The
#     registry row is carried under `declared` and labelled as the claim it is — a panel that
#     renders configuration as measurement is the thing this card exists to prevent;
#   * every surface is in ONE of the states in ``AWS_STATE_LABELS``, and a bare ``0`` is never one
#     of them. ``enabled_producing`` requires BOTH the control-plane object (a trail, a detector)
#     AND rows in the lake for the producer that carries it: presence and ingestion are DIFFERENT
#     facts (no source reads the trail's S3 bucket) and the panel must not conflate them;
#   * the lake side is read from the lake's OWN parquet partitions (producer column), never inferred
#     from the probe.
#
# The probe is the call surface ``aws_audit.py`` makes
# (``~/hermes-outbox/2026-09-18-aws-telemetry-t_6dc8c120/``), under the registry's read-only
# identity. It runs in a CHILD interpreter (boto3 is not importable in every caller), is bounded by
# a timeout, and is cached with an explicit age: a dashboard request renders
# ``UNMEASURABLE: <reason>`` rather than blocking the page on AWS latency.
#
# ⛔ NOTHING HERE ENABLES, CREATES OR MODIFIES AN AWS RESOURCE. The identity is read-only and stays
# read-only: the probe calls Describe*/List*/Get* and nothing else.
#
# ⛔ /meta DOES NOT RUN THIS PROBE. A page-load read that waits on ~35 AWS calls is exactly the
# "blocking the page" the card forbids; /meta names the panel and its call surface instead. The
# probe runs when the AWS panel itself is opened, and its result is cached for PSEC_AWS_PROBE_TTL.

# ⛔ A CENSUS, NOT A SPOT FIX: every state the state machine can put in an AWS `state` field has an
# entry here. A missing key does not fail loudly — it falls through `AWS_STATE_LABELS.get(state, state)`
# below and `state_label || state` in the page, so the operator reads a raw machine token.
# `present_no_ingest` was emitted by TWO branches (the per-account machine in `_aws_account_entry` and
# the per-scope machine in `_aws_panel`) with no entry here; `tests/test-plugin-api.py` now censuses
# this dict against every token those machines can emit.
AWS_STATE_LABELS = {
    "enabled_producing": "enabled and producing",
    "enabled_silent": "enabled but silent",
    "no_source": "present — no source ingests it (presence is not ingestion)",
    "present_no_ingest": "present — no source ingests it (presence is not ingestion)",
    "configured": "configured (measured by the probe; no lake source)",
    "absent": "ABSENT — a stated absence, not a zero",
    "unmeasurable": "UNMEASURABLE",
}

# The producer that carries CloudTrail into the lake, and the stream it lands on. MEASURED
# 2026-09-19 in the lake: platform=onestack/source=cloud_audit, producer=aws-cloudtrail.
AWS_CLOUDTRAIL_PRODUCER = "aws-cloudtrail"
AWS_CLOUDTRAIL_SOURCE = "cloud_audit"

AWS_PY_CANDIDATES = tuple(
    p for p in (sys.executable, "/home/hermes/.hermes/hermes-agent/venv/bin/python", "/usr/bin/python3") if p
)
_AWS_PY: list[Optional[str]] = []          # memo of the first interpreter that can import boto3

AWS_PROBE_TTL_S = _clamp_int(os.environ.get("PSEC_AWS_PROBE_TTL"), 300, 0, 86_400)
AWS_PROBE_TIMEOUT_S = _clamp_int(os.environ.get("PSEC_AWS_PROBE_TIMEOUT"), 90, 5, 600)
AWS_PROBE_FAIL_TTL_S = 60

_AWS_CACHE: dict[str, dict[str, Any]] = {}

# The read-only identity's environment names. NOT `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`:
# MEASURED, those hold hermes-monitoring, which is DENIED cloudtrail:LookupEvents.
AWS_CRED_NAMES = ("AWS_PROTECTION_AUDIT_ACCESS_KEY_ID", "AWS_PROTECTION_AUDIT_SECRET_ACCESS_KEY",
                  "AWS_PROTECTION_AUDIT_REGION")

# The probe. Reads its credential from STDIN (never argv: argv is world-readable in `ps`), and
# prints ONE json object on stdout. Every call is individually guarded so a refusal in one region
# cannot take the whole read down — and the failure MODE is preserved (an `AccessDenied`, a
# `not subscribed`, a `NoSuchEntity` and a transport error are four different facts).
_AWS_PROBE = r'''
import json, sys
req = json.load(sys.stdin)
import boto3
from botocore.config import Config

cfg = Config(retries={"max_attempts": 2, "mode": "standard"}, connect_timeout=5, read_timeout=15)
AK, SK = req["access_key_id"], req["secret_access_key"]
R0 = req.get("region") or "us-east-1"

def client(svc, region):
    return boto3.client(svc, aws_access_key_id=AK, aws_secret_access_key=SK,
                        region_name=region, config=cfg)

def err(e):
    s = str(e)
    return {"error": type(e).__name__, "reason": (s.splitlines()[0] if s.splitlines() else type(e).__name__)[:300]}

out = {"identity": None, "region": R0, "regions": [], "regions_error": None,
       "cloudtrail": {"regions": {}, "error": None}, "guardduty": {"regions": {}, "error": None},
       "securityhub": {"status": None, "reason": None}, "password_policy": {"status": None, "reason": None},
       "iam_users": None}

try:
    ident = client("sts", R0).get_caller_identity()
    out["identity"] = {"account": ident.get("Account"), "arn": ident.get("Arn")}
except Exception as e:
    out["identity"] = err(e)

try:
    rs = client("ec2", R0).describe_regions(AllRegions=True).get("Regions", [])
    out["regions"] = sorted(r["RegionName"] for r in rs
                            if r.get("OptInStatus") in ("opt-in-not-required", "opted-in"))
except Exception as e:
    out["regions_error"] = err(e)

for r in out["regions"]:
    try:
        tl = client("cloudtrail", r).describe_trails(includeShadowTrails=True).get("trailList", [])
        rows = []
        for x in tl:
            row = {k: x.get(k) for k in ("Name", "HomeRegion", "IsMultiRegionTrail",
                                         "LogFileValidationEnabled", "S3BucketName")}
            # IsLogging is NOT on DescribeTrails' response -- aws_audit.py read the wrong key for it.
            # GetTrailStatus is the call that answers it, so the panel measures it instead of
            # repeating a mislabelled field.
            row["IsLogging"] = None
            row["IsLogging_error"] = None
            try:
                row["IsLogging"] = bool(client("cloudtrail", r).get_trail_status(Name=x.get("Name")).get("IsLogging"))
            except Exception as e:
                row["IsLogging_error"] = err(e)
            rows.append(row)
        out["cloudtrail"]["regions"][r] = rows
    except Exception as e:
        out["cloudtrail"]["regions"][r] = err(e)
    try:
        out["guardduty"]["regions"][r] = client("guardduty", r).list_detectors().get("DetectorIds", [])
    except Exception as e:
        out["guardduty"]["regions"][r] = err(e)

try:
    h = client("securityhub", R0).describe_hub()
    out["securityhub"] = {"status": "subscribed", "reason": None, "hub_arn": h.get("HubArn")}
except Exception as e:
    msg = (str(e).splitlines()[0] if str(e).splitlines() else str(e))[:300]
    bad = err(e)
    if "not subscribed" in str(e).lower():
        out["securityhub"] = {"status": "not_subscribed", "reason": msg}
    else:
        out["securityhub"] = {"status": "refused", "reason": msg, "error": bad["error"]}

try:
    out["password_policy"] = {"status": "present",
                              "policy": client("iam", R0).get_account_password_policy().get("PasswordPolicy")}
except Exception as e:
    msg = (str(e).splitlines()[0] if str(e).splitlines() else str(e))[:300]
    if type(e).__name__ == "NoSuchEntityException" or "NoSuchEntity" in str(e):
        out["password_policy"] = {"status": "absent", "reason": msg}
    else:
        out["password_policy"] = {"status": "refused", "reason": msg, "error": type(e).__name__}

try:
    out["iam_users"] = len(client("iam", R0).list_users().get("Users", []))
except Exception:
    out["iam_users"] = None

print(json.dumps(out))
'''

# The lake side: ONE grouped read of the partition's own `producer` column.
_AWS_LAKE_PROBE = r'''
import json, sys
import duckdb
req = json.load(sys.stdin)
con = duckdb.connect()
out = {}
for p in req["probes"]:
    try:
        rows = con.execute(
            "select producer, count(*) as n, max(event_time) as mx "
            "from read_parquet('" + p["glob"] + "', hive_partitioning=true) group by 1"
        ).fetchall()
        hit = [r for r in rows if r[0] == p["producer"]]
        out[p["key"]] = {"ok": True, "rows": int(hit[0][1]) if hit else 0,
                         "last_event": str(hit[0][2]) if hit and hit[0][2] is not None else None,
                         "producers": sorted(str(r[0]) for r in rows)}
    except Exception as exc:
        out[p["key"]] = {"ok": False, "error": type(exc).__name__ + ": " + (
            str(exc).splitlines()[0] if str(exc).splitlines() else "")}
print(json.dumps(out))
'''


def _aws_python() -> Optional[str]:
    """The first candidate interpreter that can ``import boto3`` (memoised, including the negative)."""
    if _AWS_PY:
        return _AWS_PY[0]
    for cand in AWS_PY_CANDIDATES:
        if not Path(cand).is_file():
            continue
        try:
            r = subprocess.run([cand, "-c", "import boto3"], capture_output=True, text=True,
                               timeout=30, check=False)
        except Exception:  # noqa: BLE001
            continue
        if r.returncode == 0:
            _AWS_PY.append(cand)
            return cand
    _AWS_PY.append(None)
    return None


def _env_value(name: str) -> Optional[str]:
    """One variable from the environment, else from THIS hermes home's own ``.env``.

    Cron does not inherit ``.env``, so a reader must be able to open it. It is read from
    ``_hermes_home()`` and never from a hardcoded path, so a test's temp home can never silently
    read the live estate's secrets.
    """
    v = os.environ.get(name)
    if v and v.strip():
        return v.strip()
    try:
        for line in (_hermes_home() / ".env").read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, val = line.partition("=")
            if k.strip() == name:
                val = val.strip().strip('"').strip("'")
                return val or None
    except Exception:  # noqa: BLE001
        return None
    return None


def _aws_credential(platform: str, cloud: dict[str, Any]) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    """The read-only identity, resolved the way the registry says it is resolved. Never logged.

    Two places, in order: the secret store the registry names (``.secrets/<platform>/aws/estate.json``
    — the same file the CloudTrail connector resolves ``secret://aws/estate`` to), then the
    ``AWS_PROTECTION_AUDIT_*`` names in this home's ``.env``. NEITHER is a config claim about the
    account: the credential is only the identity the probe signs with.
    """
    store = _hermes_home() / ".secrets" / str(platform) / "aws" / "estate.json"
    data, err = _read_json(store)
    if isinstance(data, dict) and data.get("access_key_id") and data.get("secret_access_key"):
        return ({"access_key_id": data["access_key_id"],
                 "secret_access_key": data["secret_access_key"],
                 "region": data.get("region") or "us-east-1",
                 "source": str(store)}, None)
    tried = [f"{store} " + (f"unreadable ({err})" if err else "absent or incomplete")]
    vals = {n: _env_value(n) for n in AWS_CRED_NAMES}
    if vals[AWS_CRED_NAMES[0]] and vals[AWS_CRED_NAMES[1]]:
        return ({"access_key_id": vals[AWS_CRED_NAMES[0]],
                 "secret_access_key": vals[AWS_CRED_NAMES[1]],
                 "region": vals[AWS_CRED_NAMES[2]] or "us-east-1",
                 "source": "env:" + AWS_CRED_NAMES[0]}, None)
    tried.append(f"{_hermes_home() / '.env'} has no complete {AWS_CRED_NAMES[0]} / "
                 f"{AWS_CRED_NAMES[1]} pair")
    return None, ("no read-only AWS credential: " + "; ".join(tried)
                  + " — the AWS control plane is UNMEASURED, not healthy")


def _aws_reason(val: Any) -> str:
    if isinstance(val, dict):
        return str(val.get("reason") or val.get("error") or "no reason given")
    return str(val)


def _aws_classify_error(text: str) -> tuple[str, str]:
    """A SIGNING error is not a permission error.

    MEASURED 2026-09-18 (card t_7c560aaf): GuardDuty is REST-JSON (``GET /detector``); the
    JSON-1.1 ``x-amz-target`` form answers *Unable to determine service/operation name to be
    authorized*, which is the signer failing to find the operation — NOT a refusal by IAM. Reporting
    it as a permission error would file a false finding against the identity.
    """
    t = (text or "").lower()
    if "unable to determine service/operation name to be authorized" in t:
        return "signing_error", ("SIGNING error — the request form does not identify the operation; "
                                 "this is NOT a permission error and NOT a coverage gap")
    if "accessdenied" in t or "not authorized" in t or "unauthorized" in t or "implicit deny" in t:
        return "refused", "permission refused by the identity"
    if "not subscribed" in t:
        return "not_subscribed", "the account is not subscribed"
    if "nosuchentity" in t:
        return "absent", "the object does not exist (a stated absence)"
    return "error", "the call failed"


def _aws_probe_live(cred: dict[str, Any], timeout: int) -> dict[str, Any]:
    """Run the probe in a child interpreter. Raises RuntimeError with a NAMED reason on failure."""
    py = _aws_python()
    if not py:
        raise RuntimeError("no interpreter with boto3 (tried " + ", ".join(AWS_PY_CANDIDATES) + ")")
    payload = {"access_key_id": cred["access_key_id"], "secret_access_key": cred["secret_access_key"],
               "region": cred.get("region") or "us-east-1"}
    try:
        proc = subprocess.run([py, "-c", _AWS_PROBE], input=json.dumps(payload),
                              capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"the probe did not finish within {timeout}s")
    if proc.returncode != 0:
        raise RuntimeError(f"the probe exited {proc.returncode}: {(proc.stderr or '').strip()[:300]}")
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"the probe output was unparseable: {exc}")


def _aws_probe_cached(key: str, cred: dict[str, Any]) -> tuple[Optional[dict], Optional[str], dict]:
    """The probe's result and its AGE. A failure is cached briefly too, so a cold AWS does not make
    every page load pay the timeout."""
    now = _now()
    hit = _AWS_CACHE.get(key)
    if hit:
        age = now - int(hit["at"])
        ttl = int(hit.get("ttl") or AWS_PROBE_TTL_S)
        if age <= ttl:
            return (hit.get("data"), hit.get("error"),
                    {"cached": True, "age_seconds": age, "ttl_seconds": ttl,
                     "measured_at": _iso(hit["at"])})
    t0 = time.time()
    data, err = None, None
    try:
        data = _aws_probe_live(cred, AWS_PROBE_TIMEOUT_S)
    except Exception as exc:  # noqa: BLE001
        err = f"{type(exc).__name__}: {exc}"
    ttl = AWS_PROBE_TTL_S if err is None else min(AWS_PROBE_FAIL_TTL_S, AWS_PROBE_TTL_S or AWS_PROBE_FAIL_TTL_S)
    _AWS_CACHE[key] = {"at": now, "ttl": ttl, "data": data, "error": err}
    return (data, err, {"cached": False, "age_seconds": 0, "ttl_seconds": ttl,
                        "duration_s": round(time.time() - t0, 1), "measured_at": _iso(now)})


def _aws_lake_counts(lake_root: Optional[str], platform: str, source: str,
                     producer: str) -> dict[str, Any]:
    """Rows in the lake for ONE producer, read from the partition itself. Never inferred.

    ``rows`` is ``None`` when the lake could not be read — never ``0``. The distinction is the whole
    point: ``0`` means "the source ran and landed nothing" (enabled but silent); ``None`` means
    "I could not measure it", which is a third state and must not be rendered as the second.
    """
    out: dict[str, Any] = {"producer": producer, "source": source, "root": lake_root,
                           "rows": None, "last_event": None, "ok": False, "reason": None}
    if not lake_root:
        out["reason"] = "no lake_root resolved (psec-sources.json)"
        return out
    py = _lake_python()
    if not py:
        out["reason"] = "no lake interpreter (duckdb lives in /home/hermes/.lakevenv)"
        return out
    if not _SAFE_IDENT.match(str(platform)) or not _SAFE_IDENT.match(str(source)):
        out["reason"] = f"refused: unsafe partition name platform={platform!r} source={source!r}"
        return out
    glob = f"{lake_root.rstrip('/')}/platform={platform}/source={source}/**/*.parquet"
    if not _SAFE_GLOB.match(glob):
        out["reason"] = f"refused: unsafe glob {glob}"
        return out
    try:
        proc = subprocess.run(
            [py, "-c", _AWS_LAKE_PROBE],
            input=json.dumps({"probes": [{"key": "k", "glob": glob, "producer": producer}]}),
            capture_output=True, text=True, timeout=120, check=False)
    except Exception as exc:  # noqa: BLE001
        out["reason"] = f"lake probe failed to run: {type(exc).__name__}: {exc}"
        return out
    if proc.returncode != 0:
        out["reason"] = f"lake probe exited {proc.returncode}: {(proc.stderr or '').strip()[:200]}"
        return out
    try:
        res = json.loads(proc.stdout.strip().splitlines()[-1])["k"]
    except Exception as exc:  # noqa: BLE001
        out["reason"] = f"lake probe output unparseable: {exc}"
        return out
    if not res.get("ok"):
        out["reason"] = str(res.get("error"))
        return out
    out["ok"] = True
    out["rows"] = res.get("rows")
    out["last_event"] = res.get("last_event")
    out["producers_seen"] = res.get("producers")
    return out


def _aws_row(sid: str, surface: str, calls: list[str], state: str, *, present: Optional[bool],
             finding: str, regions_present: Optional[list[str]] = None,
             regions_empty: Optional[list[str]] = None, regions_error: Optional[dict] = None,
             lake: Optional[dict[str, Any]] = None, lake_reason: Optional[str] = None,
             details: Optional[dict[str, Any]] = None,
             unmeasured: Optional[list[str]] = None) -> dict[str, Any]:
    """One control-plane surface, in ONE of ``AWS_STATE_LABELS``. There is no path that returns a
    bare count here: ``lake_rows`` is ``None`` when it was not measured, and the state is what the
    page renders."""
    return {
        "id": sid,
        "surface": surface,
        "probe_calls": list(calls),
        "state": state,
        "state_label": AWS_STATE_LABELS.get(state, state),
        "present": present,
        "regions_present": regions_present,
        "regions_empty": regions_empty,
        "regions_error": regions_error or None,
        "lake_producer": (lake or {}).get("producer"),
        "lake_source": (lake or {}).get("source"),
        "lake_rows": (lake or {}).get("rows"),
        "lake_last_event": (lake or {}).get("last_event"),
        "lake_reason": (lake_reason if lake_reason is not None else (lake or {}).get("reason")),
        "finding": finding,
        "details": details or {},
        "unmeasured": list(unmeasured or []),
    }


def _aws_regions_split(block: Any) -> tuple[list[str], list[str], dict[str, str]]:
    """A probe block's regions split into present / empty / errored — from the response SHAPE, so a
    region that answered with an error can never be counted as an empty one."""
    regions = (block or {}).get("regions") or {}
    present, empty, errors = [], [], {}
    for r in sorted(regions):
        val = regions[r]
        if isinstance(val, list):
            (present if val else empty).append(r)
        else:
            errors[r] = _aws_reason(val)
    return present, empty, errors


def _aws_cloudtrail_row(probe: dict[str, Any], lake: dict[str, Any]) -> dict[str, Any]:
    """CloudTrail: the control-plane record, and — separately — whether it is INGESTED."""
    calls = ["cloudtrail:DescribeTrails(includeShadowTrails=True)", "cloudtrail:GetTrailStatus"]
    present_r, empty_r, err_r = _aws_regions_split(probe.get("cloudtrail"))
    probed = len((probe.get("cloudtrail") or {}).get("regions") or {})
    trails = [{"region": r, **x} for r, v in sorted((probe.get("cloudtrail") or {}).get("regions", {}).items())
              if isinstance(v, list) for x in v]
    unmeasured: list[str] = []
    if err_r:
        unmeasured.append(f"cloudtrail: {len(err_r)} of {probed} probed region(s) answered with an "
                          "error: " + "; ".join(f"{k}: {v}" for k, v in err_r.items()))
    details = {"trails": trails, "trail_s3_ingest":
               "no source reads the trail's S3 bucket (a missing SOURCE, filed separately); the lake "
               "rows for producer=aws-cloudtrail come from cloudtrail:LookupEvents (event history), "
               "NOT from the trail"}
    if not probed:
        why = _aws_reason(probe.get("regions_error")) if probe.get("regions_error") else "the probe listed no region"
        return _aws_row("cloudtrail", "CloudTrail trails — the control-plane record", calls,
                        "unmeasurable", present=None,
                        finding=f"the region list could not be read: {why} — UNMEASURABLE, not an empty estate",
                        unmeasured=unmeasured, details=details)
    if not present_r and len(err_r) == probed:
        return _aws_row("cloudtrail", "CloudTrail trails — the control-plane record", calls,
                        "unmeasurable", present=None, regions_empty=empty_r, regions_error=err_r,
                        finding="every probed region answered with an error: "
                                + "; ".join(f"{k}: {v}" for k, v in err_r.items()),
                        unmeasured=unmeasured, details=details)
    if not present_r:
        state = "absent"
        finding = (f"no trail in any of the {probed} probed region(s) — an absent control-plane "
                   "record, stated as absent and NOT rendered as a zero")
    elif not lake.get("ok"):
        state = "unmeasurable"
        finding = (f"trail present in {len(present_r)} region(s), but the lake rows for "
                   f"producer={AWS_CLOUDTRAIL_PRODUCER} could not be read ({lake.get('reason')}) — "
                   "presence alone is NOT the producing state, so this is UNMEASURABLE")
    elif (lake.get("rows") or 0) > 0:
        state = "enabled_producing"
        finding = (f"trail(s) {', '.join(sorted({str(t.get('Name')) for t in trails}))} present; "
                   f"{lake['rows']:,} row(s) in {lake['source']} for "
                   f"producer={AWS_CLOUDTRAIL_PRODUCER} — ingested via cloudtrail:LookupEvents, "
                   "NOT from the trail's S3 bucket")
    else:
        state = "enabled_silent"
        finding = ("the trail is present and its producer exists, but 0 rows have landed for "
                   f"producer={AWS_CLOUDTRAIL_PRODUCER} — ENABLED BUT SILENT, a distinct finding "
                   "and not a zero")
    return _aws_row("cloudtrail", "CloudTrail trails — the control-plane record", calls, state,
                    present=True, regions_present=present_r, regions_empty=empty_r,
                    regions_error=err_r, lake=lake, finding=finding, unmeasured=unmeasured,
                    details=details)


def _aws_guardduty_row(probe: dict[str, Any]) -> dict[str, Any]:
    """GuardDuty detectors — and the asymmetry between regions, which is a finding, not a bug."""
    calls = ["guardduty:ListDetectors"]
    present_r, empty_r, err_r = _aws_regions_split(probe.get("guardduty"))
    probed = len((probe.get("guardduty") or {}).get("regions") or {})
    unmeasured: list[str] = []
    if err_r:
        signing = [k for k, v in err_r.items() if _aws_classify_error(v)[0] == "signing_error"]
        note = (f"guardduty: {len(err_r)} of {probed} region(s) errored: "
                + "; ".join(f"{k}: {v}" for k, v in err_r.items()))
        if signing:
            note += (" — classifier: SIGNING error under the JSON-1.1 x-amz-target form; with the "
                     "REST-JSON (GET /detector) form boto3 uses here this must NOT be read as a "
                     "permission refusal")
        unmeasured.append(note)
    lake_reason = ("no producer carries GuardDuty findings into this lake — its detectors are "
                   "measured by the probe only; presence is not ingestion")
    details = {"detectors": {r: v for r, v in ((probe.get("guardduty") or {}).get("regions") or {}).items()
                             if isinstance(v, list)}}
    if not probed:
        why = _aws_reason(probe.get("regions_error")) if probe.get("regions_error") else "the probe listed no region"
        return _aws_row("guardduty", "GuardDuty detectors", calls, "unmeasurable", present=None,
                        finding=f"the region list could not be read: {why}", lake_reason=lake_reason,
                        unmeasured=unmeasured, details=details)
    if not present_r and len(err_r) == probed:
        return _aws_row("guardduty", "GuardDuty detectors", calls, "unmeasurable", present=None,
                        regions_empty=empty_r, regions_error=err_r,
                        finding="every probed region answered with an error: "
                                + "; ".join(f"{k}: {v}" for k, v in err_r.items()),
                        lake_reason=lake_reason, unmeasured=unmeasured, details=details)
    if present_r:
        state = "no_source"
        finding = (f"detector(s) in {len(present_r)} region(s) ({', '.join(present_r)}); EMPTY in "
                   f"{len(empty_r)} ({', '.join(empty_r) or 'none'}) — that asymmetry is a finding, "
                   "not a probe bug. No producer ingests GuardDuty findings, so presence is NOT "
                   "ingestion: a missing SOURCE, stated as such.")
    else:
        state = "absent"
        finding = (f"no detector in any of the {probed} probed region(s) — stated as absent, "
                   "never as a zero")
    return _aws_row("guardduty", "GuardDuty detectors", calls, state, present=bool(present_r),
                    regions_present=present_r, regions_empty=empty_r, regions_error=err_r,
                    finding=finding, lake_reason=lake_reason, unmeasured=unmeasured, details=details)


def _aws_securityhub_row(probe: dict[str, Any]) -> dict[str, Any]:
    calls = ["securityhub:DescribeHub"]
    sh = probe.get("securityhub") or {}
    status = sh.get("status")
    lake_reason = ("no producer carries Security Hub findings into this lake — a missing SOURCE, "
                   "stated as such")
    if status == "subscribed":
        return _aws_row("securityhub", "Security Hub", calls, "no_source", present=True,
                        finding=f"subscribed ({sh.get('hub_arn') or 'hub arn not returned'}); nothing "
                                "ingests its findings into this lake",
                        lake_reason=lake_reason)
    if status == "not_subscribed":
        return _aws_row("securityhub", "Security Hub", calls, "absent", present=False,
                        finding="DescribeHub: the account is NOT subscribed to AWS Security Hub — a "
                                "stated ABSENCE, not a zero",
                        lake_reason=lake_reason)
    kind, why = _aws_classify_error(sh.get("reason") or "")
    return _aws_row("securityhub", "Security Hub", calls, "unmeasurable", present=None,
                    finding=f"DescribeHub did not answer ({kind}): {why} — {sh.get('reason')}",
                    lake_reason=lake_reason)


def _aws_password_policy_row(probe: dict[str, Any]) -> dict[str, Any]:
    calls = ["iam:GetAccountPasswordPolicy"]
    pol = probe.get("password_policy") or {}
    users = probe.get("iam_users")
    over = f" over {users} IAM user(s)" if isinstance(users, int) else ""
    lake_reason = "the account password policy is an IAM setting; no lake source exists for it"
    status = pol.get("status")
    if status == "present":
        p = pol.get("policy") or {}
        return _aws_row("password_policy", "IAM account password policy", calls, "configured",
                        present=True,
                        finding=f"an account password policy IS set (MinimumPasswordLength="
                                f"{p.get('MinimumPasswordLength')}, ReusePreventionCount="
                                f"{p.get('PasswordReusePrevention')})",
                        lake_reason=lake_reason, details={"policy": p})
    if status == "absent":
        return _aws_row("password_policy", "IAM account password policy", calls, "absent",
                        present=False,
                        finding=f"iam:GetAccountPasswordPolicy -> NoSuchEntity{over}: NO account "
                                "password policy exists — a stated ABSENCE, not a zero",
                        lake_reason=lake_reason)
    kind, why = _aws_classify_error(pol.get("reason") or "")
    return _aws_row("password_policy", "IAM account password policy", calls, "unmeasurable",
                    present=None,
                    finding=f"GetAccountPasswordPolicy did not answer ({kind}): {why} — "
                            f"{pol.get('reason')}", lake_reason=lake_reason)


def _aws_account_entry(t: dict[str, Any], cloud: dict[str, Any],
                       lake_root: Optional[str], lake: dict[str, Any]) -> dict[str, Any]:
    """One AWS account: the live probe, the lake, and the four surfaces it answers for."""
    platform = str(t["platform"])
    account = cloud.get("account")
    declared = {
        # ⛔ A CLAIM, LABELLED AS ONE. Rendered beside the measurement, never as it.
        "cloud": cloud.get("cloud"), "account": account,
        "account_verified": bool(cloud.get("account_verified")),
        "credential_ref": cloud.get("credential_ref"),
        "sources": list(cloud.get("sources") or []),
        "access": cloud.get("access"),
        "note": "what the REGISTRY declares — a CLAIM, never this panel's answer: the content above "
                "comes from the live probe",
    }
    cred, cred_err = _aws_credential(platform, cloud)
    probe_meta: dict[str, Any] = {"cached": False}
    data: Optional[dict] = None
    if cred is None:
        probe = {"status": "unmeasurable", "reason": cred_err, "identity": None}
    else:
        data, err, probe_meta = _aws_probe_cached(f"{platform}|{account}", cred)
        if err is not None:
            probe = {"status": "unmeasurable", "reason": err, "identity": None}
        elif not isinstance(data, dict):
            probe = {"status": "unmeasurable", "reason": "the probe returned no result", "identity": None}
        elif isinstance(data.get("identity"), dict) and data["identity"].get("error"):
            probe = {"status": "unmeasurable",
                     "reason": "sts:GetCallerIdentity was refused ("
                               + _aws_reason(data["identity"])
                               + ") — the probe could not establish WHICH account it is, so nothing "
                                 "about this account is measured",
                     "identity": None}
        else:
            probe = {"status": "ok", "reason": None, "identity": data.get("identity")}

    if probe["status"] != "ok":
        reason = probe["reason"] or "the probe could not run"
        rows = [
            _aws_row("cloudtrail", "CloudTrail trails — the control-plane record",
                     ["cloudtrail:DescribeTrails(includeShadowTrails=True)", "cloudtrail:GetTrailStatus"],
                     "unmeasurable", present=None, finding="UNMEASURABLE: " + reason),
            _aws_row("guardduty", "GuardDuty detectors", ["guardduty:ListDetectors"], "unmeasurable",
                     present=None, finding="UNMEASURABLE: " + reason),
            _aws_row("securityhub", "Security Hub", ["securityhub:DescribeHub"], "unmeasurable",
                     present=None, finding="UNMEASURABLE: " + reason),
            _aws_row("password_policy", "IAM account password policy", ["iam:GetAccountPasswordPolicy"],
                     "unmeasurable", present=None, finding="UNMEASURABLE: " + reason),
        ]
    else:
        pd: dict[str, Any] = data or {}
        rows = [
            _aws_cloudtrail_row(pd, lake),
            _aws_guardduty_row(pd),
            _aws_securityhub_row(pd),
            _aws_password_policy_row(pd),
        ]

    states = [r["state"] for r in rows]
    if probe["status"] != "ok":
        state, reason = "unmeasurable", probe["reason"]
    elif "enabled_producing" in states:
        state, reason = "enabled_producing", None
    elif "enabled_silent" in states:
        state, reason = "enabled_silent", None
    elif all(s == "unmeasurable" for s in states):
        state, reason = "unmeasurable", "every surface was unmeasurable"
    elif any(s in ("no_source", "configured") for s in states):
        state, reason = "present_no_ingest", None
    else:
        state, reason = "absent", None

    unmeasured = [u for r in rows for u in r["unmeasured"]]
    if probe["status"] == "ok" and isinstance(data, dict) and not data.get("regions"):
        unmeasured.append("aws: the probe listed no enabled region — every regional surface is "
                          "unmeasured, not empty")
    if lake_root is None:
        unmeasured.append("aws: no lake_root resolved, so the ingestion half of the control-plane "
                          "surfaces is unmeasured (presence alone is not ingestion)")
    return {
        "platform": platform,
        "declared": declared,
        "identity": probe.get("identity"),
        "probe": {
            "status": probe["status"], "reason": probe["reason"],
            "calls": ["cloudtrail:DescribeTrails(includeShadowTrails=True)", "cloudtrail:GetTrailStatus",
                      "guardduty:ListDetectors", "securityhub:DescribeHub",
                      "iam:GetAccountPasswordPolicy"],
            "credential_source": None if cred is None else cred.get("source"),
            "cache": probe_meta,
            "timeout_s": AWS_PROBE_TIMEOUT_S, "ttl_s": AWS_PROBE_TTL_S,
            "regions_probed": (data or {}).get("regions") or [],
            "iam_users": (data or {}).get("iam_users"),
        },
        "lake": {"root": lake_root, "producer": lake.get("producer"), "source": lake.get("source"),
                 "rows": lake.get("rows"), "last_event": lake.get("last_event"),
                 "ok": lake.get("ok"), "reason": lake.get("reason")},
        "state": state, "state_label": AWS_STATE_LABELS.get(state, state), "reason": reason,
        "counts": {k: states.count(k) for k in AWS_STATE_LABELS if states.count(k)},
        "surfaces": rows,
        "unmeasured": unmeasured,
    }


def _aws_panel(chosen: str, reg: dict[str, Any]) -> dict[str, Any]:
    """Every AWS account the chosen scope declares, each probed live and stated in three states."""
    tenants = reg["tenants"] if chosen == "all" else [t for t in reg["tenants"] if t["platform"] == chosen]
    clouds = [(t, c) for t in tenants for c in (t["clouds"] or [])
              if str(c.get("cloud") or "").lower() == "aws"]
    as_of = _as_of()
    if not clouds:
        return {
            "as_of": as_of, "tenant": chosen, "accounts": [], "count": 0,
            "state": "absent", "state_label": AWS_STATE_LABELS["absent"],
            "reason": f"the registry declares NO `cloud: aws` for tenant {chosen!r} — a stated "
                      "absence, not a zero",
            "probe_calls": [], "unmeasured": [], "counts": {},
        }
    lake_root = _lake_config()["lake_root"]
    # ONE lake read per (platform, producer), shared across accounts of the same tenant: the
    # partition is the tenant's, not the credential's.
    lake_cache: dict[str, dict[str, Any]] = {}
    accounts = []
    for t, c in clouds:
        key = str(t["platform"])
        if key not in lake_cache:
            lake_cache[key] = _aws_lake_counts(lake_root, key, AWS_CLOUDTRAIL_SOURCE,
                                               AWS_CLOUDTRAIL_PRODUCER)
        accounts.append(_aws_account_entry(t, c, lake_root, lake_cache[key]))
    states = [a["state"] for a in accounts]
    if "unmeasurable" in states and all(s == "unmeasurable" for s in states):
        state, reason = "unmeasurable", accounts[0]["reason"]
    elif "enabled_producing" in states:
        state, reason = "enabled_producing", None
    elif "enabled_silent" in states:
        state, reason = "enabled_silent", None
    elif "unmeasurable" in states:
        state, reason = "unmeasurable", "at least one AWS account could not be measured"
    elif "present_no_ingest" in states:
        state, reason = "present_no_ingest", None
    else:
        state, reason = "absent", None
    return {
        "as_of": as_of, "tenant": chosen, "accounts": accounts, "count": len(accounts),
        "state": state, "state_label": AWS_STATE_LABELS.get(state, state), "reason": reason,
        "probe_calls": ["cloudtrail:DescribeTrails(includeShadowTrails=True)", "cloudtrail:GetTrailStatus",
                        "guardduty:ListDetectors", "securityhub:DescribeHub",
                        "iam:GetAccountPasswordPolicy"],
        "lake_root": lake_root,
        "counts": {k: states.count(k) for k in AWS_STATE_LABELS if states.count(k)},
        "unmeasured": [u for a in accounts for u in a["unmeasured"]],
    }


@router.get("/capability")
def capability():
    """The capability floor: what this suite does, and explicitly what it does NOT do.

    Estate-wide on purpose — a scope decision is not a tenant's, so this route takes no tenant and
    the panel does not re-scope. ``out_of_scope_count`` is the number to read first: those are the
    capabilities this dashboard must never be taken to imply.
    """
    cap = _capability()
    rows = cap["rows"]
    return {
        "as_of": _as_of(),
        "statement_version": cap["statement_version"],
        "decided": cap["decided"],
        "decided_by": cap["decided_by"],
        "decision_card": cap["decision_card"],
        "decision": cap["decision"],
        "reason": cap["reason"],
        "contract_ref": cap["contract_ref"],
        "rows": rows,
        "count": len(rows),
        "out_of_scope_count": sum(1 for r in rows if r["state"] == "out_of_scope"),
        "partial_count": sum(1 for r in rows if r["state"] == "partial"),
        "source": cap["path"],
        "provenance": cap["provenance"],
        "unmeasured": cap["unmeasured"],
    }


@router.get("/aws")
def aws(tenant: Optional[str] = None):
    """The AWS control-plane panel — a LIVE probe in three states, never a config claim, never a zero.

    Tenant is required and has no default, like every other per-tenant read. The probe is bounded by
    ``PSEC_AWS_PROBE_TIMEOUT`` and cached for ``PSEC_AWS_PROBE_TTL``; a refusal or a timeout renders
    ``UNMEASURABLE: <reason>``, never an empty panel and never a zero.
    """
    reg = _load_registry()
    chosen = _tenant_or_refuse(tenant, reg["tenants"])
    return _aws_panel(chosen, reg)


@router.get("/meta")
def meta():
    """What every other route is reading — the provenance panel, and the honest source census."""
    reg = _load_registry()
    det = _detections()
    lake = _lake_config()
    post = _posture()
    cap = _capability()
    return {
        "as_of": _as_of(),
        "registry": {"root": reg["root"], "provenance": reg["provenance"],
                     "tenants": len(reg["tenants"]), "errors": reg["errors"]},
        "detections": {"path": det["path"], "provenance": det["provenance"],
                       "rules": det["rules_total"], "rules_total": det["rules_total"],
                       "catalogs_rules_total": det["catalogs_rules_total"],
                       "catalogs": [_catalog_summary(c) for c in det["catalogs"]],
                       "shadowed": det["shadowed"]},
        "lake": {"root": lake["lake_root"], "provenance": lake["provenance"],
                 "feeds": len(lake["feeds"])},
        "retirement": {"path": post["path"], "provenance": post["provenance"]},
        # The AWS panel's provenance, WITHOUT running it: /meta is fetched on every page load and a
        # ~35-call AWS probe behind it is exactly the "blocking the page" this panel must avoid. The
        # live probe runs on /aws itself, and its result is cached for PSEC_AWS_PROBE_TTL.
        "aws": {"endpoint": "/aws?tenant=<slug>", "probe": "live (read-only)",
                "calls": ["cloudtrail:DescribeTrails(includeShadowTrails=True)",
                          "cloudtrail:GetTrailStatus", "guardduty:ListDetectors",
                          "securityhub:DescribeHub", "iam:GetAccountPasswordPolicy"],
                "lake_producer": AWS_CLOUDTRAIL_PRODUCER,
                "note": "this page does not run the probe; the AWS panel does, and it renders "
                        "UNMEASURABLE:<reason> rather than a zero"},
        "capability": {"path": cap["path"], "provenance": cap["provenance"],
                       "out_of_scope": sum(1 for r in cap["rows"] if r["state"] == "out_of_scope")},
        "unmeasured": (reg["unmeasured"] + det["unmeasured"] + lake["unmeasured"]
                       + post["unmeasured"] + cap["unmeasured"]),
        "boards": [b["slug"] for b in _boards()],
    }


@router.get("/tenants")
def tenants():
    """The tenant switcher's list: who exists, what state, and what can never be attributed."""
    reg = _load_registry()
    rows = []
    for t in reg["tenants"]:
        rows.append({
            "platform": t["platform"],
            "display_name": t["display_name"],
            "status": t["status"],
            "maturity": t["maturity"],
            "products_count": t["products_count"],
            "clouds_count": t["clouds_count"],
            "unverified_accounts": sum(1 for c in t["clouds"] if not c["account_verified"]),
            "sources_declared": t["sources_declared_count"],
            "detections_enabled_count": t["detections_enabled_count"],
            "waivers_count": t["waivers_count"],
            "assets_count": t["assets_count"],
            "attribution_rules": len(t["assets"]),
            "routing": t["routing"],
        })
    return {
        "as_of": _as_of(),
        "rows": rows,
        "count": len(rows),
        "registry_root": reg["root"],
        "registry_provenance": reg["provenance"],
        # `_unattributed` is not a tenant: it is the bucket for findings no registry rule claims.
        "synthetic_rows": ["_unattributed", "all"],
        "unmeasured": reg["unmeasured"],
    }


@router.get("/health")
def health(tenant: Optional[str] = None):
    """Per-tenant liveness — is the instrument on. Tenant is required (no default)."""
    reg = _load_registry()
    chosen = _tenant_or_refuse(tenant, reg["tenants"])
    lake = _lake_config()
    unmeasured = list(reg["unmeasured"]) + list(lake["unmeasured"])

    feeds: list[dict[str, Any]] = []
    if lake["lake_root"]:
        probe = _probe_feeds(lake["lake_root"], lake["feeds"], legacy=(lake["provenance"] == "legacy-live"))
        unmeasured += probe["unmeasured"]
        for r in probe["rows"]:
            feeds.append({
                "name": r.get("name"),
                "alive": bool(r.get("ok")),
                "rows": r.get("rows"),
                "last_event": r.get("last_event"),
                "last_ingest": r.get("last_ingest"),
                "assets_seen": r.get("devices"),
                "error": r.get("error"),
                "schema": "legacy" if lake["provenance"] == "legacy-live" else "psec",
            })
        if not feeds:
            unmeasured.append("lake: no feed returned a row count")
    else:
        unmeasured.append("lake: no lake_root resolved")

    per_tenant = []
    for t in (reg["tenants"] if chosen == "all" else [x for x in reg["tenants"] if x["platform"] == chosen]):
        # Stream-level coverage needs the FROZEN eight-column header; the legacy feed does not
        # carry it, so stream presence is unmeasured rather than inferred from a different schema.
        per_tenant.append({
            "platform": t["platform"],
            "status": t["status"],
            "maturity": t["maturity"],
            "sources_declared": t["sources_declared"],
            "sources_declared_count": t["sources_declared_count"],
            "streams_expected": list(FIVE_STREAMS),
            "streams_present": None,
            "rules_enabled": t["detections_enabled_count"],
            "rules_total": None,
            "unmeasured": ["streams: no psec-lake rows for this platform yet (the frozen five-stream "
                           "lake is unwritten)"],
        })
    if chosen != "all" and not per_tenant:
        raise HTTPException(status_code=404, detail=f"tenant {chosen!r} not found")
    return {
        "as_of": _as_of(),
        "tenant": chosen,
        "lake": {"root": lake["lake_root"], "config": lake["path"], "provenance": lake["provenance"]},
        "feeds": feeds,
        "feeds_alive": sum(1 for f in feeds if f["alive"]),
        "feeds_probed": len(feeds),
        "tenants": per_tenant,
        "unmeasured": unmeasured,
    }


@router.get("/coverage")
def coverage(tenant: Optional[str] = None):
    """The coverage matrix: detection rules x tenants, with learning/enforcing and waivers.

    Coverage is a claim, not a measurement (contract §3.4): what IS measured here is rules enabled /
    rules total, the tenant's declared sources, and each rule's platform scope. Anything else is
    named in ``unmeasured``.

    The matrix is the PLATFORM catalog's (contract §5's index). The suite's ENDPOINT catalog is
    returned beside it — its own entry, its own engine, its own lake, its own ids — precisely so
    that a reader cannot take these ``rules_total`` rows for the estate's whole detection coverage.
    The two catalogs are not comparable rule-for-rule; only their ids are counted together
    (``catalogs_rules_total``).
    """
    reg = _load_registry()
    chosen = _tenant_or_refuse(tenant, reg["tenants"])
    det = _detections()
    unmeasured = list(reg["unmeasured"]) + list(det["unmeasured"])
    tenants = reg["tenants"] if chosen == "all" else [t for t in reg["tenants"] if t["platform"] == chosen]
    enabled_by_tenant = {t["platform"]: set(t["detections_enabled"]) for t in tenants}
    waivers_by_tenant = {t["platform"]: {w["detection"]: w for w in t["waivers"]} for t in tenants}
    rows = []
    for rule in det["rules"]:
        cells = []
        for t in tenants:
            plats = rule.get("platforms")
            in_scope = (plats == "all" or (isinstance(plats, list) and t["platform"] in plats))
            enabled = rule["rule"] in enabled_by_tenant.get(t["platform"], set())
            waiver = waivers_by_tenant.get(t["platform"], {}).get(rule["rule"])
            cells.append({
                "platform": t["platform"],
                "in_scope": bool(in_scope),
                "enabled": bool(enabled),
                "maturity": t["maturity"],
                "waiver": waiver or None,
                "state": ("excluded" if not in_scope else
                          ("waived" if waiver else ("enabled" if enabled else "not_enabled"))),
            })
        rows.append({"rule": rule["rule"], "title": rule["title"], "severity": rule["severity"],
                     "stream": rule["stream"], "maturity": rule["maturity"], "cells": cells})
    if det["endpoint_catalog"]["readable"]:
        # The matrix is the PLATFORM catalog's, and it must never be read as the estate's whole
        # detection coverage: the endpoint catalog is a second named catalog of the suite, read by
        # another engine against another lake (ruling on t_0e78bcf9). Its rules are NOT in this
        # matrix and are NOT comparable rule-for-rule with these — only the ids are counted together.
        unmeasured.append(
            "coverage: `rules_total` counts the PLATFORM catalog only "
            f"({det['rules_total']} rule(s), engine {det['platform_catalog']['engine']}). The "
            f"ENDPOINT catalog is the suite's second named catalog "
            f"({det['endpoint_catalog']['count']} rule(s), engine "
            f"{det['endpoint_catalog']['engine']}, lake "
            f"{det['endpoint_catalog']['lake'] or 'unmeasured'}) and is NOT in this matrix: "
            "different engine, different lake, not comparable rule-for-rule. Between them the "
            f"suite's catalogs carry {det['catalogs_rules_total']} distinct rule id(s)."
        )
    # The other direction of the same join, and the honest one: a detection a tenant's registry
    # ENABLES that the catalog does not carry is a GAP, not a quiet zero. Name it.
    catalog_ids = {r["rule"] for r in det["rules"]}
    declared_only: dict[str, list[str]] = {}
    for t in tenants:
        missing = [d for d in t["detections_enabled"] if d not in catalog_ids]
        if missing:
            declared_only[str(t["platform"])] = missing
    if declared_only:
        unmeasured.append(
            "coverage: " + "; ".join(f"{k} enables {len(v)} detection(s) the catalog does not carry "
                                     f"({', '.join(v[:4])}{'…' if len(v) > 4 else ''})"
                                     for k, v in declared_only.items())
        )
    return {
        "as_of": _as_of(),
        "tenant": chosen,
        "rules_total": len(det["rules"]),
        "tenants_total": len(tenants),
        "rows": rows,
        "count": len(rows),
        "declared_only": declared_only,
        "detections_source": det["path"],
        "detections_provenance": det["provenance"],
        # BOTH catalogs of the suite, each with its own identity and its own rule ids. The matrix
        # above is the platform catalog's alone — see the `comparability` note.
        "catalogs": det["catalogs"],
        "platform_catalog": det["platform_catalog"],
        "endpoint_catalog": det["endpoint_catalog"],
        "catalogs_rules_total": det["catalogs_rules_total"],
        "comparability": det["comparability"],
        "shadowed": det["shadowed"],
        "shadowed_rules_total": sum(s["count"] for s in det["shadowed"]),
        "unmeasured": unmeasured,
    }


@router.get("/findings")
def findings(tenant: Optional[str] = None, state: Optional[str] = None,
             limit: int = Query(DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
             sort: str = Query("created_at")):
    """The finding queue with the SOC lifecycle, MTTA/MTTR and what is stale.

    ``sort`` is an allowlist (04 §3.1): an unknown value is refused, not interpolated. So is
    ``state`` — an unrecognised lifecycle value is refused rather than quietly matching nothing.
    ``archived`` IS a lifecycle value (a SILENCING state, contract §7): it is selectable here and it
    renders as itself, never as a closure.

    ⛔ THE FINDINGS ARE ALSO RECONCILED AGAINST THE CATALOGS, which nothing did before 2026-09-23
    (card t_be4443f9): ``unmatched_rule_ids`` names every rule id carried by a filed finding that NO
    readable catalog carries — a detector the suite does not admit to having. It is reported HERE and
    not in ``coverage`` on purpose: ``coverage`` is a function of the registry and the two catalogs,
    and the bench's arm B asserts that deleting a finding moves no section but ``findings``/``cross``.
    A partial join (a catalog present-but-unreadable, a board that could not be read) reports
    ``filed_findings_reconciled.state == "unmeasured"`` and keeps ``unmatched_rule_ids`` EMPTY — what
    no READABLE catalog carries is not the same claim as what no catalog carries.

    Scope is applied in this order: read the whole population, attribute, filter tenant, filter
    state, THEN cap the page. The cap therefore bounds the RETURNED rows only; ``in_scope_total`` is
    the exact count of the scope the operator asked for, and ``population_total`` is the whole read.
    (A cap applied before the filters makes a tenant read report the estate's numbers and can hide a
    tenant's rows entirely — the defect this route was rebuilt to remove.)
    """
    allowed_sort = {"created_at": lambda r: r["created_at"] or "",
                    "age": lambda r: -(r["age_seconds"] or 0),
                    "severity": lambda r: SEVERITIES.index(r["severity"]) if r["severity"] in SEVERITIES else 99,
                    "lifecycle": lambda r: r["lifecycle"]}
    if sort not in allowed_sort:
        raise HTTPException(status_code=400,
                            detail=f"sort must be one of {sorted(allowed_sort)}")
    reg = _load_registry()
    chosen = _tenant_or_refuse(tenant, reg["tenants"])
    wanted = _states_or_refuse(state)
    cap = _clamp_int(limit, DEFAULT_LIST_LIMIT, 1, MAX_LIST_LIMIT)
    data = _read_findings()
    rows = _attribute_all(data["rows"], reg["tenants"])
    if chosen != "all":
        rows = [r for r in rows if r["platform"] == chosen]
    if wanted:
        rows = [r for r in rows if r["lifecycle"] in wanted]
    # 04 §3.1's required `id DESC` tiebreaker, applied to the page as well as the COUNT: sorting by
    # id first and then STABLE-sorting by the chosen key keeps ties in descending-id order, so a
    # truncated page stops at the same row every time instead of at an arbitrary tie.
    rows.sort(key=lambda r: r["id"] or "", reverse=True)
    rows.sort(key=allowed_sort[sort])
    in_scope_total = len(rows)
    cap_hit = in_scope_total > cap
    counts: dict[str, int] = {s: 0 for s in SOC_STATES}
    counts["unrecognised_status"] = 0
    for r in rows:
        counts[r["lifecycle"]] = counts.get(r["lifecycle"], 0) + 1
    page = rows[:cap]
    unmeasured = list(data["unmeasured"]) + list(reg["unmeasured"])
    unmeasured.append("MTTA (delivery): the outbox `sent` timestamp does not exist yet, so time-to-"
                      "delivery is unmeasured — do not read MTTR below as detection responsiveness")
    unmeasured.append("MTTR: " + MTTR_EPISODE_NOTE)
    scope_predicate = "tenant=" + chosen
    if wanted:
        scope_predicate += " & state=" + str(state).strip()
    # THE OTHER DIRECTION, and the one that was missing: a FILED FINDING reconciled against the
    # catalogs. Registry -> catalog IS reconciled (declared_only, above); finding -> catalog was NOT,
    # so a card filed under a rule id no catalog carries rendered as a normal finding and appeared in
    # no note at all. MEASURED 2026-09-23 (card t_be4443f9, arm XREF): a card filed under
    # `psec.not.in.any.catalog` was indistinguishable in the payload from one filed under a declared
    # detector.
    #
    # ⛔ IT IS REPORTED HERE, IN `findings`, AND NOT IN `coverage` — deliberately. `coverage` is a
    # function of the registry and the two catalogs, and the t_a6731507 bench's arm B asserts exactly
    # that (delete the fixture finding and NO section but `findings`/`cross` may move). Hanging this
    # join off `coverage` broke that control, and bending the control to admit it would have been the
    # repair buying its own pass. A filed finding's rule id is a property of the FINDING POPULATION,
    # so it is reported with it.
    det = _detections()
    readable_catalogs = [c for c in det["catalogs"] if c.get("readable")]
    catalog_ids: set[str] = set()
    for c in readable_catalogs:
        catalog_ids |= set(c.get("rules") or [])
    seen: dict[str, dict[str, Any]] = {}
    rows_with_rule = 0
    for r in rows:
        rid = r.get("rule_id")
        if not rid:
            continue
        rows_with_rule += 1
        if str(rid) in catalog_ids:
            continue
        entry = seen.setdefault(str(rid), {"rule_id": str(rid), "findings": 0, "cards": []})
        entry["findings"] += 1
        if len(entry["cards"]) < 5:
            entry["cards"].append(r["id"])
    # A PARTIAL join is not a join. "No catalog carries this rule" is only established when EVERY
    # catalog of the suite was readable and every board was read: otherwise the id may live in the
    # index that could not be read, and naming it UNMATCHED would be the same false-positive class as
    # a failed measurement rendered as a zero. MEASURED 2026-09-23 (the bench's `sub` shape, platform
    # catalog ABSENT): `psec.auth.spike` — a rule the missing index carries — was named unmatched by a
    # reconciliation that had only read the other catalog. So the ids seen over the readable catalogs
    # are reported under a name that says exactly that, and `unmatched_rule_ids` stays empty.
    complete = (len(readable_catalogs) == len(det["catalogs"])) and not data["unmeasured"]
    unmatched = seen if complete else {}
    partial = {} if complete else seen
    reconciliation_state = "complete" if complete else "unmeasured"
    if complete and unmatched:
        unmeasured.append(
            f"findings: {len(unmatched)} rule id(s) carried by FILED FINDINGS appear in NO readable "
            "catalog — findings from a detector the suite does not declare: "
            + "; ".join(f"{k} ({v['findings']} finding(s), e.g. {', '.join(v['cards'])})"
                        for k, v in sorted(unmatched.items()))
        )
    if not complete:
        why = []
        for c in det["catalogs"]:
            if not c.get("readable"):
                why.append(f"catalog {c['path']} is "
                           f"{'present but unreadable' if c['present'] else 'ABSENT'}")
        why.extend(f"board {u}" for u in data["unmeasured"])
        unmeasured.append(
            "findings: the finding->catalog reconciliation is UNMEASURED — " + "; ".join(why)
            + f". It read {len(readable_catalogs)} of {len(det['catalogs'])} catalogs and "
            f"{len(data['boards_scanned'])} board(s), and "
            + (f"{len(partial)} rule id(s) no READABLE catalog carries are reported under "
               "`unmatched_in_readable_catalogs_only` — that is NOT a claim that no catalog carries "
               "them: " + ", ".join(sorted(partial))
               if partial else
               "no rule id was left over on the reads it did make, which is not the same as none "
               "being undeclared")
        )
    # PER ROW, so that "distinguishable in the payload" does not require a join: a row filed under a
    # rule id no readable catalog carries says so on itself. `None` — not `False` — when the join is
    # incomplete or the row carries no rule id at all: `False` would be a CLAIM, and the whole point
    # of the state field is that an unmeasured join must not be read as one.
    for r in rows:
        rid = r.get("rule_id")
        r["rule_in_catalog"] = (None if (not complete or not rid)
                                else str(rid) in catalog_ids)
    return {
        "as_of": _as_of(),
        "tenant": chosen,
        "state": state,
        "rows": page,
        "count": len(page),
        # The two scopes are named and never mixed in one number: `count` is the page, `in_scope_total`
        # is what the operator's tenant+state filter matches, `population_total` is everything read.
        "in_scope_total": in_scope_total,
        "population_total": data["population_total"],
        "cap": cap,
        "cap_hit": cap_hit,
        "scope_predicate": scope_predicate,
        "lifecycle_counts": counts,
        "boards_scanned": data["boards_scanned"],
        "unrecognised_status_count": counts["unrecognised_status"],
        "lifecycle_vocab": list(SOC_STATES),
        "open_states": list(OPEN_STATES),
        "silenced_states": list(SILENCED_STATES),
        # WHAT `stale` IS A PROPERTY OF, said in the payload rather than left to be inferred from the
        # field name. MEASURED 2026-09-23 (card t_be4443f9, arm STALE): a 100-day-old resolved row
        # read `stale: false` with nothing anywhere saying the false was "not applicable".
        "stale_scope": "open_rows_only",
        "stale_open_seconds": STALE_OPEN_SECONDS,
        "stale_definition": (
            "`stale` is an OPEN-CASE signal: true only for a row whose lifecycle is in "
            "`open_states` AND whose `age_seconds` and time-since-last-touch both exceed "
            "`stale_open_seconds`. `stale_applicable` is false on every closed or silenced row, so "
            "`stale: false` there means NOT APPLICABLE, not fresh (contract §7). A row-level "
            "untouched-for-N-seconds fact is `age_seconds`, which is reported for every row."
        ),
        "unmatched_rule_ids": unmatched,
        "unmatched_rule_ids_count": len(unmatched),
        # NOT a substitute for the above: ids no READABLE catalog carries while the join is
        # incomplete. Named separately so a consumer cannot read it as "undeclared".
        "unmatched_in_readable_catalogs_only": partial,
        "unmatched_in_readable_catalogs_only_count": len(partial),
        "filed_findings_reconciled": {
            "state": reconciliation_state,
            "scope": scope_predicate,
            "catalogs_readable": len(readable_catalogs),
            "catalogs_total": len(det["catalogs"]),
            "rows_in_scope": len(rows),
            "rows_with_rule_id": rows_with_rule,
            "boards_scanned": data["boards_scanned"],
        },
        "unmeasured": unmeasured,
    }


@router.get("/cross")
def cross():
    """Across tenants: one row per tenant, plus ``_unattributed`` and ``all``.

    ``all`` is its OWN aggregate over the whole population, never the arithmetic of the rows above,
    so ``all != sum(rows)`` is visible rather than silently under-counted (04 §3.3). No composite
    risk score is produced, by design (04 §3.4).

    **No LIMIT is applied to this read.** A KPI computed over a capped page is not a KPI (04 §3.1,
    §3.4): both sides being truncated identically made ``all_equals_sum`` true while open cases were
    missing. The whole population is read and aggregated, and the response says so — ``capped:
    false`` with ``population_total`` — instead of leaving a cap flag for the page to ignore.
    """
    reg = _load_registry()
    data = _read_findings()
    rows = _attribute_all(data["rows"], reg["tenants"])
    buckets: dict[str, dict[str, Any]] = {}
    for r in rows:
        b = buckets.setdefault(r["platform"], {"open": 0, "needs_human": 0, "resolved": 0,
                                               "silenced": 0, "ages": [], "unrecognised": 0})
        if r["lifecycle"] in OPEN_STATES:
            b["open"] += 1
        elif r["lifecycle"] == "resolved":
            b["resolved"] += 1
        if r["lifecycle"] in SILENCED_STATES:
            # A SILENCING act is its OWN bucket, never a closure (contract §7): MEASURED 2026-09-23
            # (card t_be4443f9, arm ARCH) an archived card incremented `resolved` here.
            b["silenced"] += 1
        if r["lifecycle"] == "unrecognised_status":
            b["unrecognised"] += 1
        if r["block_kind"] == "needs_input":
            b["needs_human"] += 1
        if r["age_seconds"] is not None and r["lifecycle"] in OPEN_STATES:
            b["ages"].append(r["age_seconds"])
    out_rows = []
    for t in reg["tenants"]:
        b = buckets.get(str(t["platform"]), {})
        row_unmeasured = ["streams: psec lake unwritten"]
        if not any(b.get(k) for k in ("open", "resolved", "silenced", "needs_human", "unrecognised")):
            row_unmeasured.append(
                "no finding on any board attributes to this tenant — read that as 'nothing is "
                "attributed', not as 'nothing happened'"
            )
        out_rows.append(_cross_row(str(t["platform"]), t["display_name"], b,
                                   is_tenant=True, maturity=t["maturity"],
                                   unmeasured=row_unmeasured))
    b = buckets.get("_unattributed", {})
    unattr_unmeasured = ["no registry asset rule claims these findings — its own row, never "
                         "folded into a tenant (contract §4.2 r9)"]
    if not b:
        unattr_unmeasured.append("nothing is unattributed on any board right now")
    out_rows.append(_cross_row("_unattributed", "Unattributed", b, is_tenant=False,
                               maturity=None, unmeasured=unattr_unmeasured))
    open_rows = [r for r in rows if r["lifecycle"] in OPEN_STATES]
    total_open = len(open_rows)
    # Two sums are reported because they answer different questions: the TENANT sum deliberately
    # excludes `_unattributed` (folding it into a tenant would be a cross-tenant write, §4.2 r9), and
    # the ROW sum includes it, so `all_equals_sum` isolates "a row is missing" from "unattributed is
    # kept apart".
    sum_tenant = sum(r["open"] for r in out_rows if r.get("is_tenant"))
    sum_rows = sum(r["open"] for r in out_rows)
    all_row = {
        "platform": "all",
        "display_name": "ALL (own aggregate over the whole population, not the sum of the rows above)",
        "is_tenant": False,
        "open": total_open,
        "needs_human": sum(1 for r in rows if r["block_kind"] == "needs_input"),
        "oldest_open_age_seconds": max([r["age_seconds"] or 0 for r in open_rows] or [0]) or None,
        "resolved": sum(1 for r in rows if r["lifecycle"] == "resolved"),
        "silenced": sum(1 for r in rows if r["lifecycle"] in SILENCED_STATES),
        "unrecognised_status": sum(1 for r in rows if r["lifecycle"] == "unrecognised_status"),
        "maturity": None,
        "unmeasured": [],
    }
    unmeasured = list(data["unmeasured"]) + list(reg["unmeasured"])
    unmeasured.append("MTTA: unmeasured (no delivery outbox yet)")
    unmeasured.append("coalescing factor: no occurence_count table yet — occurrences/cases is "
                      "unmeasured, not 1.0")
    return {
        "as_of": _as_of(),
        "rows": out_rows,
        "all": all_row,
        "rows_count": len(out_rows) + 1,
        "sum_of_tenant_open": sum_tenant,
        "sum_of_rows_open": sum_rows,
        "all_open": total_open,
        "all_equals_sum": total_open == sum_rows,
        "tenant_rows_equal_all": sum_tenant == total_open,
        "cap": None,
        "cap_hit": False,
        "capped": False,
        "population_total": data["population_total"],
        "aggregate_scope": ("every finding on every board read and aggregated; no LIMIT applied "
                            "(a KPI over a capped read is not a KPI)"),
        "unmeasured": unmeasured,
    }


def _cross_row(platform: str, label: str, b: dict[str, Any], is_tenant: bool,
               maturity: Optional[str], unmeasured: list[str]) -> dict[str, Any]:
    ages = b.get("ages") or []
    return {
        "platform": platform,
        "display_name": label,
        "is_tenant": is_tenant,
        "open": b.get("open", 0),
        "needs_human": b.get("needs_human", 0),
        "oldest_open_age_seconds": max(ages) if ages else None,
        "resolved": b.get("resolved", 0),
        "silenced": b.get("silenced", 0),
        "unrecognised_status": b.get("unrecognised", 0),
        "maturity": maturity,
        "unmeasured": list(unmeasured),
    }


@router.get("/retirement")
def retirement():
    """Sentinel/Defender exit items and their shadow-proof state. Nothing is cut until proven."""
    post = _posture()
    sentinel = _sentinel_facts(post["data"])
    defender = _defender_facts(post["data"])
    gate = None
    gate_path = None
    for root, _prov in [(_scripts_dir(), "scripts-store"),
                        (_artifact_root(), "wip-outbox")]:
        p = root / "psec-exit-gate.json"
        if p.is_file():
            gate, err = _read_json(p)
            gate_path = str(p)
            if err:
                gate = None
            break
    items = _exit_gate_items(post["path"], gate, sentinel, defender)
    unmeasured = list(post["unmeasured"])
    if not gate_path:
        unmeasured.append("retirement: no psec-exit-gate.json — every item's proof state renders "
                          "`unproven`; absence of proof is not proof")
    else:
        unmeasured.append(
            "retirement: the gate artifact is read by item id as the proof key, with "
            "`sentinel.shadow.7d`/`.7` accepted as aliases for `sentinel.shadow` "
            "(exit-gate.schema.json); `proof.key` names the key that answered"
        )
    spend = _owner_spend_card()
    unmeasured += spend.get("unmeasured", [])
    return {
        "as_of": _as_of(),
        "posture_source": post["path"],
        "posture_provenance": post["provenance"],
        "posture_mtime": post.get("mtime"),
        "gate_source": gate_path,
        "sentinel": sentinel,
        "defender": defender,
        "items": items,
        "items_proven": sum(1 for i in items if (i.get("proof") or {}).get("state") == "green"),
        "items_total": len(items),
        "owner_spend_card": spend,
        "unmeasured": unmeasured,
    }


# --- endpoints: the two owner writes -----------------------------------------

class AnswerBody(BaseModel):
    board: str
    task_id: str
    choice: Optional[int] = None
    text: Optional[str] = None
    option_text: Optional[str] = None
    unblock: bool = True


class CommentBody(BaseModel):
    board: str
    task_id: str
    body: str


def _write_conn(slug: str):
    if not any(b["slug"] == slug for b in _boards()):
        raise HTTPException(status_code=404, detail=f"board {slug!r} not found")
    kanban_db.init_db(board=slug)
    return kbc.connect(board=slug)


def _owner_comment(choice: Optional[int], option_text: Optional[str], text: Optional[str]) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [f"**OWNER DECISION** — answered from the Protection Suite dashboard ({stamp})", ""]
    if choice is not None:
        chosen = (option_text or "").strip()
        if chosen and chosen[-1] not in ".!?":
            chosen += "."
        lines.append(f"Option {choice} chosen" + (f": {chosen}" if chosen else "."))
    if text and text.strip():
        lines.append("")
        lines.append(text.strip())
    return "\n".join(lines)


@router.post("/answer")
def answer(body: AnswerBody):
    """Record the owner's answer on a card and (by default) re-open it for dispatch."""
    if body.choice is None and not (body.text and body.text.strip()):
        raise HTTPException(status_code=400, detail="provide a choice and/or text")
    with closing(_write_conn(body.board)) as conn:
        task = kanban_db.get_task(conn, body.task_id)
        if task is None:
            raise HTTPException(status_code=404, detail=f"task {body.task_id} not found")
        before = task.status
        comment_id = kanban_db.add_comment(
            conn, body.task_id, "jesse",
            _owner_comment(body.choice, body.option_text, body.text),
        )
        after = before
        if body.unblock and before in ("blocked", "scheduled"):
            ok = kanban_db.unblock_task(conn, body.task_id)
            if not ok:
                raise HTTPException(status_code=409, detail="unblock refused (state changed?)")
            reread = kanban_db.get_task(conn, body.task_id)
            after = reread.status if reread else "?"
        final = kanban_db.get_task(conn, body.task_id)
    return {"ok": True, "comment_id": comment_id, "status_before": before, "status_after": after,
            "block_kind": (final.block_kind if final else None)}


@router.post("/comment")
def comment(body: CommentBody):
    """Comment on a card as the owner, changing no state."""
    if not body.body.strip():
        raise HTTPException(status_code=400, detail="empty comment")
    with closing(_write_conn(body.board)) as conn:
        if kanban_db.get_task(conn, body.task_id) is None:
            raise HTTPException(status_code=404, detail=f"task {body.task_id} not found")
        cid = kanban_db.add_comment(conn, body.task_id, "jesse", body.body.strip())
    return {"ok": True, "comment_id": cid}
