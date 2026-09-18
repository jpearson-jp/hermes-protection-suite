# Protection Suite dashboard plugin — the operator surface

A Hermes **web-dashboard plugin** (drop-in: no `web/src/` edit, no core rebuild, no `npm run build`).
It is the operator surface of the Protection Suite programme (umbrella kanban `t_2c5fb09a`, this card
`t_4806df6b`), built against the frozen contract in
`/home/hermes/hermes-outbox/2026-09-18-protection-suite/PROTECTION-SUITE-CONTRACT.md` §8 and
`04-soc-dashboards-automations.md` §3-§4.

    ~/.hermes/plugins/protection-suite/
      plugin.yaml                 general-plugin manifest (the enable gate reads this)
      __init__.py                 no-op agent-side registration — no tools, no hooks
      dashboard/manifest.json     tab `after:kanban`, path `/protection-suite`, entry/css/api
      dashboard/dist/index.js     the IIFE bundle (built by build.sh from src/)
      dashboard/dist/style.css    theme-true CSS
      dashboard/plugin_api.py     FastAPI router, mounted at /api/plugins/protection-suite/
      src/                        core.js (shared helpers), pages/suite.js (the page), style.css
      templates/manifest.json     manifest template
      tools/enable-everywhere.py  enable the plugin in the ROOT config AND every profile
      tests/                      the checks that can run without a browser

## Surfaces

| # | Panel | Route | What it answers |
|---|---|---|---|
| 1 | Liveness | `GET /health?tenant=` | is the instrument ON: per-feed rows, last event, last ingest, assets seen; per-tenant maturity, sources declared, rules enabled |
| 2 | Finding queue | `GET /findings?tenant=` | the SOC lifecycle per case, age, staleness, disposition, MTTR over cards, and what cannot be measured (MTTA-delivery) |
| 3 | Across tenants | `GET /cross` | one row per tenant + `_unattributed` + `all` (its own query, so `all != sum(rows)` is visible) |
| 4 | Coverage matrix | `GET /coverage?tenant=` | detections x tenants: scope, enabled, maturity, waivers, and declared-but-not-in-catalog gaps |
| 5 | Retirement board | `GET /retirement` | Sentinel/Defender exit items, each with its shadow-proof state and the owner-spend card |
| — | Provenance | `GET /meta` | what every other route is reading, and what could not be read |
| — | Owner writes | `POST /answer`, `POST /comment` | record a decision on a card / comment without changing state (via `hermes_cli.kanban_db`) |

**The owner write surface is API-first, deliberately.** The estate's human ask-inbox is Mission
Control's *Waiting on me* tab, which renders the same park rows and posts to its own `/answer`. This
plugin exposes the same two writes for the automation tiers and for a tenant-scoped answer; it does
NOT render a second answer form, because a second surface for the same question is exactly the
"two query layers disagree" defect the design forbids (`04 §3.4` rule 4). The round-1 bundle carried
a copied `AskRow`/`CardDetail` that nothing rendered — removed.

## The rules this code keeps

* **An unmeasured source is never a zero.** Every response carries `unmeasured: [...]` naming what
  could not be read; the page renders it under the panel. A feed that never delivered shows
  `unreadable`, not `0`.
* **A KPI over a capped read is not a KPI — and a cap must never change a scope's count.** The scope
  predicate (tenant, lifecycle state) is applied to the POPULATION and the row cap last, so the page
  bounds only the rows RETURNED: `count` is the page, `in_scope_total` is the operator's scope,
  `population_total` is the whole read, and `lifecycle_counts` describe the scope (never the page).
  `cap_hit` is scoped, so a tenant's rows cannot vanish behind an estate-wide cap and render as a
  zero. Paging over a tie is deterministic: `ORDER BY created_at DESC, id DESC` in SQL and the same
  `id DESC` tiebreaker in the page sort (`04 §3.1`).
* **The cross panel applies no LIMIT at all.** `all` is an aggregate over the whole population, so
  `all_equals_sum` cannot be an artefact of both sides being truncated; the response says
  `capped: false` with `population_total` and the page renders that state.
* **Tenant is a required argument with no default.** Omitting it is a 400; an unregistered value is
  a 404. The cross-tenant view is a different function with `all` as its explicit value.
* **`state` and `sort` are allowlists.** An unrecognised value is refused (400) rather than silently
  matching nothing — an empty queue caused by a misspelling is the same false-zero class as a
  dropped read.
* **`_unattributed` is a row, never a default tenant**, and `all` is computed separately.
* **Boards are home-scoped.** `kanban_db`'s metadata can name a board path outside the resolved
  hermes home; such an entry is logged and dropped, so a test (or a profile) can never silently read
  another home's ledger.
* **No composite risk score** (refused by the contract), and no second push rail.
* **Nothing is cut until proven**: a retirement item whose shadow proof has not been written renders
  `unproven`, never green.
* **A switch visibly re-scopes.** The tenant banner carries a colour AND stripe pattern derived from
  a hash of the tenant name, so `04 §4.2 r4`'s "tenant-distinct colour or pattern" is satisfied —
  and two tenants that hash to neighbouring hues are still separated by the stripe angle.

## The exit gate's key contract (consuming side)

`/retirement` reads `psec-exit-gate.json` (scripts store first, then the exit measurement's artifact
dir). Its producer publishes no schema, so the contract this consumer keeps is written here and in
`exit-gate.schema.json` in the programme directory:

    {"items": [ {id, board, item, measured, proof: {state, evidence}}, ... ]}     <- preferred
    {"shadow": {"<proof key>": {"green": true|false, "evidence": ...}}, ...}      <- fallback

A proof key is the item's `id`. The one alias: the shadow item's id is `sentinel.shadow` and the
programme has also called that proof `sentinel.shadow.7d`, so both are read (as is `.7`) and
`proof.key` echoes the key that answered. Without the alias a producer writing the obvious key left
the item `unproven` forever, silently.

## Sources (each resolved in order; the one used is reported)

| source | frozen home | fallback while the producers are in flight |
|---|---|---|
| tenant registry | `~/.hermes/scripts/platform-registry/*.yaml` | the foundation card's artifact dir, labelled `wip-outbox` |
| detection catalog | `~/.hermes/scripts/psec-detections.json` | `siem-detections.json`, labelled `legacy-live` — and when the frozen index IS resolved, BOTH are still read: the other one is reported as `shadowed` (file, provenance, every rule id) on `/coverage` and `/meta`, because resolving one index must never turn a second LIVE index into a silence |
| lake | `~/.hermes/scripts/psec-sources.json` → `lake_root` | `siem-lake-sources.json`, labelled `legacy-live` (its schema is the predecessor's, so stream-level panels stay `unmeasured`) |
| retirement | `azure-posture.json` in the scripts store | the exit measurement's artifact dir, labelled `wip-outbox` |
| ledger | the kanban boards, via `kanban_db.list_boards()` | — |

DuckDB is **not** importable in the dashboard's venv, so the lake probe runs in the lake venv
(`/home/hermes/.lakevenv/bin/python3`) as a subprocess and reports a probe that fails to run as
`unmeasured` rather than as an empty feed list.

## Build and enable

```bash
./build.sh                                   # assemble dist/ + manifest, node --check the bundle
python3 tools/enable-everywhere.py protection-suite   # root config AND every profile, .bak first
kill -TERM "$(systemctl show hermes-dashboard.service -p MainPID --value)"   # routes mount at startup
```

Every profile matters: the desktop app spawns a `hermes --profile <p> serve --isolated` backend per
profile, and a user-source plugin absent from that profile's `plugins.enabled` makes its app view
answer `404 {"detail":"Plugin not found"}`.

The dashboard is loopback-only at `127.0.0.1:9119` by design; it is not published and must not be.
