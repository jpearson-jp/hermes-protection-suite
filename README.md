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

## The rules this code keeps

* **An unmeasured source is never a zero.** Every response carries `unmeasured: [...]` naming what
  could not be read; the page renders it under the panel. A feed that never delivered shows
  `unreadable`, not `0`.
* **A KPI over a capped read is not a KPI.** List responses echo `cap`, `cap_hit` and
  `total_before_cap`; the page prints `<n> of >= <n>`.
* **Tenant is a required argument with no default.** Omitting it is a 400; an unregistered value is
  a 404. The cross-tenant view is a different function with `all` as its explicit value.
* **`_unattributed` is a row, never a default tenant**, and `all` is computed separately.
* **No composite risk score** (refused by the contract), and no second push rail.
* **Nothing is cut until proven**: a retirement item whose shadow proof has not been written renders
  `unproven`, never green.

## Sources (each resolved in order; the one used is reported)

| source | frozen home | fallback while the producers are in flight |
|---|---|---|
| tenant registry | `~/.hermes/scripts/platform-registry/*.yaml` | the foundation card's artifact dir, labelled `wip-outbox` |
| detection catalog | `~/.hermes/scripts/psec-detections.json` | `siem-detections.json`, labelled `legacy-live` |
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
