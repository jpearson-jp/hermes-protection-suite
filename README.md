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
      desktop/plugin.js           the DESKTOP half (see below) — app route + sidebar row
      dashboard/dist/desktop-plugin.js   served copy of the desktop half (fetchable over HTTP)

## Two halves, two surfaces — because they are not the same surface

The Hermes **desktop app** does not render web-dashboard plugins. Upstream is explicit:
`website/docs/user-guide/desktop.md` — *"The desktop app is self-contained: it runs its own
`hermes serve` backend and never opens or requires the web dashboard"*; and
`developer-guide/desktop-plugin-sdk.md` — *"This is not the web-dashboard plugin SDK … The three do
not share code, APIs, or delivery."* So a `dashboard/manifest.json` tab was never going to appear in
the app, however correctly it was built, enabled and restarted. A package that wants a tab in the app
must ship `desktop/plugin.js` — one ESM file, no build step, loading uncompiled (no JSX; only
`@hermes/plugin-sdk`, `react`, `react/jsx-runtime`).

`desktop/plugin.js` contributes `ROUTES_AREA` (`/protection-suite`) + `SIDEBAR_NAV_AREA` + a status-bar
chip + palette/keybind entries, and reads the SAME Python routes through `ctx.rest` (scoped to
`/api/plugins/protection-suite/` by construction, which is what makes it work against a REMOTE
backend — a bare `fetch` does not). It renders the same panels, including the capability floor, and
keeps the same honesty rule: what could not be measured is named, never rendered as a zero.

Delivery: the app loads `<hermes home>/desktop-plugins/protection-suite/plugin.js` from **the machine
the app runs on** (`electron/fs-ipc.ts` resolves it from the main process's `HERMES_HOME`, never the
connected backend's — `#66899`). `build.sh` therefore also materializes the half at that app-level
root on this box (harmless when the renderer is elsewhere), and the half is served at
`/dashboard-plugins/protection-suite/dist/desktop-plugin.js` for a renderer that must fetch it.
For an app on another machine, install it through the app's own dialog:

    hermes://plugin/install?repo=jpearson-jp/hermes-protection-suite&enable=1


## Surfaces

| # | Panel | Route | What it answers |
|---|---|---|---|
| 0 | **Capability floor** | `GET /capability` | **what this suite does and, explicitly, what it does NOT do** — host prevention and host rollback render `out_of_scope` from a recorded decision (t_527e3f35); leads the page, and does not re-scope with the tenant switcher |
| 1 | Liveness | `GET /health?tenant=` | is the instrument ON: per-feed rows, last event, last ingest, assets seen; per-tenant maturity, sources declared, rules enabled |
| 2 | Finding queue | `GET /findings?tenant=` | the SOC lifecycle per case, age, staleness, disposition, MTTR over cards, and what cannot be measured (MTTA-delivery) |
| 3 | Across tenants | `GET /cross` | one row per tenant + `_unattributed` + `all` (its own query, so `all != sum(rows)` is visible) |
| 4 | Coverage matrix | `GET /coverage?tenant=` | detections x tenants: scope, enabled, maturity, waivers, and declared-but-not-in-catalog gaps |
| 5 | Retirement board | `GET /retirement` | Sentinel/Defender exit items, each with its shadow-proof state and the owner-spend card |
| — | Provenance | `GET /meta` | what every other route is reading, and what could not be read |
| — | Owner writes | `POST /answer`, `POST /comment` | record a decision on a card / comment without changing state (via `hermes_cli.kanban_db`) |

### The capability floor — why there is a panel for what the suite does NOT do

`GET /capability` renders `dashboard/capability.json`, the recorded scope decision for kanban
`t_527e3f35`: **host prevention and host rollback are `out_of_scope`**, control-plane enforcement is
in scope (and is only ever the reversible actions whose inverse ships with them), and host tamper
resistance is `partial` (userspace-only). It leads the page because every number below it is only
readable once that is known: coverage, liveness and a case queue together imply a capability the
estate does not have, and the measured position is that Linux prevention is post-exec *confinement*
(the payload runs), `bpf_lsm` is dormant and `bpf` is not in the host's active LSM list, and nothing
can undo a host change.

A decision is not a measurement, so this record is **versioned with the module and never inferred**;
it is the dashboard's copy of the decision owned by `PROTECTION-SUITE-CONTRACT.md` §11. If the
record cannot be read, the API renders a compiled-in floor **with the same two gaps named** and adds
an `unmeasured` entry — "I could not read the record" may never render as "the suite does
everything" (`tests/test-plugin-api.py` asserts both arms).

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
* **A capability the suite does not have is stated, not implied.** Host prevention and host rollback
  render `out_of_scope` on the leading panel; a decision is versioned with the module rather than
  inferred, and an unreadable capability record falls back to a compiled-in floor that still names
  the gaps (`t_527e3f35`).
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

## Sources (each source is NAMED; a source that is absent is reported, never guessed at)

| source | frozen home | fallback while the producers are in flight |
|---|---|---|
| tenant registry | `~/.hermes/scripts/platform-registry/*.yaml` | the foundation card's artifact dir, labelled `wip-outbox` |
| detection catalogs — **two NAMED catalogs**, never one resolved in candidate order | **platform catalog** `~/.hermes/scripts/psec-detections.json` (contract §5's index; `rules` is a DICT; engine `psec-gaps-detect.py` — cron `8065d45ca251`, every 15 min — + `psec-detect.py`; lake `psec-sources.json` → `lake_root`) and **endpoint catalog** `~/.hermes/scripts/siem-detections.json` (the suite's second named index; `rules` is a LIST; engine `siem-detect.py` — cron `f1ed861d4b6f`, **every 5 min**, `file_cards: true`; lake `siem-lake-sources.json` → `lake_root`, stream `rmm-edr`) | **none — there is no fallback.** An absent or unreadable platform index is `unmeasured` **for platform detection**, named as such: the endpoint catalog is a different engine on a different lake and is never its substitute (ruling `t_0e78bcf9` §1.5). A genuine THIRD live catalog (`*detections*.json` that is neither named catalog) is still reported as `shadowed` with every rule id. `siem-detections-la.json` is the LA lane's **staging** file (46 KQL rules, no cron) and is in no census |
| lake | `~/.hermes/scripts/psec-sources.json` → `lake_root` | `siem-lake-sources.json`, labelled `legacy-live` (its schema is the predecessor's, so stream-level panels stay `unmeasured`) |
| retirement | `azure-posture.json` in the scripts store | the exit measurement's artifact dir, labelled `wip-outbox` |
| capability floor | `dashboard/capability.json`, shipped inside this plugin and versioned with it | the compiled-in floor in `plugin_api.py`, labelled `compiled-in`, which names the same gaps |
| ledger | the kanban boards, via `kanban_db.list_boards()` | — |

`/coverage` returns both catalogs (`catalogs`, `platform_catalog`, `endpoint_catalog`) beside the
matrix, with `catalogs_rules_total` = the distinct rule ids across both and `comparability` stating
that the two are **not** comparable rule-for-rule. `rules_total` is the **platform** catalog only —
the matrix is that index's, and the response's `unmeasured` names it as such so the matrix is never
read as the estate's whole detection coverage.

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
