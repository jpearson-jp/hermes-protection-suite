/**
 * Protection Suite — the DESKTOP half of the `protection-suite` package.
 *
 * WHY THIS FILE EXISTS: the package's other half (`dashboard/manifest.json` +
 * `dashboard/dist/index.js` + `dashboard/plugin_api.py`) is a WEB-DASHBOARD plugin. The Hermes
 * desktop app does NOT render the web dashboard — upstream is explicit (`website/docs/user-guide/
 * desktop.md`: "The desktop app is self-contained: it runs its own `hermes serve` backend and never
 * opens or requires the web dashboard"; `developer-guide/desktop-plugin-sdk.md`: "This is not the
 * web-dashboard plugin SDK ... The three do not share code, APIs, or delivery"). So a dashboard tab
 * could never appear in the app, however correctly it was built or enabled. This file is the half
 * that makes the Protection Suite reachable in the app: one route + one sidebar row, over the SAME
 * Python routes at `/api/plugins/protection-suite/` — reached through `ctx.rest`, which is scoped to
 * this plugin's own namespace by construction (and therefore works against a REMOTE backend, unlike
 * a bare `fetch`).
 *
 * Plugin `id` MUST equal the package folder name ('protection-suite'): the Electron main process
 * copies this file to `$HERMES_HOME/desktop-plugins/protection-suite/plugin.js`, and the id is what
 * namespaces both the backend route and this plugin's contributions.
 *
 * Loaded UNCOMPILED as ESM: no JSX (jsx()/jsxs() only), and the ONLY importable specifiers are
 * `@hermes/plugin-sdk`, `react` and `react/jsx-runtime`. Colours come from theme variables, never
 * literals, so it reskins with the app.
 *
 * The SDK surface used here is deliberately SMALL (areas + `host` + `useQuery`/`queryClient`), so a
 * component-library change upstream cannot break this pane; the markup is plain elements and the
 * CSS is local. The contract's two rules are kept on this surface too: an unmeasured source renders
 * as `unmeasured` (never as a zero), and `all` is shown beside the sum of the rows so
 * `all != sum(rows)` stays visible.
 */

import {
  KEYBINDS_AREA, PALETTE_AREA, haptic, host, queryClient,
  ROUTES_AREA, SIDEBAR_NAV_AREA, STATUSBAR_AREAS, useQuery
} from '@hermes/plugin-sdk'
import { useEffect, useMemo, useState } from 'react'
import { jsx, jsxs } from 'react/jsx-runtime'

const ID = 'protection-suite'
const PAGE = '/protection-suite'

// Assigned on register(); a module-level `let` so every component uses the scoped door.
let rest = () => Promise.reject(new Error('protection-suite: rest() before register()'))
let clipboard = () => {}

const CSS = `
.ps-page{display:flex;flex-direction:column;gap:12px;padding:14px 16px 40px;height:100%;overflow:auto}
.ps-bar{display:flex;flex-wrap:wrap;align-items:center;gap:8px}
.ps-h1{font-size:14px;font-weight:600;color:var(--ui-text-primary)}
.ps-sub{font-size:11px;color:var(--ui-text-tertiary)}
.ps-spacer{flex:1 1 auto}
.ps-btn{border:1px solid var(--ui-stroke-secondary);border-radius:5px;background:transparent;
  color:var(--ui-text-secondary);font-size:11.5px;padding:3px 8px;cursor:pointer}
.ps-btn:hover{border-color:var(--ui-accent);color:var(--ui-text-primary)}
.ps-btn[data-on=true]{border-color:var(--ui-accent);color:var(--ui-text-primary);
  background:color-mix(in srgb,var(--ui-accent) 12%,transparent)}
.ps-switch{display:flex;flex-wrap:wrap;gap:4px}
.ps-banner{border:1px solid var(--ui-stroke-secondary);border-radius:6px;padding:6px 10px;
  display:flex;flex-wrap:wrap;gap:6px 14px;align-items:center;font-size:11.5px;
  color:var(--ui-text-secondary)}
.ps-banner b{color:var(--ui-text-primary);font-size:12.5px}
.ps-swatch{width:10px;height:10px;border-radius:2px;display:inline-block;margin-right:6px}
.ps-tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px}
.ps-tile{border:1px solid var(--ui-stroke-secondary);border-radius:6px;padding:8px 10px;
  display:flex;flex-direction:column;gap:2px}
.ps-tile-k{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--ui-text-quaternary)}
.ps-tile-v{font-size:19px;line-height:23px;font-weight:600;color:var(--ui-text-primary)}
.ps-tile-n{font-size:11px;color:var(--ui-text-tertiary)}
.ps-tile[data-tone=warn]{border-color:color-mix(in srgb,var(--ui-accent) 45%,var(--ui-stroke-secondary))}
.ps-tile[data-tone=warn] .ps-tile-v{color:var(--ui-accent)}
.ps-sec{border:1px solid var(--ui-stroke-secondary);border-radius:6px;overflow:hidden}
.ps-sec-h{display:flex;flex-wrap:wrap;align-items:baseline;gap:8px;padding:7px 10px;
  border-bottom:1px solid var(--ui-stroke-secondary);background:color-mix(in srgb,var(--ui-text-primary) 3%,transparent)}
.ps-sec-t{font-size:12px;font-weight:600;color:var(--ui-text-primary)}
.ps-sec-s{font-size:11px;color:var(--ui-text-tertiary)}
.ps-sec-b{padding:10px;display:flex;flex-direction:column;gap:8px}
.ps-tbl{width:100%;border-collapse:collapse;font-size:11.5px}
.ps-tbl th{text-align:left;font-weight:600;color:var(--ui-text-quaternary);font-size:10px;
  text-transform:uppercase;letter-spacing:.06em;padding:4px 6px;border-bottom:1px solid var(--ui-stroke-secondary)}
.ps-tbl td{padding:4px 6px;border-bottom:1px solid color-mix(in srgb,var(--ui-stroke-secondary) 55%,transparent);
  color:var(--ui-text-secondary);vertical-align:top}
.ps-tbl tr:last-child td{border-bottom:none}
.ps-mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px}
.ps-row{border:1px solid var(--ui-stroke-secondary);border-radius:6px;padding:7px 9px;
  display:flex;flex-direction:column;gap:5px}
.ps-row-t{font-size:12.5px;color:var(--ui-text-primary)}
.ps-row-m{display:flex;flex-wrap:wrap;gap:4px 10px;font-size:11px;color:var(--ui-text-tertiary);align-items:center}
.ps-pill{display:inline-block;border:1px solid var(--ui-stroke-secondary);border-radius:999px;
  padding:1px 7px;font-size:10.5px;color:var(--ui-text-secondary);white-space:nowrap}
.ps-pill[data-tone=warn]{border-color:color-mix(in srgb,var(--ui-accent) 55%,var(--ui-stroke-secondary));color:var(--ui-accent)}
.ps-pill[data-tone=good]{border-color:color-mix(in srgb,var(--ui-accent) 30%,var(--ui-stroke-secondary));color:var(--ui-text-primary)}
.ps-pill[data-tone=mute]{opacity:.6}
.ps-id{border:1px dashed var(--ui-stroke-secondary);border-radius:4px;padding:0 5px;cursor:pointer;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:10.5px;color:var(--ui-text-tertiary)}
.ps-id:hover{border-color:var(--ui-accent);color:var(--ui-text-primary)}
.ps-cell{width:20px;height:16px;border-radius:3px;display:inline-block;border:1px solid var(--ui-stroke-secondary)}
.ps-cell[data-state=enabled]{background:color-mix(in srgb,var(--ui-accent) 62%,transparent);border-color:transparent}
.ps-cell[data-state=not_enabled]{background:color-mix(in srgb,var(--ui-text-quaternary) 26%,transparent);border-color:transparent}
.ps-cell[data-state=waived]{background:repeating-linear-gradient(45deg,color-mix(in srgb,var(--ui-text-quaternary) 40%,transparent) 0 4px,transparent 4px 8px)}
.ps-cell[data-state=excluded]{background:transparent;opacity:.35}
.ps-unm{border-left:2px solid color-mix(in srgb,var(--ui-accent) 40%,var(--ui-stroke-secondary));
  padding:4px 0 4px 8px;font-size:11px;line-height:1.45;color:var(--ui-text-tertiary);
  display:flex;flex-direction:column;gap:3px}
.ps-err{font-size:11.5px;color:var(--ui-accent);border:1px solid color-mix(in srgb,var(--ui-accent) 40%,var(--ui-stroke-secondary));
  border-radius:6px;padding:7px 9px;white-space:pre-wrap}
.ps-empty{font-size:11.5px;color:var(--ui-text-tertiary);padding:4px 0}
.ps-dot{width:7px;height:7px;border-radius:50%;display:inline-block;background:var(--ui-text-quaternary)}
.ps-dot[data-on=true]{background:var(--ui-accent)}
`

// ----------------------------------------------------------------------------- helpers

function words(v) {
  if (v === null || v === undefined || v === '') return 'unmeasured'
  if (typeof v === 'boolean') return v ? 'yes' : 'no'
  if (Array.isArray(v)) return v.length ? v.join(', ') : 'none'
  if (typeof v === 'object') return Object.keys(v).length ? JSON.stringify(v) : 'none'
  return String(v)
}

function num(v) {
  return typeof v === 'number' && isFinite(v) ? String(v) : 'unmeasured'
}

function age(sec) {
  if (typeof sec !== 'number' || !isFinite(sec) || sec < 0) return 'unmeasured'
  const s = Math.floor(sec)
  if (s < 60) return s + 's'
  const m = Math.floor(s / 60)
  if (m < 60) return m + 'm'
  const h = Math.floor(m / 60)
  if (h < 24) return h + 'h ' + (m % 60) + 'm'
  return Math.floor(h / 24) + 'd ' + (h % 24) + 'h'
}

/** A tenant's own hue, derived from its name — same idea as the web page's banner, so the two
 *  surfaces agree on which tenant is which. */
function hueOf(name) {
  let h = 0
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) % 360
  return h
}

function swatch(name) {
  return { background: 'hsl(' + hueOf(name) + ' 70% 55%)' }
}

function useJson(path, everyMs) {
  const q = useQuery({
    queryKey: [ID, path],
    queryFn: () => rest(path),
    staleTime: 10000,
    retry: 0,
    refetchInterval: everyMs || false
  })
  return q
}

function refreshAll() {
  void queryClient.invalidateQueries({ queryKey: [ID] })
}

// ----------------------------------------------------------------------------- atoms

function Pill(props) {
  return jsx('span', { className: 'ps-pill', 'data-tone': props.tone || null, title: props.title || null, children: props.children })
}

function Tile(props) {
  return jsxs('div', {
    className: 'ps-tile', 'data-tone': props.tone || null,
    children: [
      jsx('div', { className: 'ps-tile-k', children: props.k }),
      jsx('div', { className: 'ps-tile-v', children: props.v }),
      props.n ? jsx('div', { className: 'ps-tile-n', children: props.n }) : null
    ]
  })
}

function Sec(props) {
  return jsxs('div', {
    className: 'ps-sec',
    children: [
      jsxs('div', {
        className: 'ps-sec-h',
        children: [
          jsx('div', { className: 'ps-sec-t', children: props.title }),
          props.sub ? jsx('div', { className: 'ps-sec-s', children: props.sub }) : null,
          props.right ? jsx('div', { className: 'ps-spacer' }) : null,
          props.right || null
        ]
      }),
      jsx('div', { className: 'ps-sec-b', children: props.children })
    ]
  })
}

/** The contract's honesty rule, rendered: anything the backend could not measure is NAMED here,
 *  under its panel — never folded into a zero. */
function Unmeasured(props) {
  const list = (props.items || []).filter(Boolean)
  if (!list.length) return null
  return jsxs('div', {
    className: 'ps-unm',
    children: [
      jsx('div', { className: 'ps-pill', style: { alignSelf: 'flex-start' }, children: 'unmeasured' }),
      list.map((t, i) => jsx('div', { key: i, children: t }))
    ]
  })
}

function QErr(props) {
  const q = props.q
  if (!q || (!q.isError && !q.error)) return null
  const msg = q.error && q.error.message ? q.error.message : String(q.error || 'request failed')
  return jsx('div', { className: 'ps-err', children: props.what + ' failed: ' + msg })
}

function Loading(props) {
  if (!props.q || !props.q.isLoading) return null
  return jsx('div', { className: 'ps-empty', children: 'reading ' + props.what + '…' })
}

function IdChip(props) {
  const id = String(props.id || '')
  const [copied, setCopied] = useState(false)
  useEffect(() => { if (!copied) return; const t = setTimeout(() => setCopied(false), 1200); return () => clearTimeout(t) }, [copied])
  return jsx('span', {
    className: 'ps-id',
    title: 'click to copy the card id',
    onClick: () => { haptic('tap'); clipboard(id); setCopied(true) },
    children: copied ? 'copied' : id
  })
}

function KV(props) {
  const entries = useMemo(() => {
    const o = props.obj
    if (!o || typeof o !== 'object') return []
    return Object.keys(o)
      .filter(k => k !== 'unmeasured')
      .map(k => [k, o[k]])
  }, [props.obj])
  if (!entries.length) return jsx('span', { className: 'ps-sub', children: 'nothing measured' })
  return jsx('span', { children: entries.map((e, i) => jsx('span', { key: i, className: 'ps-sub', children: (i ? ' · ' : '') + e[0] + '=' + words(e[1]) })) })
}

// ----------------------------------------------------------------------------- tenant switcher

function TenantSwitcher(props) {
  const q = useJson('/tenants')
  const rows = (q.data && q.data.rows) || []
  const options = useMemo(() => ['all'].concat(rows.map(r => String(r.platform))), [q.data])
  return jsxs('div', {
    className: 'ps-banner',
    children: [
      jsxs('div', { children: [jsx('span', { className: 'ps-swatch', style: swatch(props.tenant) }), jsx('b', { children: props.tenant })] }),
      jsxs('div', {
        className: 'ps-switch',
        children: options.map(t => jsx('button', {
          key: t, type: 'button', className: 'ps-btn', 'data-on': String(props.tenant === t),
          onClick: () => { haptic('tap'); props.onPick(t) },
          children: t
        }))
      }),
      jsx('div', { className: 'ps-spacer' }),
      jsx('div', {
        className: 'ps-sub',
        children: q.isLoading ? 'reading tenants…'
          : q.isError ? 'tenant registry unreadable — switcher shows `all` only'
          : rows.length + ' registered tenant(s) + `all`; `_unattributed` is a ROW in the cross table, never a tenant'
      })
    ]
  })
}

// ----------------------------------------------------------------------------- panels

const CAP_TONE = { shipped: 'good', partial: 'warn', out_of_scope: 'warn' }

function CapabilityPanel() {
  const q = useJson('/capability', false)
  const d = q.data || {}
  const rows = d.rows || []
  return jsxs(Sec, {
    title: 'Capability floor — what this suite does, and what it does NOT do',
    sub: 'a recorded DECISION, not a measurement; estate-wide, so it does not re-scope with the tenant switcher',
    right: jsx('button', { type: 'button', className: 'ps-btn', onClick: refreshAll, children: 'refresh' }),
    children: [
      q.isError ? jsx('div', {
        className: 'ps-empty',
        children: 'the capability route is not mounted on this backend yet — that is NOT a claim that the '
          + 'capabilities exist; read the web dashboard for the recorded floor'
      }) : null,
      jsx(QErr, { q: q.isError ? null : q, what: '/capability' }),
      jsx(Loading, { q: q, what: '/capability' }),
      rows.length ? jsxs('div', {
        className: 'ps-tiles',
        children: [
          jsx(Tile, { k: 'out of scope', v: num(d.out_of_scope_count), n: 'never to be implied by any panel here', tone: d.out_of_scope_count ? 'warn' : null }),
          jsx(Tile, { k: 'partial', v: num(d.partial_count), n: 'stated as partial', tone: d.partial_count ? 'warn' : null }),
          jsx(Tile, { k: 'capabilities', v: num(d.count), n: 'in the recorded floor' }),
          jsx(Tile, { k: 'record', v: words(d.provenance), n: words(d.source) })
        ]
      }) : null,
      d.decision ? jsx('div', { className: 'ps-row', children: jsxs('div', {
        className: 'ps-row-m',
        children: [
          jsx(Pill, { tone: 'good', children: 'decision' }),
          jsx('span', { children: words(d.decision) }),
          jsx('span', { children: 'card ' + words(d.decision_card) })
        ]
      }) }) : null,
      rows.length ? jsx('div', {
        style: { display: 'flex', flexDirection: 'column', gap: '6px' },
        children: rows.map((r, i) => jsxs('div', {
          className: 'ps-row',
          children: [
            jsxs('div', {
              className: 'ps-row-m',
              children: [
                jsx(Pill, { tone: CAP_TONE[r.state] || null, children: words(r.state) }),
                jsx('span', { className: 'ps-mono', children: words(r.id) }),
                jsx('span', { children: words(r.capability) })
              ]
            }),
            r.promise ? jsx('div', { className: 'ps-row-t', children: words(r.promise) }) : null,
            r.statement ? jsx('div', { className: 'ps-sub', children: words(r.statement) }) : null
          ]
        }, i))
      }) : null,
      jsx(Unmeasured, { items: d.unmeasured })
    ]
  })
}

function LivenessPanel(props) {
  const q = useJson('/health?tenant=' + encodeURIComponent(props.tenant), 60000)
  const d = q.data || {}
  const feeds = d.feeds || []
  const tenants = d.tenants || []
  return jsxs(Sec, {
    title: 'Liveness — is the instrument ON',
    sub: 'tenant=' + props.tenant,
    right: jsx('button', { type: 'button', className: 'ps-btn', onClick: refreshAll, children: 'refresh' }),
    children: [
      jsxs('div', {
        className: 'ps-tiles',
        children: [
          jsx(Tile, { k: 'feeds alive', v: num(d.feeds_alive), n: 'of ' + num(d.feeds_probed) + ' probed' }),
          jsx(Tile, { k: 'tenants in scope', v: num(tenants.length), n: 'rows below' }),
          jsx(Tile, { k: 'lake', v: words(d.lake && d.lake.provenance), n: words(d.lake && d.lake.root) }),
          jsx(Tile, { k: 'as of', v: d.as_of ? String(d.as_of).slice(11, 19) : 'unmeasured', n: d.as_of ? String(d.as_of).slice(0, 10) : null })
        ]
      }),
      jsx(QErr, { q: q, what: '/health' }),
      jsx(Loading, { q: q, what: '/health' }),
      feeds.length ? jsxs('table', {
        className: 'ps-tbl',
        children: [
          jsx('thead', { children: jsxs('tr', { children: ['feed', 'alive', 'rows', 'last event', 'last ingest', 'assets', 'error', 'schema'].map(h => jsx('th', { key: h, children: h })) }) }),
          jsx('tbody', { children: feeds.map((f, i) => jsxs('tr', {
            children: [
              jsx('td', { children: jsx('span', { children: [jsx('span', { className: 'ps-dot', 'data-on': String(!!f.alive) }), ' ' + words(f.name)] }) }),
              jsx('td', { children: words(f.alive) }),
              jsx('td', { children: num(f.rows) }),
              jsx('td', { children: f.last_event ? String(f.last_event) : 'unmeasured' }),
              jsx('td', { children: f.last_ingest ? String(f.last_ingest) : 'unmeasured' }),
              jsx('td', { children: num(f.assets_seen) }),
              jsx('td', { children: f.error ? jsx(Pill, { tone: 'warn', children: String(f.error) }) : '—' }),
              jsx('td', { children: words(f.schema) })
            ]
          }, i)) })
        ]
      }) : jsx('div', { className: 'ps-empty', children: 'no feed returned a row — read the unmeasured list, not a 0' }),
      tenants.length ? jsxs('table', {
        className: 'ps-tbl',
        children: [
          jsx('thead', { children: jsxs('tr', { children: ['tenant', 'status', 'maturity', 'sources declared', 'rules enabled', 'rules total', 'streams present'].map(h => jsx('th', { key: h, children: h })) }) }),
          jsx('tbody', { children: tenants.map((t, i) => jsxs('tr', {
            children: [
              jsx('td', { children: words(t.platform) }),
              jsx('td', { children: words(t.status) }),
              jsx('td', { children: words(t.maturity) }),
              jsx('td', { children: num(t.sources_declared_count) }),
              jsx('td', { children: num(t.rules_enabled) }),
              jsx('td', { children: num(t.rules_total) }),
              jsx('td', { children: words(t.streams_present) })
            ]
          }, i)) })
        ]
      }) : null,
      jsx(Unmeasured, { items: d.unmeasured })
    ]
  })
}

const LIFECYCLE_ORDER = ['new', 'triaging', 'contained', 'false_positive', 'resolved']
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']

function FindingsPanel(props) {
  const [state, setState] = useState('')
  const [sort, setSort] = useState('created_at')
  const path = '/findings?tenant=' + encodeURIComponent(props.tenant)
    + '&sort=' + encodeURIComponent(sort)
    + (state ? '&state=' + encodeURIComponent(state) : '')
  const q = useJson(path, 60000)
  const d = q.data || {}
  const rows = d.rows || []
  const counts = d.lifecycle_counts || {}
  const vocab = (d.lifecycle_vocab || LIFECYCLE_ORDER)
  return jsxs(Sec, {
    title: 'Finding queue — the SOC lifecycle',
    sub: d.scope_predicate || ('tenant=' + props.tenant),
    right: jsxs('div', {
      className: 'ps-bar',
      children: [
        jsx('span', { className: 'ps-sub', children: 'sort' }),
        ['created_at', 'age', 'severity', 'lifecycle'].map(s => jsx('button', {
          key: s, type: 'button', className: 'ps-btn', 'data-on': String(sort === s),
          onClick: () => { haptic('tap'); setSort(s) }, children: s
        })),
        jsx('button', { type: 'button', className: 'ps-btn', onClick: refreshAll, children: 'refresh' })
      ]
    }),
    children: [
      jsxs('div', {
        className: 'ps-bar',
        children: [
          jsx('button', { type: 'button', className: 'ps-btn', 'data-on': String(state === ''), onClick: () => { haptic('tap'); setState('') }, children: 'all states' }),
          vocab.map(s => jsx('button', {
            key: s, type: 'button', className: 'ps-btn', 'data-on': String(state === s),
            onClick: () => { haptic('tap'); setState(s) }, children: s + ' (' + num(counts[s] || 0) + ')'
          }))
        ]
      }),
      jsxs('div', {
        className: 'ps-tiles',
        children: [
          jsx(Tile, { k: 'rows returned', v: num(d.count), n: 'cap ' + num(d.cap) + (d.cap_hit ? ' — CAP HIT' : ''), tone: d.cap_hit ? 'warn' : null }),
          jsx(Tile, { k: 'in scope', v: num(d.in_scope_total), n: 'tenant + state filter' }),
          jsx(Tile, { k: 'population read', v: num(d.population_total), n: 'every finding on every board' }),
          jsx(Tile, { k: 'needs human', v: num(counts.unrecognised_status), n: 'unrecognised card status', tone: counts.unrecognised_status ? 'warn' : null })
        ]
      }),
      jsx(QErr, { q: q, what: '/findings' }),
      jsx(Loading, { q: q, what: '/findings' }),
      rows.length ? jsx('div', {
        style: { display: 'flex', flexDirection: 'column', gap: '6px' },
        children: rows.map(r => jsxs('div', {
          className: 'ps-row',
          children: [
            jsxs('div', {
              className: 'ps-row-m',
              children: [
                jsx(IdChip, { id: r.id }),
                jsx(Pill, { tone: SEV_ORDER.indexOf(r.severity) <= 1 && SEV_ORDER.indexOf(r.severity) >= 0 ? 'warn' : null, children: words(r.severity) }),
                jsx(Pill, { children: words(r.lifecycle) }),
                r.stale ? jsx(Pill, { tone: 'warn', children: 'stale' }) : null,
                jsx('span', { children: 'age ' + age(r.age_seconds) }),
                jsx('span', { children: 'board ' + words(r.board) }),
                jsx('span', { children: 'assignee ' + words(r.assignee) }),
                jsx('span', { children: 'filed by ' + words(r.filed_by) })
              ]
            }),
            jsx('div', { className: 'ps-row-t', children: words(r.title) }),
            jsxs('div', {
              className: 'ps-row-m',
              children: [
                jsx('span', { children: 'rule ' + words(r.rule_id) }),
                jsx('span', { children: 'subject ' + words(r.subject) }),
                jsx('span', { children: 'device ' + words(r.device_id) }),
                jsx('span', { children: 'disposition ' + words(r.disposition) }),
                jsx('span', { children: 'MTTR ' + (r.mttr_seconds === null || r.mttr_seconds === undefined ? 'unmeasured' : age(r.mttr_seconds)) })
              ]
            }),
            r.detail ? jsx('div', { className: 'ps-sub', children: words(r.detail) }) : null
          ]
        }, r.board + ':' + r.id))
      }) : jsx('div', { className: 'ps-empty', children: q.isLoading ? 'reading…' : 'no finding in this scope — an empty scope, not an empty estate (see population and unmeasured)' }),
      jsx(Unmeasured, { items: d.unmeasured })
    ]
  })
}

function CrossPanel() {
  const q = useJson('/cross', 60000)
  const d = q.data || {}
  const rows = d.rows || []
  const all = d.all || null
  return jsxs(Sec, {
    title: 'Across tenants',
    sub: 'one row per tenant, plus _unattributed and all — all is its OWN aggregate, so all != sum(rows) is visible',
    right: jsx('button', { type: 'button', className: 'ps-btn', onClick: refreshAll, children: 'refresh' }),
    children: [
      jsxs('div', {
        className: 'ps-tiles',
        children: [
          jsx(Tile, { k: 'all (open)', v: num(d.all_open), n: 'whole population' }),
          jsx(Tile, { k: 'sum of rows', v: num(d.sum_of_rows_open), n: 'includes _unattributed' }),
          jsx(Tile, { k: 'tenant rows only', v: num(d.sum_of_tenant_open), n: '_unattributed kept out, never folded in' }),
          jsx(Tile, {
            k: 'capped', v: d.capped === false ? 'no' : words(d.capped), n: 'population ' + num(d.population_total),
            tone: d.capped === false ? null : 'warn'
          })
        ]
      }),
      jsx(QErr, { q: q, what: '/cross' }),
      jsx(Loading, { q: q, what: '/cross' }),
      rows.length || all ? jsxs('table', {
        className: 'ps-tbl',
        children: [
          jsx('thead', { children: jsxs('tr', { children: ['tenant', 'open', 'needs human', 'oldest open', 'resolved', 'unrecognised'].map(h => jsx('th', { key: h, children: h })) }) }),
          jsx('tbody', {
            children: rows.map((r, i) => jsxs('tr', {
              children: [
                jsx('td', { children: jsx(Pill, { tone: r.platform === '_unattributed' ? 'warn' : (r.is_tenant ? null : 'good'), children: words(r.platform) }) }),
                jsx('td', { children: num(r.open) }),
                jsx('td', { children: num(r.needs_human) }),
                jsx('td', { children: r.oldest_open_age_seconds === null || r.oldest_open_age_seconds === undefined ? 'unmeasured' : age(r.oldest_open_age_seconds) }),
                jsx('td', { children: num(r.resolved) }),
                jsx('td', { children: num(r.unrecognised_status) })
              ]
            }, i))
          })
        ]
      }) : jsx('div', { className: 'ps-empty', children: q.isLoading ? 'reading…' : 'no row — see unmeasured' }),
      all ? jsxs('div', {
        className: 'ps-row',
        children: [
          jsxs('div', {
            className: 'ps-row-m',
            children: [
              jsx(Pill, { tone: 'good', children: 'all' }),
              jsx('span', { children: 'open ' + num(all.open) }),
              jsx('span', { children: 'needs human ' + num(all.needs_human) }),
              jsx('span', { children: 'resolved ' + num(all.resolved) }),
              jsx('span', { children: 'oldest open ' + (all.oldest_open_age_seconds === null || all.oldest_open_age_seconds === undefined ? 'unmeasured' : age(all.oldest_open_age_seconds)) }),
              jsx('span', { children: 'all_equals_sum ' + words(d.all_equals_sum) }),
              jsx('span', { children: 'tenant_rows_equal_all ' + words(d.tenant_rows_equal_all) })
            ]
          }),
          jsx('div', { className: 'ps-sub', children: words(all.display_name) })
        ]
      }) : null,
      jsx(Unmeasured, { items: d.unmeasured })
    ]
  })
}

function CoveragePanel(props) {
  const q = useJson('/coverage?tenant=' + encodeURIComponent(props.tenant), 120000)
  const d = q.data || {}
  const rows = d.rows || []
  const cols = useMemo(() => {
    const seen = []
    rows.forEach(r => (r.cells || []).forEach(c => { if (seen.indexOf(String(c.platform)) === -1) seen.push(String(c.platform)) }))
    return seen
  }, [d.rows])
  const declaredOnly = d.declared_only || {}
  return jsxs(Sec, {
    title: 'Coverage matrix — detections × tenants',
    sub: (d.rules_total !== undefined ? d.rules_total + ' rules · ' + d.tenants_total + ' tenant(s)' : 'reading…')
      + ' · coverage is a CLAIM; what is measured here is scope, enablement, maturity and waivers',
    right: jsx('button', { type: 'button', className: 'ps-btn', onClick: refreshAll, children: 'refresh' }),
    children: [
      jsxs('div', {
        className: 'ps-tiles',
        children: [
          jsx(Tile, { k: 'rules', v: num(d.rules_total), n: 'in the catalog' }),
          jsx(Tile, { k: 'tenants', v: num(d.tenants_total), n: 'in scope' }),
          jsx(Tile, { k: 'shadowed rules', v: num(d.shadowed_rules_total), n: 'one index shadowing another', tone: d.shadowed_rules_total ? 'warn' : null }),
          jsx(Tile, { k: 'declared-not-in-catalog', v: num(Object.keys(declaredOnly).length), n: 'tenant(s) enabling a rule the catalog lacks', tone: Object.keys(declaredOnly).length ? 'warn' : null })
        ]
      }),
      jsx(QErr, { q: q, what: '/coverage' }),
      jsx(Loading, { q: q, what: '/coverage' }),
      cols.length ? jsxs('table', {
        className: 'ps-tbl',
        children: [
          jsx('thead', { children: jsxs('tr', { children: ['rule', 'severity', 'stream', 'maturity'].concat(cols).map((h, i) => jsx('th', { key: h + i, children: h })) }) }),
          jsx('tbody', { children: rows.map((r, i) => {
            const by = {}
            ;(r.cells || []).forEach(c => { by[String(c.platform)] = c })
            return jsxs('tr', {
              children: [
                jsx('td', { children: jsxs('span', { children: [jsx('span', { className: 'ps-mono', children: words(r.rule) }), jsx('div', { className: 'ps-sub', children: words(r.title) })] }) }),
                jsx('td', { children: jsx(Pill, { tone: SEV_ORDER.indexOf(r.severity) <= 1 && SEV_ORDER.indexOf(r.severity) >= 0 ? 'warn' : null, children: words(r.severity) }) }),
                jsx('td', { children: words(r.stream) }),
                jsx('td', { children: words(r.maturity) })
              ].concat(cols.map(c => {
                const cell = by[c]
                return jsx('td', {
                  key: 'c' + c,
                  title: c + ': ' + (cell ? cell.state : 'not in scope') + (cell && cell.waiver ? ' (waiver)' : ''),
                  children: jsx('span', { className: 'ps-cell', 'data-state': cell ? cell.state : 'excluded' })
                })
              }))
            }, i)
          }) })
        ]
      }) : jsx('div', { className: 'ps-empty', children: q.isLoading ? 'reading…' : 'no rule in the catalog — see unmeasured' }),
      jsxs('div', {
        className: 'ps-row-m',
        children: [
          jsx(Pill, { children: 'enabled' }), jsx('span', { className: 'ps-cell', 'data-state': 'enabled' }),
          jsx(Pill, { children: 'not enabled' }), jsx('span', { className: 'ps-cell', 'data-state': 'not_enabled' }),
          jsx(Pill, { children: 'waived' }), jsx('span', { className: 'ps-cell', 'data-state': 'waived' }),
          jsx(Pill, { children: 'out of scope' }), jsx('span', { className: 'ps-cell', 'data-state': 'excluded' })
        ]
      }),
      Object.keys(declaredOnly).length ? jsx('div', {
        className: 'ps-unm',
        children: Object.keys(declaredOnly).map(k => jsx('div', { key: k, children: k + ' enables ' + declaredOnly[k].length + ' detection(s) the catalog does not carry: ' + declaredOnly[k].join(', ') }))
      }) : null,
      jsx(Unmeasured, { items: d.unmeasured })
    ]
  })
}

function RetirementPanel() {
  const q = useJson('/retirement', 120000)
  const d = q.data || {}
  const items = d.items || []
  return jsxs(Sec, {
    title: 'Retirement board — Sentinel / Defender exit',
    sub: 'nothing is cut until proven: an item without a shadow proof renders `unproven`, never green',
    right: jsx('button', { type: 'button', className: 'ps-btn', onClick: refreshAll, children: 'refresh' }),
    children: [
      jsxs('div', {
        className: 'ps-tiles',
        children: [
          jsx(Tile, { k: 'items proven', v: num(d.items_proven), n: 'of ' + num(d.items_total) }),
          jsx(Tile, { k: 'gate artifact', v: d.gate_source ? 'present' : 'absent', n: d.gate_source ? '' : 'every item renders `unproven`', tone: d.gate_source ? null : 'warn' }),
          jsx(Tile, { k: 'posture', v: words(d.posture_provenance), n: words(d.posture_source) })
        ]
      }),
      jsx(QErr, { q: q, what: '/retirement' }),
      jsx(Loading, { q: q, what: '/retirement' }),
      items.length ? jsx('div', {
        style: { display: 'flex', flexDirection: 'column', gap: '6px' },
        children: items.map((it, i) => {
          const proof = it.proof || {}
          const tone = proof.state === 'green' ? 'good' : 'warn'
          return jsxs('div', {
            className: 'ps-row',
            children: [
              jsxs('div', {
                className: 'ps-row-m',
                children: [
                  jsx(Pill, { tone, children: words(proof.state || 'unproven') }),
                  jsx('span', { className: 'ps-mono', children: words(it.id) }),
                  jsx('span', { children: 'board ' + words(it.board) }),
                  proof.key ? jsx('span', { children: 'proof key ' + words(proof.key) }) : null
                ]
              }),
              jsx('div', { className: 'ps-row-t', children: words(it.item) }),
              jsx('div', { className: 'ps-row-m', children: jsx(KV, { obj: it.measured }) }),
              proof.evidence ? jsx('div', { className: 'ps-sub', children: 'evidence: ' + words(proof.evidence) }) : null
            ]
          }, i)
        })
      }) : jsx('div', { className: 'ps-empty', children: q.isLoading ? 'reading…' : 'no exit item — see unmeasured' }),
      jsx('div', { className: 'ps-sub', children: 'owner spend card: ' }),
      jsx('div', { className: 'ps-row-m', children: jsx(KV, { obj: d.owner_spend_card }) }),
      jsxs('div', {
        className: 'ps-row-m',
        children: [
          jsx('span', { children: 'sentinel measured: ' }),
          jsx(KV, { obj: d.sentinel }),
          jsx('span', { children: ' · defender measured: ' }),
          jsx(KV, { obj: d.defender })
        ]
      }),
      jsx(Unmeasured, { items: d.unmeasured })
    ]
  })
}

function ProvenancePanel() {
  const q = useJson('/meta', 120000)
  const d = q.data || {}
  return jsxs(Sec, {
    title: 'Provenance — what every other panel is reading',
    sub: 'a source that could not be read is named, never rendered as a zero',
    right: jsx('button', { type: 'button', className: 'ps-btn', onClick: refreshAll, children: 'refresh' }),
    children: [
      jsx(QErr, { q: q, what: '/meta' }),
      jsx(Loading, { q: q, what: '/meta' }),
      jsxs('table', {
        className: 'ps-tbl',
        children: [
          jsx('thead', { children: jsxs('tr', { children: ['source', 'provenance', 'path / root', 'counts'].map(h => jsx('th', { key: h, children: h })) }) }),
          jsx('tbody', {
            children: ['registry', 'detections', 'lake', 'retirement'].map(k => {
              const s = d[k] || {}
              return jsxs('tr', {
                children: [
                  jsx('td', { children: k }),
                  jsx('td', { children: jsx(Pill, { tone: s.provenance && String(s.provenance).indexOf('live') >= 0 ? 'good' : null, children: words(s.provenance) }) }),
                  jsx('td', { className: 'ps-mono', children: words(s.path || s.root) }),
                  jsx('td', { children: words(s.tenants !== undefined ? s.tenants + ' tenants'
                    : s.rules !== undefined ? s.rules + ' rules'
                    : s.feeds !== undefined ? s.feeds + ' feeds' : null) })
                ]
              }, k)
            })
          })
        ]
      }),
      jsxs('div', { className: 'ps-row-m', children: [jsx('span', { children: 'boards scanned: ' }), jsx('span', { className: 'ps-mono', children: words(d.boards) }), jsx('span', { children: ' · as of ' + words(d.as_of) })] }),
      jsx(Unmeasured, { items: d.unmeasured })
    ]
  })
}

// ----------------------------------------------------------------------------- page

function SuitePage() {
  const [tenant, setTenant] = useState('all')

  useEffect(() => {
    if (!document.getElementById('ps-css')) {
      const el = document.createElement('style')
      el.id = 'ps-css'
      el.textContent = CSS
      document.head.appendChild(el)
    }
  }, [])

  return jsxs('div', {
    className: 'ps-page',
    children: [
      jsxs('div', {
        className: 'ps-bar',
        children: [
          jsx('div', { className: 'ps-h1', children: 'Protection Suite' }),
          jsx('div', {
            className: 'ps-sub',
            children: 'tenant switcher · coverage matrix · finding queue · retirement board — reads the registry, the '
              + 'catalog, the boards and the lake; every panel names what it could not measure'
          }),
          jsx('div', { className: 'ps-spacer' }),
          jsx('button', { type: 'button', className: 'ps-btn', onClick: () => { haptic('tap'); refreshAll() }, children: 'refresh all' })
        ]
      }),
      jsx(TenantSwitcher, { tenant, onPick: setTenant }),
      jsx(CapabilityPanel, {}),
      jsx(LivenessPanel, { tenant }),
      jsx(FindingsPanel, { tenant }),
      jsx(CrossPanel, {}),
      jsx(CoveragePanel, { tenant }),
      jsx(RetirementPanel, {}),
      jsx(ProvenancePanel, {})
    ]
  })
}

function SuiteChip() {
  const q = useJson('/cross', 60000)
  const d = q.data || {}
  const open = d.all_open
  const tone = typeof open === 'number' && open > 0 ? 'warn' : null
  return jsx('button', {
    type: 'button',
    className: 'ps-btn',
    'data-on': String(tone === 'warn'),
    title: q.isError ? 'cross-tenant read failed' : 'open findings across the whole population',
    onClick: () => { haptic('tap'); host.navigate(PAGE) },
    children: 'shield ' + (q.isLoading ? '…' : q.isError ? '?' : num(open))
  })
}

export default {
  id: ID,
  name: 'Protection Suite',
  description: 'The multi-tenant security operator surface: tenant switcher with per-tenant liveness, the detection coverage matrix, the finding queue with the SOC lifecycle, the Sentinel/Defender retirement board and cross-tenant counts.',
  defaultEnabled: true,
  register(ctx) {
    rest = (path, opts) => ctx.rest(path, opts)
    clipboard = text => ctx.os.writeClipboard(String(text))

    ctx.registerMany([
      { id: 'page', area: ROUTES_AREA, data: { path: PAGE }, render: () => jsx(SuitePage, {}) },
      { id: 'nav', area: SIDEBAR_NAV_AREA, data: { path: PAGE, label: 'Protection Suite', codicon: 'shield' } },
      { id: 'chip', area: STATUSBAR_AREAS.right, order: 121, render: () => jsx(SuiteChip, {}) },
      {
        id: 'open', area: PALETTE_AREA,
        data: {
          id: 'protection-suite.open', label: 'Protection Suite: open',
          keywords: ['protection', 'suite', 'psec', 'tenants', 'findings', 'coverage', 'sentinel', 'defender'],
          run: () => host.navigate(PAGE)
        }
      },
      {
        id: 'bind', area: KEYBINDS_AREA,
        data: {
          id: 'protection-suite.open', label: 'Open Protection Suite',
          category: 'Protection Suite', defaults: ['mod+shift+s'], run: () => host.navigate(PAGE)
        }
      }
    ])
  }
}
