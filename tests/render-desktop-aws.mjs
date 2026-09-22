#!/usr/bin/env node
/**
 * Render the DESKTOP half's AWS control-plane panel and assert the never-a-bare-zero rule.
 *
 * WHY THIS EXISTS. `desktop/plugin.js` loads uncompiled in the Electron renderer, so `node --check`
 * can only tell that it PARSES; neither it nor a Python test can tell whether the panel RENDERS
 * correctly. The rules that matter here are render rules ("no path renders a bare zero", "an
 * unmeasurable probe renders UNMEASURABLE:<reason>"), so this harness executes the component and
 * reads its output.
 *
 * HOW. The plugin's only imports are `@hermes/plugin-sdk`, `react` and `react/jsx-runtime`; those
 * stand up as minimal stubs in a temp dir, and a COPY of `desktop/plugin.js` is imported from there
 * (copying keeps node_modules out of the plugin repo; the copy's sha256 is printed so the file under
 * test is identifiable). The stubs are a ~40-line mini renderer: `jsx`/`jsxs` build plain elements,
 * `useState` gets real slots and function components are expanded — so the page renders, the tenant
 * switch is actually pressed, and the panel re-renders on the new scope. The panel is reached the
 * way the renderer reaches it: through the contribution `register()` puts in ROUTES_AREA, not by
 * importing an internal.
 *
 * The never-a-bare-zero rule is checked STRUCTURALLY: the ingestion cell of every surface row and
 * the account lake line are located in the tree and compared, character for character, against the
 * one allowed rendering of that count. The API's own finding prose is not part of that comparison —
 * a rule that fired on the backend's sentences would be a rule about the backend.
 *
 * USAGE
 *   node tests/render-desktop-aws.mjs                        # synthetic arms only
 *   node tests/render-desktop-aws.mjs <live-aws-panel.json>  # plus the LIVE /aws payload
 *
 * The synthetic arms always run (they are the RULES, not the account): a measured 0, an unread lake,
 * a refused probe, and a `present_no_ingest` account. The live payload is the acceptance evidence
 * for "renders the real state for onestack".
 */
import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const REPO = resolve(HERE, '..')
const HALF = join(REPO, 'desktop', 'plugin.js')
const TENANT = 'onestack'

// ------------------------------------------------------- stubs for the three importable specifiers

const JSXRUNTIME = `
export function jsx(type, props) { return { __el: true, type, props: props || {} } }
export const jsxs = jsx
export function Fragment(props) { return props.children }
`
const SDK = `
export const KEYBINDS_AREA = 'keybinds', PALETTE_AREA = 'palette', ROUTES_AREA = 'routes'
export const SIDEBAR_NAV_AREA = 'sidebar', STATUSBAR_AREAS = { right: 'statusbar.right' }
export const haptic = () => {}
export const host = { navigate: () => {} }
export const queryClient = { invalidateQueries: () => {} }
// The page's data, keyed by the exact path the component asks for; every path asked for is recorded.
export const useQuery = (opts) => globalThis.__PS_DATA__[opts.queryKey[1]]()
`
const REACT = `
export const useState = (init) => {
  const H = globalThis.__PS_HOOKS__
  const i = H.cur++
  if (!(i in H.slots)) H.slots[i] = init
  return [H.slots[i], (v) => { H.slots[i] = (typeof v === 'function' ? v(H.slots[i]) : v); H.dirty = true }]
}
export const useEffect = () => {}
export const useMemo = (fn) => fn()
export const useCallback = (fn) => fn
`

function loadHalf() {
  const dir = mkdtempSync(join(tmpdir(), 'ps-desktop-render-'))
  const nm = join(dir, 'node_modules')
  mkdirSync(join(nm, '@hermes', 'plugin-sdk'), { recursive: true })
  mkdirSync(join(nm, 'react'), { recursive: true })
  writeFileSync(join(dir, 'package.json'), '{"type":"module"}\n')
  writeFileSync(join(nm, 'react', 'package.json'),
    '{"name":"react","type":"module","exports":{".":"./index.mjs","./jsx-runtime":"./jsx-runtime.mjs"}}\n')
  writeFileSync(join(nm, 'react', 'index.mjs'), REACT)
  writeFileSync(join(nm, 'react', 'jsx-runtime.mjs'), JSXRUNTIME)
  writeFileSync(join(nm, '@hermes', 'plugin-sdk', 'package.json'),
    '{"name":"@hermes/plugin-sdk","type":"module","main":"index.mjs"}\n')
  writeFileSync(join(nm, '@hermes', 'plugin-sdk', 'index.mjs'), SDK)
  const copy = join(dir, 'plugin.js')
  writeFileSync(copy, readFileSync(HALF))
  return { dir, copy, sha: createHash('sha256').update(readFileSync(copy)).digest('hex') }
}

// ------------------------------------------------------------------------- the mini renderer

/** Expand an element tree into the list of elements actually rendered, invoking function
 *  components (the page is one component element until something renders it). */
function expand(el, out) {
  if (el === null || el === undefined || typeof el === 'boolean') return
  if (Array.isArray(el)) { el.forEach(e => expand(e, out)); return }
  if (typeof el === 'object' && el.__el) {
    out.push(el)
    expand(typeof el.type === 'function' ? el.type(el.props) : (el.props && el.props.children), out)
    return
  }
  if (typeof el === 'function') expand(el({}), out)
}

function text(el) {
  if (el === null || el === undefined || typeof el === 'boolean') return ''
  if (typeof el === 'string' || typeof el === 'number') return String(el)
  if (Array.isArray(el)) return el.map(text).join('')
  if (typeof el === 'object' && el.__el) {
    return typeof el.type === 'function' ? text(el.type(el.props)) : text(el.props.children)
  }
  return ''
}

/** The ingestion cell of a surface row: the 4th <td> of a 5-cell row whose 3rd cell is the probe
 *  call list. Located by SHAPE, so no marker has to be added to the panel for the test's benefit. */
function ingestionCells(nodes) {
  const out = []
  nodes.forEach(n => {
    if (n.type !== 'tr') return
    const tds = (n.props.children || []).filter(c => c && c.__el && c.type === 'td')
    if (tds.length !== 5) return
    if (!/:(Describe|List|Get)/.test(text(tds[2]))) return
    out.push(text(tds[3]))
  })
  return out
}

/** The account-level lake line: a `ps-sub` whose text opens with the lake producer. */
function lakeLines(nodes) {
  return nodes.filter(n => n.props && n.props.className === 'ps-sub'
    && text(n).indexOf('lake: producer=') === 0).map(text)
}

const SEC_TITLE = 'AWS control plane'

async function renderAws(payload) {
  const { dir, copy, sha } = await loadHalf()
  try {
    const mod = await import(pathToFileURL(copy).href + '?v=' + Date.now())
    const contributions = []
    mod.default.register({
      rest: () => Promise.resolve({}),
      os: { writeClipboard: () => {} },
      registerMany: list => contributions.push(...list)
    })
    const route = contributions.filter(c => c.id === 'page')[0]
    if (!route) throw new Error('no `page` contribution registered')

    const asked = []
    const serve = (data) => () => ({ data, isLoading: false, isError: false, error: null })
    globalThis.__PS_DATA__ = new Proxy({
      '/tenants': serve({ rows: [{ platform: TENANT, display_name: 'One Stack', status: 'active', maturity: 'enforcing' }] }),
      ['/aws?tenant=' + TENANT]: serve(payload)
    }, {
      get(target, prop) {
        asked.push(String(prop))
        return target[prop] || serve({})
      }
    })

    let slots = []
    let nodes = []
    for (let pass = 0; pass < 4; pass++) {
      const H = globalThis.__PS_HOOKS__ = { slots, cur: 0, dirty: false }
      nodes = []
      expand(route.render(), nodes)
      slots = H.slots
      if (pass === 0) {
        // Press the tenant switch, as the operator would: the page opens on `all` on purpose.
        const btn = nodes.filter(n => n.type === 'button' && n.props && n.props.children === TENANT
          && typeof n.props.onClick === 'function')[0]
        if (!btn) throw new Error('the tenant switcher offered no button for ' + TENANT)
        btn.props.onClick()
        continue
      }
      if (!H.dirty) break
    }
    const sec = nodes.filter(n => n.props && typeof n.props.title === 'string'
      && n.props.title.indexOf(SEC_TITLE) === 0)[0]
    const sectionNodes = []
    if (sec) expand(sec, sectionNodes)
    return {
      sha, section: sec ? text(sec) : null,
      ingestions: sec ? ingestionCells(sectionNodes) : [],
      lakeLines: sec ? lakeLines(sectionNodes) : [],
      ids: contributions.map(c => c.id), asked
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

// ------------------------------------------------------------------------------ assertions

let failures = 0
function check(name, ok, detail) {
  console.log((ok ? '  PASS  ' : '  FAIL  ') + name + (ok || detail === undefined ? '' : '  -> ' + detail))
  if (!ok) failures++
}

/** The one allowed rendering of a lake count — the rule, restated as a function. */
function countText(rows, reason, lastEvent) {
  if (rows === null || rows === undefined) return 'unmeasured' + (reason ? ' (' + reason + ')' : '')
  if (rows === 0) return '0 rows — silent'
  const m = String(lastEvent || '').match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})/)
  return String(rows) + ' rows' + (lastEvent ? ' · last ' + (m ? m[2] + '-' + m[3] + ' ' + m[4] + ':' + m[5] : lastEvent) : '')
}

const surface = (over) => Object.assign({
  id: 'cloudtrail', surface: 'CloudTrail trails — the control-plane record',
  probe_calls: ['cloudtrail:DescribeTrails(includeShadowTrails=True)', 'cloudtrail:GetTrailStatus'],
  state: 'enabled_producing', state_label: 'enabled and producing', present: true,
  regions_present: ['us-east-1'], regions_empty: [], regions_error: null,
  lake_producer: 'aws-cloudtrail', lake_source: 'cloud_audit',
  lake_rows: 10, lake_last_event: '2026-09-20 07:16:27', lake_reason: null,
  finding: 'trail(s) jpthegeek-multiregion present', details: {}, unmeasured: []
}, over)

const account = (over) => Object.assign({
  platform: TENANT,
  declared: { cloud: 'aws', account: '912632857388', account_verified: true,
    credential_ref: 'secret://env/AWS_PROTECTION_AUDIT_ACCESS_KEY_ID',
    sources: ['cloudtrail_lookup_events'], access: 'read-only' },
  identity: { account: '912632857388', arn: 'arn:aws:iam::912632857388:user/hermes-protection-audit' },
  probe: { status: 'ok', reason: null, calls: [], credential_source: '/home/hermes/.hermes/.secrets/onestack/aws/estate.json',
    cache: { cached: false, age_seconds: 0, ttl_seconds: 300, duration_s: 30.6 },
    timeout_s: 90, ttl_s: 300, regions_probed: ['us-east-1', 'eu-west-1'], iam_users: 69 },
  lake: { root: '/mnt/ohscratch/logs/platform-security', producer: 'aws-cloudtrail', source: 'cloud_audit',
    rows: 3067, last_event: '2026-09-20 07:16:27', ok: true, reason: null },
  state: 'enabled_producing', state_label: 'enabled and producing', reason: null,
  surfaces: [surface({})], unmeasured: []
}, over)

const panel = (accounts, over) => Object.assign({
  as_of: '2026-09-20T07:29:38Z', tenant: TENANT, accounts, count: accounts.length,
  state: 'enabled_producing', state_label: 'enabled and producing', reason: null,
  probe_calls: ['cloudtrail:DescribeTrails(includeShadowTrails=True)', 'cloudtrail:GetTrailStatus',
    'guardduty:ListDetectors', 'securityhub:DescribeHub', 'iam:GetAccountPasswordPolicy'],
  lake_root: '/mnt/ohscratch/logs/platform-security', unmeasured: []
}, over)

const ARMS = [
  ['measured 0 rows', panel([account({
    state: 'enabled_silent', state_label: 'enabled but silent',
    lake: { root: '/lake', producer: 'aws-cloudtrail', source: 'cloud_audit', rows: 0, ok: true, reason: null },
    surfaces: [surface({ state: 'enabled_silent', state_label: 'enabled but silent', lake_rows: 0,
      finding: 'trail present; the source ran and landed nothing' })]
  })]), ['enabled but silent', '0 rows — silent']],

  ['unread lake', panel([account({
    state: 'unmeasurable', state_label: 'UNMEASURABLE',
    lake: { root: '/lake', producer: 'aws-cloudtrail', source: 'cloud_audit', rows: null, ok: false,
      reason: 'no lake interpreter (duckdb lives in /home/hermes/.lakevenv)' },
    surfaces: [surface({ state: 'unmeasurable', state_label: 'UNMEASURABLE', lake_rows: null,
      lake_reason: 'no lake interpreter (duckdb lives in /home/hermes/.lakevenv)' })]
  })]), ['UNMEASURABLE', 'unmeasured (no lake interpreter (duckdb lives in /home/hermes/.lakevenv))']],

  ['refused probe', panel([account({
    state: 'unmeasurable', state_label: 'UNMEASURABLE', identity: null,
    probe: { status: 'unmeasurable', reason: 'AccessDenied: not authorized to perform cloudtrail:DescribeTrails',
      cache: { cached: true, age_seconds: 12, ttl_seconds: 300 }, timeout_s: 90, regions_probed: [], iam_users: null },
    surfaces: [surface({ state: 'unmeasurable', state_label: 'UNMEASURABLE', lake_rows: null,
      lake_reason: 'no lake_root resolved' })]
  })], { state: 'unmeasurable', state_label: 'UNMEASURABLE', reason: 'every surface was unmeasurable' }),
    ['UNMEASURABLE: AccessDenied: not authorized to perform cloudtrail:DescribeTrails']],

  ['present, no source', panel([account({
    state: 'present_no_ingest', state_label: null,
    lake: { root: '/lake', producer: null, source: null, rows: null, ok: true,
      reason: 'no producer carries GuardDuty findings into this lake' },
    surfaces: [surface({ id: 'guardduty', surface: 'GuardDuty detectors', state: 'no_source',
      state_label: 'present — no source ingests it (presence is not ingestion)', lake_rows: null,
      lake_producer: null, lake_reason: 'no producer carries GuardDuty findings into this lake' })]
  })]), ['present — no source ingests it (presence is not ingestion)']]
]

/** Assert the count cells and the lake lines of one render against the rule. */
function checkCounts(r, payload, tag) {
  const surfaces = (payload.accounts || []).flatMap(a => a.surfaces || [])
  check(tag + ': one ingestion cell per surface row (' + surfaces.length + ')',
    r.ingestions.length === surfaces.length, 'got ' + r.ingestions.length + ': ' + JSON.stringify(r.ingestions))
  surfaces.forEach((s, i) => {
    const want = countText(s.lake_rows, s.lake_reason, s.lake_last_event)
    check(tag + ': ingestion cell for ' + s.id + ' is the named form', r.ingestions[i] === want,
      'got ' + JSON.stringify(r.ingestions[i]) + ' want ' + JSON.stringify(want))
  })
  const accounts = payload.accounts || []
  check(tag + ': one lake line per account (' + accounts.length + ')',
    r.lakeLines.length === accounts.length, 'got ' + r.lakeLines.length)
  accounts.forEach((a, i) => {
    const lake = a.lake || {}
    const want = 'lake: producer=' + (lake.producer === null || lake.producer === undefined ? 'unmeasured' : String(lake.producer))
      + ' in ' + (lake.source === null || lake.source === undefined ? 'unmeasured' : String(lake.source))
      + ' under ' + (lake.root === null || lake.root === undefined ? 'unmeasured' : String(lake.root))
      + ' — ' + countText(lake.rows, lake.reason, lake.last_event)
    check(tag + ': account lake line is the named form', r.lakeLines[i] === want,
      'got ' + JSON.stringify(r.lakeLines[i]) + ' want ' + JSON.stringify(want))
  })
}

let sha = null
console.log("=== the panel is reached through the renderer's own contribution ===")
for (const [name, payload, must] of ARMS) {
  const r = await renderAws(payload)
  sha = sha || r.sha
  console.log('\n--- ' + name)
  check('a `page` contribution is registered', r.ids.indexOf('page') >= 0)
  check("the AWS section is in the RENDERED page (AwsPanel is in SuitePage's list)", r.section !== null)
  if (r.section === null) continue
  console.log(r.section)
  check('the panel asked the shipped route for the selected tenant',
    r.asked.indexOf('/aws?tenant=' + TENANT) >= 0, 'asked: ' + r.asked.join(', '))
  must.forEach(s => check('renders: ' + JSON.stringify(s), r.section.includes(s), JSON.stringify(r.section.slice(0, 160))))
  checkCounts(r, payload, name)
}

if (process.argv[2]) {
  console.log('\n=== LIVE: the shipped /aws route, tenant=' + TENANT + ' ===')
  const live = JSON.parse(readFileSync(process.argv[2], 'utf8'))
  const r = await renderAws(live)
  console.log(r.section)
  check('the live section renders', r.section !== null)
  if (r.section) {
    check('shows the identity ARN the probe measured',
      r.section.includes('arn:aws:iam::912632857388:user/hermes-protection-audit'))
    check('shows how many regions were probed', /\d+ region\(s\) probed/.test(r.section))
    check('shows the probe cache age', /cache: (hit|fresh read in)/.test(r.section))
    check('shows the registry row LABELLED as a claim', r.section.includes("a CLAIM, never this panel's answer"))
    check('renders the panel state from the live probe', r.section.includes(live.state_label))
    ;(live.accounts || []).forEach(a => (a.surfaces || []).forEach(s => {
      check('surface ' + s.id + ' renders its state label', r.section.includes(s.state_label || s.state))
      check('surface ' + s.id + ' renders its probe call', r.section.includes(s.probe_calls[0]))
      check('surface ' + s.id + ' renders its finding', r.section.includes(s.finding))
    }))
    checkCounts(r, live, 'live')
  }
}

console.log('\nsha256 of the file under test: ' + sha)
console.log(failures ? '\nFAILED: ' + failures + ' check(s)' : '\nALL CHECKS PASSED')
process.exit(failures ? 1 : 0)
