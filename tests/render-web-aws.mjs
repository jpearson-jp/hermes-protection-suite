#!/usr/bin/env node
/**
 * Render the WEB half's AWS control-plane panel and assert the never-a-bare-zero rule and the
 * never-a-raw-machine-token rule — from the BUILT BUNDLE, not from the sources.
 *
 * WHY THIS EXISTS. `dashboard/dist/index.js` is what the browser loads; the sources only reach a
 * reader after `build.sh` runs. The Python suite can assert that `dist/` CONTAINS the sources, but
 * neither Python nor `node --check` can tell whether the panel RENDERS a measured 0 with its
 * meaning at the ACCOUNT scope (it did not: the account lake line printed `rows 0` while the surface
 * row three lines below carried `0 rows — silent`). The rules that matter here are render rules, so
 * this harness executes the component and reads its output.
 *
 * HOW. The bundle is an IIFE that reads `window.__HERMES_PLUGIN_SDK__` (React + fetchJSON) and
 * registers its page on `window.__HERMES_PLUGINS__`. Both stand up as a ~40-line mini renderer in a
 * `node:vm` context: `createElement` builds plain elements, `useState`/`useEffect`/`useCallback` get
 * real slots, function components are expanded and effects run — so the page renders, the tenant
 * switch is actually pressed, and every panel re-renders on the new scope. The panel is reached the
 * way the browser reaches it: through the registered page, not by importing an internal.
 *
 * The two rules are checked STRUCTURALLY: every surface row's ingestion cell and every account's
 * lake line are located in the tree and compared, character for character, against the ONE allowed
 * rendering of that count; and no state token the backend can emit (any `snake_case` state) may
 * appear as text on the page. The API's own finding prose is not part of that comparison — a rule
 * that fired on the backend's sentences would be a rule about the backend.
 *
 * USAGE
 *   node tests/render-web-aws.mjs                        # synthetic arms only
 *   node tests/render-web-aws.mjs <live-aws-panel.json>  # plus the LIVE /aws payload
 *
 * The synthetic arms always run (they are the RULES, not the account): a measured 0, an unread lake,
 * a refused probe, a `present_no_ingest` account, and a trail that is present but NOT logging (the
 * `details` half of the payload, which the page must render rather than merely carry).
 */
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import vm from 'node:vm'

const HERE = dirname(fileURLToPath(import.meta.url))
const REPO = resolve(HERE, '..')
const BUNDLE = join(REPO, 'dashboard', 'dist', 'index.js')
const API = '/api/plugins/protection-suite'
const TENANT = 'onestack'
const SEC_TITLE = 'AWS control plane'

// ------------------------------------------------------------- the SDK the bundle is handed

let H = { slots: [], cur: 0, dirty: false }

function createElement(type, props, ...children) {
  const p = Object.assign({}, props)
  if (children.length === 1) p.children = children[0]
  else if (children.length > 1) p.children = children
  return { __el: true, type, props: p }
}

const React = {
  createElement,
  useState(init) {
    const i = H.cur++
    if (!(i in H.slots)) H.slots[i] = typeof init === 'function' ? init() : init
    return [H.slots[i], (v) => { H.slots[i] = typeof v === 'function' ? v(H.slots[i]) : v; H.dirty = true }]
  },
  useEffect(fn, deps) {
    const i = H.cur++
    const prev = H.slots[i]
    const changed = !prev || !prev.deps || !deps || deps.some((d, j) => d !== prev.deps[j])
    H.slots[i] = { deps, cleanup: changed ? fn() : (prev && prev.cleanup) }
  },
  useCallback(fn) { H.cur++; return fn },
  useMemo(fn) { H.cur++; return fn() },
  useRef(init) { const i = H.cur++; if (!(i in H.slots)) H.slots[i] = { current: init }; return H.slots[i] },
}

/** A stand-in for a route this harness does not serve: an empty array that answers `.map()`,
 *  `.join()`, `.length` and string coercion, and whose properties are themselves empty. The panel
 *  under test is the only one that matters; the others must merely render without throwing. */
function emptyAny() {
  const arr = []
  return new Proxy(arr, {
    get(t, prop) {
      if (prop === '__el' || prop === Symbol.iterator) return undefined
      if (prop === Symbol.toPrimitive) return () => ''
      if (prop === 'toString') return () => ''
      if (prop === 'valueOf') return () => 0
      switch (prop) {
        case 'length': return 0
        case 'map': return (fn) => arr.map(fn)
        case 'filter': return (fn) => arr.filter(fn)
        case 'slice': return () => []
        case 'concat': return () => []
        case 'flatMap': return () => []
        case 'forEach': return () => undefined
        case 'join': return () => ''
        case 'indexOf': return () => -1
        case 'includes': return () => false
        case 'some': return () => false
        case 'every': return () => true
        case 'find': return () => undefined
        default: return emptyAny()
      }
    },
  })
}

function mountBundle(serve) {
  const asked = []
  const registered = {}
  const browserWindow = {
    __HERMES_PLUGIN_SDK__: {
      React,
      fetchJSON: (path) => { asked.push(path); return serve(String(path).replace(API, '')) },
    },
    __HERMES_PLUGINS__: { register: (name, page) => { registered.name = name; registered.page = page } },
  }
  const sandbox = {
    window: browserWindow,
    console,
    // The page's poll interval must not hold node open; `useEffect` calls `load()` itself.
    setInterval: () => 0,
    clearInterval: () => {},
  }
  vm.createContext(sandbox)
  vm.runInContext(readFileSync(BUNDLE, 'utf8'), sandbox, { filename: BUNDLE })
  if (typeof registered.page !== 'function') throw new Error('the bundle registered no page component')
  return { page: registered.page, asked }
}

// ------------------------------------------------------------------------- the mini renderer

/** Expand an element tree into the flat list of elements actually rendered, invoking function
 *  components (the page is one component element until something renders it). */
function expand(el, out) {
  if (el === null || el === undefined || typeof el === 'boolean') return
  if (Array.isArray(el)) { el.forEach((e) => expand(e, out)); return }
  if (typeof el === 'object' && el.__el === true) {
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
  if (typeof el === 'object' && el.__el === true) {
    return typeof el.type === 'function' ? text(el.type(el.props)) : text(el.props.children)
  }
  return ''
}

/** The ingestion cell of a surface row: the 4th <td> of a 5-cell row whose 3rd cell is the probe
 *  call list. Located by SHAPE, so no marker has to be added to the panel for the test's benefit. */
function ingestionCells(nodes) {
  const out = []
  nodes.forEach((n) => {
    if (n.type !== 'tr') return
    const tds = (n.props.children || []).filter((c) => c && c.__el === true && c.type === 'td')
    if (tds.length !== 5) return
    if (!/:(Describe|List|Get)/.test(text(tds[2]))) return
    out.push(text(tds[3]))
  })
  return out
}

/** The account-level lake line: the muted div whose text opens with the lake producer. */
function lakeLines(nodes) {
  return nodes.filter((n) => n.props && n.props.className === 'mc-muted'
    && text(n).indexOf('lake: producer=') === 0).map(text)
}

/** The per-trail lines of the `details` half — located STRUCTURALLY, inside the one container whose
 *  text opens with "trails the probe measured:". A leading-text match alone is not enough: a
 *  CloudTrail ROW's finding also opens with the word "trail" ("trail present; the source ran and
 *  landed nothing"). */
function trailLines(nodes) {
  const box = nodes.filter((n) => n.type === 'div' && n.props
    && text(n).indexOf('trails the probe measured:') === 0)[0]
  if (!box) return []
  const out = []
  expand(box, out)
  const lines = out.filter((n) => n.type === 'div' && n.props && text(n).indexOf('trail ') === 0)
  // ...and drop the wrapper whose text is the concatenation of the lines inside it.
  return lines.filter((n) => !lines.some((m) => m !== n && text(m).length < text(n).length
    && text(n).indexOf(text(m)) === 0)).map(text)
}

/** The reason text the page prints for an unmeasured logging state — the rule restated. A dict
 *  `{error, reason}` string-concatenated is `[object Object]`, which is what this rule exists for. */
function errText(e) {
  if (e === null || e === undefined || e === '') return ''
  if (typeof e === 'string') return e.length > 160 ? e.slice(0, 160) + '…' : e
  const s = String(e.reason || e.error || JSON.stringify(e))
  return s.length > 160 ? s.slice(0, 160) + '…' : s
}

/** One measured trail's line: the structural fields, then the logging state. */
function trailText(t) {
  const multi = (t.IsMultiRegionTrail === null || t.IsMultiRegionTrail === undefined)
    ? t.IsMultiTrail : t.IsMultiRegionTrail
  const why = errText(t.IsLogging_error)
  const logging = t.IsLogging === true ? 'logging'
    : (t.IsLogging === false ? 'NOT logging' : ('logging unmeasured' + (why ? ': ' + why : '')))
  return 'trail ' + (t.Name || 'name not returned') + ' — ' + (t.region || 'region unmeasured')
    + ' · home ' + (t.HomeRegion || 'unmeasured')
    + ' · multi-region ' + (multi === true ? 'yes' : (multi === false ? 'no' : 'unmeasured'))
    + ' · s3 ' + (t.S3BucketName || 'unmeasured') + ' · ' + logging
}

const settle = () => new Promise((r) => setTimeout(r, 0))

async function renderAws(payload) {
  const data = {
    '/tenants': {
      as_of: '2026-09-20T08:00:00Z', unmeasured: [],
      rows: [{ platform: TENANT, display_name: 'One Stack', status: 'active', maturity: 'enforcing' }],
    },
  }
  const { page, asked } = mountBundle((path) => Promise.resolve(
    path.indexOf('/aws?tenant=') === 0 ? payload : (data[path] || emptyAny())))
  let slots = []
  async function pass() {
    H = { slots, cur: 0, dirty: false }
    const out = []
    expand(createElement(page, {}), out)
    slots = H.slots
    await settle()
    return { nodes: out, dirty: H.dirty }
  }
  let pressed = false
  let r = { nodes: [], dirty: true }
  for (let i = 0; i < 12; i++) {
    if (!r.dirty && pressed) break
    r = await pass()
    if (!pressed) {
      // Press the tenant switch, as the operator would — but only once the tenant list has arrived
      // (the page opens on `all` on purpose, and its first render is the loading one).
      const btn = r.nodes.filter((n) => n.type === 'button' && n.props && n.props.children === TENANT
        && typeof n.props.onClick === 'function')[0]
      if (btn) { btn.props.onClick(); pressed = true }
    }
  }
  if (!pressed) throw new Error('the tenant switcher offered no button for ' + TENANT)
  const nodes = r.nodes
  const sec = nodes.filter((n) => n.props && typeof n.props.title === 'string'
    && n.props.title.indexOf(SEC_TITLE) === 0)[0]
  const sectionNodes = []
  if (sec) expand(sec, sectionNodes)
  return {
    page: nodes, section: sec ? text(sec) : null,
    ingestions: sec ? ingestionCells(sectionNodes) : [],
    lakeLines: sec ? lakeLines(sectionNodes) : [],
    trails: sec ? trailLines(sectionNodes) : [],
    asked,
  }
}

// ------------------------------------------------------------------------------ assertions

let failures = 0
function check(name, ok, detail) {
  console.log((ok ? '  PASS  ' : '  FAIL  ') + name + (ok || detail === undefined ? '' : '  -> ' + detail))
  if (!ok) failures++
}

/** The one allowed rendering of a lake count — the rule, restated as a function. The page's `num()`
 *  groups thousands, so a count's rendering is compared in that form. */
function countText(rows, reason, lastEvent) {
  if (rows === null || rows === undefined) return 'unmeasured' + (reason ? ' (' + reason + ')' : '')
  if (rows === 0) return '0 rows — silent'
  const m = String(lastEvent || '').match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})/)
  const grouped = String(rows).replace(/\B(?=(\d{3})+(?!\d))/g, ',')
  return grouped + ' rows' + (lastEvent ? ' · last ' + (m ? m[2] + '-' + m[3] + ' ' + m[4] + ':' + m[5] : lastEvent) : '')
}

const trail = (over) => Object.assign({
  region: 'us-east-1', Name: 'jpthegeek-multiregion', HomeRegion: 'us-east-1',
  IsMultiRegionTrail: true, LogFileValidationEnabled: true,
  S3BucketName: 'aws-cloudtrail-logs-912632857388', IsLogging: true,
  IsLogging_error: null,
}, over)

const surface = (over) => Object.assign({
  id: 'cloudtrail', surface: 'CloudTrail trails — the control-plane record',
  probe_calls: ['cloudtrail:DescribeTrails(includeShadowTrails=True)', 'cloudtrail:GetTrailStatus'],
  state: 'enabled_producing', state_label: 'enabled and producing', present: true,
  regions_present: ['us-east-1'], regions_empty: [], regions_error: null,
  lake_producer: 'aws-cloudtrail', lake_source: 'cloud_audit',
  lake_rows: 10, lake_last_event: '2026-09-20 07:16:27', lake_reason: null,
  finding: 'trail(s) jpthegeek-multiregion present', details: {}, unmeasured: [],
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
  surfaces: [surface({})], unmeasured: [],
}, over)

const panel = (accounts, over) => Object.assign({
  as_of: '2026-09-20T07:29:38Z', tenant: TENANT, accounts, count: accounts.length,
  state: 'enabled_producing', state_label: 'enabled and producing', reason: null,
  probe_calls: ['cloudtrail:DescribeTrails(includeShadowTrails=True)', 'cloudtrail:GetTrailStatus',
    'guardduty:ListDetectors', 'securityhub:DescribeHub', 'iam:GetAccountPasswordPolicy'],
  lake_root: '/mnt/ohscratch/logs/platform-security', unmeasured: [],
}, over)

const ARMS = [
  ['measured 0 rows', panel([account({
    state: 'enabled_silent', state_label: 'enabled but silent',
    lake: { root: '/lake', producer: 'aws-cloudtrail', source: 'cloud_audit', rows: 0, ok: true, reason: null },
    surfaces: [surface({ state: 'enabled_silent', state_label: 'enabled but silent', lake_rows: 0,
      finding: 'trail present; the source ran and landed nothing' })],
  })]), ['enabled but silent', '0 rows — silent']],

  ['unread lake', panel([account({
    state: 'unmeasurable', state_label: 'UNMEASURABLE',
    lake: { root: '/lake', producer: 'aws-cloudtrail', source: 'cloud_audit', rows: null, ok: false,
      reason: 'no lake interpreter (duckdb lives in /home/hermes/.lakevenv)' },
    surfaces: [surface({ state: 'unmeasurable', state_label: 'UNMEASURABLE', lake_rows: null,
      lake_reason: 'no lake interpreter (duckdb lives in /home/hermes/.lakevenv)' })],
  })]), ['UNMEASURABLE', 'unmeasured (no lake interpreter (duckdb lives in /home/hermes/.lakevenv))']],

  ['refused probe', panel([account({
    state: 'unmeasurable', state_label: 'UNMEASURABLE', identity: null,
    probe: { status: 'unmeasurable', reason: 'AccessDenied: not authorized to perform cloudtrail:DescribeTrails',
      cache: { cached: true, age_seconds: 12, ttl_seconds: 300 }, timeout_s: 90, regions_probed: [], iam_users: null },
    surfaces: [surface({ state: 'unmeasurable', state_label: 'UNMEASURABLE', lake_rows: null,
      lake_reason: 'no lake_root resolved' })],
  })], { state: 'unmeasurable', state_label: 'UNMEASURABLE', reason: 'every surface was unmeasurable' }),
    ['UNMEASURABLE: AccessDenied: not authorized to perform cloudtrail:DescribeTrails']],

  // The state the page used to render as the raw token `present_no_ingest`, and the details the
  // payload carries: a trail present but NOT logging is a measured fact the state cell cannot say.
  ['present, no source', panel([account({
    state: 'present_no_ingest', state_label: 'present — no source ingests it (presence is not ingestion)',
    lake: { root: '/lake', producer: 'aws-cloudtrail', source: 'cloud_audit', rows: 2327, ok: true, reason: null },
    surfaces: [
      surface({ details: {
        trails: [trail({}), trail({ region: 'eu-west-1', Name: 'jpthegeek-eu', HomeRegion: 'eu-west-1',
                                 IsMultiRegionTrail: false, S3BucketName: 'eu-trail-logs', IsLogging: false }),
                 // The LIVE shape for a shadow registration: GetTrailStatus answers not-found, and the
                 // error is an OBJECT — string-concatenated it renders "[object Object]".
                 trail({ region: 'ap-southeast-2', IsLogging: null,
                         IsLogging_error: { error: 'TrailNotFoundException',
                           reason: 'An error occurred (TrailNotFoundException) when calling the GetTrailStatus operation: Unknown trail: arn:aws:cloudtrail:ap-southeast-2:912632857388:trail/jpthegeek-multiregion for the user: 912632857388' } })],
        trail_s3_ingest: 'no source reads the trail\'s S3 bucket (a missing SOURCE, filed separately); '
          + 'the lake rows for producer=aws-cloudtrail come from cloudtrail:LookupEvents (event history), NOT from the trail' } }),
      surface({ id: 'guardduty', surface: 'GuardDuty detectors', probe_calls: ['guardduty:ListDetectors'],
        state: 'no_source', state_label: 'present — no source ingests it (presence is not ingestion)',
        lake_rows: null, lake_producer: null,
        lake_reason: 'no producer carries GuardDuty findings into this lake' }),
    ],
  })]), ['present — no source ingests it (presence is not ingestion)',
    'trail jpthegeek-multiregion — us-east-1 · home us-east-1 · multi-region yes · s3 aws-cloudtrail-logs-912632857388 · logging',
    'trail jpthegeek-eu — eu-west-1 · home eu-west-1 · multi-region no · s3 eu-trail-logs · NOT logging',
    'trail jpthegeek-multiregion — ap-southeast-2 · home us-east-1 · multi-region yes · s3 aws-cloudtrail-logs-912632857388 · logging unmeasured: An error occurred (TrailNotFoundException)',
    "no source reads the trail's S3 bucket"]],
]

/** Assert the count cells, the account lake lines and the raw-token rule of one render. */
function checkRender(r, payload, tag) {
  const accounts = payload.accounts || []
  const surfaces = accounts.flatMap((a) => a.surfaces || [])
  check(tag + ': one ingestion cell per surface row (' + surfaces.length + ')',
    r.ingestions.length === surfaces.length, 'got ' + r.ingestions.length + ': ' + JSON.stringify(r.ingestions))
  surfaces.forEach((s, i) => {
    const want = countText(s.lake_rows, s.lake_reason, s.lake_last_event)
    check(tag + ': ingestion cell for ' + s.id + ' is the named form', r.ingestions[i] === want,
      'got ' + JSON.stringify(r.ingestions[i]) + ' want ' + JSON.stringify(want))
  })
  check(tag + ': one account lake line per account (' + accounts.length + ')',
    r.lakeLines.length === accounts.length, 'got ' + r.lakeLines.length + ': ' + JSON.stringify(r.lakeLines))
  accounts.forEach((a, i) => {
    const lake = a.lake || {}
    const want = 'lake: producer=' + (lake.producer === null || lake.producer === undefined ? 'unmeasured' : String(lake.producer))
      + ' in ' + (lake.source === null || lake.source === undefined ? 'unmeasured' : String(lake.source))
      + ' under ' + (lake.root === null || lake.root === undefined ? 'unmeasured' : String(lake.root))
      + ' — ' + countText(lake.rows, lake.reason, lake.last_event)
    check(tag + ': account lake line is the named form', r.lakeLines[i] === want,
      'got ' + JSON.stringify(r.lakeLines[i]) + ' want ' + JSON.stringify(want))
  })
  // The `details` half: one line per measured trail, character for character against the rule. This
  // is the check that catches a key the probe does not use (a MEASURED boolean rendered as
  // "unmeasured") and an object concatenated into the text ("[object Object]").
  const trails = surfaces.flatMap((s) => ((s.details || {}).trails) || [])
  check(tag + ': one trail line per measured trail (' + trails.length + ')',
    r.trails.length === trails.length, 'got ' + r.trails.length + ': ' + JSON.stringify(r.trails))
  trails.forEach((t, i) => {
    const want = trailText(t)
    check(tag + ': trail line ' + i + ' (' + (t.region || '?') + ') is the named form',
      r.trails[i] === want, 'got ' + JSON.stringify(r.trails[i]) + ' want ' + JSON.stringify(want))
  })
  // No object ever leaks into the rendered text.
  check(tag + ': no object leaks into the rendered text', !String(r.section).includes('[object Object]'),
    'the page rendered [object Object]')
  // No raw machine token: every state the backend can emit is snake_case, and none of it is prose.
  const tokens = new Set()
  const walk = (node) => {
    if (!node || typeof node !== 'object') return
    if (Array.isArray(node)) { node.forEach(walk); return }
    if (typeof node.state === 'string' && /_/.test(node.state)) tokens.add(node.state)
    Object.keys(node).forEach((k) => walk(node[k]))
  }
  walk(payload)
  tokens.forEach((tok) => check(tag + ': the page never renders the raw token ' + JSON.stringify(tok),
    !String(r.section).includes(tok)))
}

let sha = null
console.log('=== the panel is reached through the registered page, from the BUILT bundle ===')
console.log('    ' + BUNDLE)
sha = createHash('sha256').update(readFileSync(BUNDLE)).digest('hex')
check('the built bundle CARRIES the one-rule function (src was rebuilt, dist was not hand-edited)',
  readFileSync(BUNDLE, 'utf8').includes('var lakeCell = function (rows, reason, lastEvent)'))
for (const [name, payload, must] of ARMS) {
  const r = await renderAws(payload)
  console.log('\n--- ' + name)
  check('the page rendered the AWS section', r.section !== null)
  check('the panel asked the shipped route for the selected tenant',
    r.asked.indexOf(API + '/aws?tenant=' + TENANT) >= 0, 'asked: ' + r.asked.join(', '))
  if (r.section === null) continue
  console.log(r.section)
  must.forEach((s) => check('renders: ' + JSON.stringify(s), r.section.includes(s),
    JSON.stringify(r.section.slice(0, 200))))
  checkRender(r, payload, name)
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
    ;(live.accounts || []).forEach((a) => (a.surfaces || []).forEach((s) => {
      check('surface ' + s.id + ' renders its state label', r.section.includes(s.state_label || s.state))
      check('surface ' + s.id + ' renders its probe call', r.section.includes(s.probe_calls[0]))
      check('surface ' + s.id + ' renders its finding', r.section.includes(s.finding))
      if (s.state_label) {
        check('surface ' + s.id + ' renders its state label and NOT the raw token',
          s.state_label !== s.state ? !r.section.includes(s.state) : true)
      }
    }))
    checkRender(r, live, 'live')
  }
}

console.log('\nsha256 of the bundle under test: ' + sha)
console.log(failures ? '\nFAILED: ' + failures + ' check(s)' : '\nALL CHECKS PASSED')
process.exit(failures ? 1 : 0)
