/* Protection Suite — the operator surface: tenant switcher, liveness, coverage matrix,
 * finding queue, retirement board, cross-tenant view.
 *
 * Every panel renders `unmeasured` beside its numbers, because a panel whose every cell is a
 * number implies a completeness it cannot have (04-soc-dashboards-automations.md §3.4). The one
 * number that matters is open cases; everything else is a breakdown of how that number is
 * distributed and how long it has been true.
 *
 * Switching tenant is an explicit RE-SCOPE (§4.2 r4): the whole subtree is keyed on the tenant so
 * every piece of child state (filters, open rows, caches) is discarded, and the banner changes.
 */

  function SuitePage() {
    var tenantsPoll = usePoll("/tenants", 120000);
    var metaPoll = usePoll("/meta", 300000);
    var [tenant, setTenant] = useState(null);
    var [showSources, setShowSources] = useState(false);

    var m = metaPoll.state.data || {};
    var t = tenantsPoll.state.data;
    var list = (t && t.rows) || [];

    // The selector starts on `all` ON PURPOSE: a silent default into ONE tenant is leak path #4
    // ("the operator's own context as an implicit default"), and the operator's first question is
    // "what do I have to do", which spans tenants. The API has no default at all.
    useEffect(function () {
      if (tenant === null) setTenant("all");
    }, [tenant]);

    if (tenantsPoll.state.error && !t) {
      return h("div", { className: "mc-root" },
        h("div", { className: "mc-err" }, "Protection Suite backend error: " + tenantsPoll.state.error));
    }
    if (!t) return h("div", { className: "mc-root" }, h("div", { className: "mc-muted" }, "loading protection suite…"));

    var current = tenant || "all";
    var label = (list.filter(function (x) { return x.platform === current; })[0] || {}).display_name;
    var unm = t.unmeasured || [];

    return h("div", { className: "mc-root" },
      h(PageHead, { title: "Protection Suite", sub: "one operator surface, many tenants — open cases first, coverage stated, absence named" },
        h("span", { className: "mc-muted" }, "as of " + (t.as_of || "—")),
        h("button", { className: "mc-btn", onClick: function () { setShowSources(!showSources); } },
          showSources ? "hide sources" : "sources")),

      h("div", { className: "ps-banner", style: tenantCss(current), "data-tenant": current },
        h("span", { className: "ps-banner-k" }, "TENANT"),
        h("span", { className: "ps-banner-v" }, current + (label ? "  ·  " + label : "")),
        h("span", { className: "mc-muted" },
          "switching re-scopes every panel and clears its state; the banner's colour and pattern are "
          + "this tenant's own (derived from its name), so a screenshot cannot be mistaken for another tenant")),

      h("div", { className: "ps-switch" },
        h("button", { className: "mc-btn" + (current === "all" ? " mc-btn-p" : ""), onClick: function () { setTenant("all"); } },
          "all tenants"),
        list.map(function (x) {
          return h("button", {
            key: x.platform,
            className: "mc-btn" + (current === x.platform ? " mc-btn-p" : ""),
            onClick: function () { setTenant(x.platform); },
            title: (x.display_name || x.platform) + " · status " + x.status + " · " + x.maturity
          }, x.platform + (x.status !== "active" ? " (" + x.status + ")" : ""));
        }),
        list.length ? null : h("span", { className: "mc-muted" }, "no registry record found — tenants are unknown, not zero")),

      showSources ? h(Panel, { title: "Sources this page is reading", sub: "provenance, not decoration — every number below comes from one of these" },
        h("table", { className: "mc-table" },
          h("tbody", null,
            h("tr", null, h("td", null, "registry"), h("td", null, (m.registry || {}).root || "—"), h("td", null, ((m.registry || {}).tenants) + " tenants (" + ((m.registry || {}).provenance) + ")")),
            h("tr", null, h("td", null, "detections"), h("td", null, (m.detections || {}).path || "—"), h("td", null, ((m.detections || {}).rules) + " rules (" + ((m.detections || {}).provenance) + ")")),
            h("tr", null, h("td", null, "lake"), h("td", null, (m.lake || {}).root || "—"), h("td", null, ((m.lake || {}).feeds) + " feeds (" + ((m.lake || {}).provenance) + ")")),
            h("tr", null, h("td", null, "retirement"), h("td", null, (m.retirement || {}).path || "—"), h("td", null, String((m.retirement || {}).provenance))),
            h("tr", null, h("td", null, "boards"), h("td", null, "kanban"), h("td", null, (m.boards || []).join(", "))),
            h("tr", null, h("td", null, "synthetic rows"), h("td", null, (t.synthetic_rows || []).join(", ")), h("td", null, "never folded into a tenant"))),
        ),
        (m.unmeasured || []).length ? h("div", { className: "mc-err" }, "unmeasured: " + (m.unmeasured || []).join(" · ")) : null) : null,

      h("div", { key: "scope-" + current },
        h(LivenessPanel, { tenant: current, onError: null }),
        h(FindingsPanel, { tenant: current }),
        h(CrossPanel, { tenant: current }),
        h(CoveragePanel, { tenant: current }),
        h(RetirementPanel, { tenant: current })));
  }

  /* A small shared shell: title, the panel's own as_of, its unmeasured list, then content. */
  function PsPanel(props) {
    var unm = props.unmeasured || [];
    return h(Panel, {
      title: props.title,
      sub: props.sub + (props.as_of ? "   · as of " + props.as_of : ""),
      right: props.right || null
    },
      props.error ? h("div", { className: "mc-err" }, props.error) : null,
      props.children,
      unm.length ? h("div", { className: "ps-unm" }, "unmeasured: " + unm.join(" · ")) : null);
  }

  function LivenessPanel(props) {
    var p = usePoll("/health?tenant=" + encodeURIComponent(props.tenant), 60000);
    var d = p.state.data;
    var unm = (d && d.unmeasured) || [];
    if (p.state.error && !d) return h(PsPanel, { title: "Liveness — is the instrument on", error: p.state.error });
    if (!d) return h(PsPanel, { title: "Liveness — is the instrument on", sub: "loading" }, h("div", { className: "mc-muted" }, "…"));
    return h(PsPanel, {
      title: "Liveness — is the instrument on",
      sub: "silence is not health: a feed that stopped and a feed with nothing to say look identical",
      as_of: d.as_of, unmeasured: unm,
      right: h("span", { className: "mc-row-m" },
        h(Pill, { kind: d.feeds_alive === d.feeds_probed && d.feeds_probed ? "" : "mc-pill-warn" },
          d.feeds_alive + " / " + d.feeds_probed + " feeds answering"))
    },
      h("div", { className: "mc-row-m" },
        h("span", null, "lake root: " + (d.lake.root || "—")),
        h("span", null, "config: " + (d.lake.config || "—")),
        h(Pill, { kind: d.lake.provenance === "scripts-store" ? "" : "mc-pill-warn" }, d.lake.provenance || "none")),
      h("table", { className: "mc-table" },
        h("thead", null, h("tr", null,
          h("th", null, "feed"), h("th", null, "schema"), h("th", null, "rows"),
          h("th", null, "last event"), h("th", null, "last ingest"), h("th", null, "assets"))),
        h("tbody", null, (d.feeds || []).map(function (f) {
          return h("tr", { key: f.name },
            h("td", null, f.name, f.alive ? null : h(Pill, { kind: "mc-pill-err" }, "unreadable")),
            h("td", null, h("span", { className: "mc-muted" }, f.schema)),
            h("td", null, f.rows == null ? h("span", { className: "mc-muted" }, "unmeasured") : num(f.rows)),
            h("td", null, f.last_event ? hhmm(f.last_event) : h("span", { className: "mc-muted" }, "—")),
            h("td", null, f.last_ingest ? hhmm(f.last_ingest) : h("span", { className: "mc-muted" }, "—")),
            h("td", null, f.assets_seen == null ? "—" : num(f.assets_seen)),
            f.error ? h("td", { className: "mc-muted" }, String(f.error).slice(0, 120)) : null);
        }))),
      (d.feeds || []).length ? null : h("div", { className: "mc-muted" }, "no feed returned a row count"),
      h("table", { className: "mc-table" },
        h("thead", null, h("tr", null,
          h("th", null, "tenant"), h("th", null, "maturity"), h("th", null, "sources declared"),
          h("th", null, "streams present / expected"), h("th", null, "rules enabled"))),
        h("tbody", null, (d.tenants || []).map(function (x) {
          return h("tr", { key: x.platform },
            h("td", null, x.platform, " ", h("span", { className: "mc-muted" }, x.status)),
            h("td", null, h(Pill, { kind: x.maturity === "enforcing" ? "" : "mc-pill-warn" }, x.maturity)),
            h("td", null, num(x.sources_declared_count)),
            h("td", null, x.streams_present == null
              ? h("span", { className: "mc-muted" }, "unmeasured")
              : (x.streams_present.length + " / " + x.streams_expected.length)),
            h("td", null, num(x.rules_enabled), " / ", x.rules_total == null ? h("span", { className: "mc-muted" }, "unmeasured") : num(x.rules_total)));
        }))));
  }

  function FindingsPanel(props) {
    var [state, setState] = useState("");
    var path = "/findings?tenant=" + encodeURIComponent(props.tenant) + (state ? "&state=" + encodeURIComponent(state) : "");
    var p = usePoll(path, 45000);
    var d = p.state.data;
    if (p.state.error && !d) return h(PsPanel, { title: "Finding queue", error: p.state.error });
    if (!d) return h(PsPanel, { title: "Finding queue", sub: "loading" }, h("div", { className: "mc-muted" }, "…"));
    var rows = d.rows || [];
    // Counts come from the API's scope-wide tally, never from the page: the table shows at most
    // `cap` rows, and counting the page would print a number about a DIFFERENT scope than the one
    // the operator selected (the defect this panel was rebuilt for).
    var counts = d.lifecycle_counts || {};
    return h(PsPanel, {
      title: "Finding queue — the SOC lifecycle",
      sub: "scope " + (d.scope_predicate || ("tenant=" + props.tenant))
        + " · " + (d.cap_hit ? (rows.length + " of >= " + d.in_scope_total) : (rows.length + " of " + d.in_scope_total))
        + " rows in scope (of " + d.population_total + " findings read, uncapped)"
        + " · lifecycle counts are over the whole scope · MTTR over cards, not episodes · MTTA unmeasured",
      as_of: d.as_of, unmeasured: d.unmeasured,
      right: h("span", { className: "mc-row-m" },
        d.lifecycle_vocab.map(function (s) {
          return h(Pill, { key: s, kind: (d.open_states.indexOf(s) >= 0 && counts[s]) ? "mc-pill-warn" : "" },
            s + " " + (counts[s] || 0));
        }),
        d.unrecognised_status_count ? h(Pill, { kind: "mc-pill-err" }, "unrecognised " + d.unrecognised_status_count) : null,
        d.cap_hit ? h(Pill, { kind: "mc-pill-warn" }, "page capped at " + d.cap) : null)
    },
      h("div", { className: "mc-row-m" },
        h("button", { className: "mc-btn" + (state === "" ? " mc-btn-p" : ""), onClick: function () { setState(""); } }, "all"),
        d.open_states.map(function (s) {
          return h("button", { key: s, className: "mc-btn" + (state === s ? " mc-btn-p" : ""), onClick: function () { setState(s); } }, "open: " + s);
        }),
        h("button", { className: "mc-btn" + (state === "resolved" ? " mc-btn-p" : ""), onClick: function () { setState("resolved"); } }, "resolved"),
        h("span", { className: "mc-muted" }, "boards: " + (d.boards_scanned || []).join(", "))),
      h("table", { className: "mc-table" },
        h("thead", null, h("tr", null,
          h("th", null, "case"), h("th", null, "sev"), h("th", null, "rule"), h("th", null, "subject"),
          h("th", null, "lifecycle"), h("th", null, "age"), h("th", null, "stale"), h("th", null, "disposition"), h("th", null, "tenant"))),
        h("tbody", null, rows.map(function (r) {
          return h("tr", { key: r.board + r.id, className: r.stale ? "ps-stale" : "" },
            h("td", null, h(IdChip, { id: r.id }), " ", h("span", { className: "mc-muted" }, r.board)),
            h("td", null, h(Pill, { kind: "ps-sev-" + (r.severity || "info") }, r.severity)),
            h("td", null, r.rule_id
              ? h("span", { title: r.rule_id }, r.rule_id.length > 26 ? r.rule_id.slice(0, 26) + "…" : r.rule_id)
              : h("span", { className: "mc-muted" }, "unmeasured")),
            h("td", null, r.device_id ? h("span", { title: r.subject || "" }, r.device_id.length > 22 ? r.device_id.slice(0, 22) + "…" : r.device_id) : "—"),
            h("td", null, h(Pill, { kind: r.lifecycle === "unrecognised_status" ? "mc-pill-err" : "" }, r.lifecycle),
              r.block_kind ? h("span", { className: "mc-muted" }, " " + r.block_kind) : null),
            h("td", null, dur(r.age_seconds)),
            h("td", null, r.stale ? h(Pill, { kind: "mc-pill-err" }, "stale") : h("span", { className: "mc-muted" }, "—")),
            h("td", null, r.disposition || h("span", { className: "mc-muted" }, "unrecorded")),
            h("td", null, h(Pill, { kind: r.platform === "_unattributed" ? "mc-pill-warn" : "" }, r.platform)));
        }))),
      rows.length ? null : h("div", { className: "mc-muted" }, "no finding rows for this scope"));
  }

  function CrossPanel(props) {
    var p = usePoll("/cross", 60000);
    var d = p.state.data;
    if (p.state.error && !d) return h(PsPanel, { title: "Across tenants", error: p.state.error });
    if (!d) return h(PsPanel, { title: "Across tenants", sub: "loading" }, h("div", { className: "mc-muted" }, "…"));
    var rows = d.rows || [];
    var all = d.all || {};
    return h(PsPanel, {
      title: "Across tenants",
      sub: "one row per tenant, plus _unattributed and all — all is its own aggregate over the whole population, so all != sum(rows) is visible",
      as_of: d.as_of, unmeasured: d.unmeasured,
      right: h("span", { className: "mc-row-m" },
        h(Pill, { kind: d.cap_hit ? "mc-pill-warn" : "" },
          d.cap_hit
            ? ("capped: " + d.cap + " of " + d.population_total + " — these numbers are a page, not a KPI")
            : ("uncapped: all " + d.population_total + " findings aggregated")),
        h(Pill, { kind: d.all_equals_sum ? "" : "mc-pill-warn" },
          "all open " + d.all_open + " = rows " + d.sum_of_rows_open
          + (d.all_equals_sum ? " (own aggregate agrees with the rows)" : " (A ROW IS MISSING)")),
        h(Pill, { kind: d.tenant_rows_equal_all ? "" : "mc-pill-warn" },
          "tenant rows " + d.sum_of_tenant_open + " vs all " + d.all_open
          + (d.tenant_rows_equal_all ? "" : " — _unattributed kept out, never folded in")))
    },
      h("table", { className: "mc-table" },
        h("thead", null, h("tr", null,
          h("th", null, "tenant"), h("th", null, "open"), h("th", null, "needs human"),
          h("th", null, "oldest open"), h("th", null, "resolved"), h("th", null, "unrecognised"),
          h("th", null, "maturity"), h("th", null, "unmeasured"))),
        h("tbody", null,
          rows.map(function (r) {
            var hi = r.platform === "_unattributed";
            return h("tr", { key: r.platform, className: hi ? "ps-unattr" : "" },
              h("td", null, h(Pill, { kind: hi ? "mc-pill-warn" : (r.is_tenant ? "" : "mc-pill-me") }, r.platform),
                " ", h("span", { className: "mc-muted" }, r.display_name || "")),
              h("td", null, num(r.open)),
              h("td", null, r.needs_human ? h(Pill, { kind: "mc-pill-warn" }, r.needs_human) : "0"),
              h("td", null, r.oldest_open_age_seconds ? dur(r.oldest_open_age_seconds) : h("span", { className: "mc-muted" }, "—")),
              h("td", null, num(r.resolved)),
              h("td", null, r.unrecognised_status ? h(Pill, { kind: "mc-pill-err" }, r.unrecognised_status) : "0"),
              h("td", null, r.maturity || h("span", { className: "mc-muted" }, "n/a")),
              h("td", { className: "mc-muted" }, (r.unmeasured || []).join("; ") || "—"));
          }),
          h("tr", { className: "ps-allrow" },
            h("td", null, h(Pill, { kind: "mc-pill-me" }, "all")),
            h("td", null, num(all.open)),
            h("td", null, num(all.needs_human)),
            h("td", null, all.oldest_open_age_seconds ? dur(all.oldest_open_age_seconds) : "—"),
            h("td", null, num(all.resolved)),
            h("td", null, num(all.unrecognised_status)),
            h("td", { className: "mc-muted" }, "n/a"),
            h("td", { className: "mc-muted" }, all.oldest_open_age_seconds ? "" : "no open case has an age"))))); 
  }

  function CoveragePanel(props) {
    var p = usePoll("/coverage?tenant=" + encodeURIComponent(props.tenant), 120000);
    var d = p.state.data;
    if (p.state.error && !d) return h(PsPanel, { title: "Coverage matrix", error: p.state.error });
    if (!d) return h(PsPanel, { title: "Coverage matrix", sub: "loading" }, h("div", { className: "mc-muted" }, "…"));
    var rows = d.rows || [];
    var tenantCols = [];
    rows.forEach(function (r) {
      (r.cells || []).forEach(function (c) {
        if (tenantCols.indexOf(c.platform) < 0) tenantCols.push(c.platform);
      });
    });
    return h(PsPanel, {
      title: "Coverage matrix — detections x tenants",
      sub: d.rules_total + " rules · " + d.tenants_total + " tenant(s) · coverage is a CLAIM; what is measured here is scope, enablement, maturity and waivers",
      as_of: d.as_of, unmeasured: d.unmeasured,
      right: h("span", { className: "mc-row-m" },
        h(Pill, { kind: d.detections_provenance === "scripts-store" ? "" : "mc-pill-warn" },
          "rules: " + (d.detections_provenance || "none")),
        h(Pill, { kind: Object.keys(d.declared_only || {}).length ? "mc-pill-warn" : "" },
          "declared-not-in-catalog: " + Object.keys(d.declared_only || {}).length + " tenant(s)"))
    },
      rows.length ? h("table", { className: "mc-table" },
        h("thead", null, h("tr", null,
          h("th", null, "rule"), h("th", null, "sev"), h("th", null, "stream"),
          tenantCols.map(function (c) { return h("th", { key: c }, c); }))),
        h("tbody", null, rows.map(function (r) {
          return h("tr", { key: r.rule },
            h("td", null, h("span", { title: r.rule }, r.title || r.rule)),
            h("td", null, h(Pill, { kind: "ps-sev-" + (r.severity || "info") }, r.severity || "—")),
            h("td", { className: "mc-muted" }, r.stream || "—"),
            (r.cells || []).map(function (c) {
              return h("td", { key: c.platform, title: "waiver: " + (c.waiver ? c.waiver.reason : "none") },
                h(Pill, { kind: c.state === "enabled" ? "" : (c.state === "excluded" ? "mc-pill-me" : "mc-pill-warn") },
                  c.state + (c.state !== "excluded" ? " · " + c.maturity : "")));
            }));
        }))) : h("div", { className: "mc-muted" }, "no detection index and/or no registry — the matrix cannot be built; that is not an empty matrix"));
  }

  function RetirementPanel(props) {
    var p = usePoll("/retirement", 180000);
    var d = p.state.data;
    if (p.state.error && !d) return h(PsPanel, { title: "Retirement board", error: p.state.error });
    if (!d) return h(PsPanel, { title: "Retirement board", sub: "loading" }, h("div", { className: "mc-muted" }, "…"));
    var s = d.sentinel || {}, f = d.defender || {}, items = d.items || [];
    return h(PsPanel, {
      title: "Retirement board — Sentinel / Defender exit",
      sub: "nothing is cut until its replacement passes its shadow-mode proof; absence of proof renders as unproven",
      as_of: d.as_of, unmeasured: d.unmeasured,
      right: h("span", { className: "mc-row-m" },
        h(Pill, { kind: d.items_proven === d.items_total && d.items_total ? "" : "mc-pill-warn" },
          d.items_proven + " / " + d.items_total + " items proven"))
    },
      h("div", { className: "mc-row-m" },
        h("span", null, "posture: " + (d.posture_source || "—")),
        h(Pill, { kind: d.posture_provenance === "scripts-store" ? "" : "mc-pill-warn" }, d.posture_provenance || "none"),
        d.posture_mtime ? h("span", { className: "mc-muted" }, "snapshot " + hhmm(d.posture_mtime)) : null,
        h("span", { className: "mc-muted" }, "gate: " + (d.gate_source || "not shipped — every item unproven"))),
      h("table", { className: "mc-table" },
        h("thead", null, h("tr", null,
          h("th", null, "exit item"), h("th", null, "measured"), h("th", null, "shadow proof"))),
        h("tbody", null, items.map(function (i) {
          return h("tr", { key: i.id },
            h("td", null, h("div", null, i.item), h("span", { className: "mc-muted" }, i.id)),
            h("td", { className: "mc-muted" }, JSON.stringify(i.measured == null ? "unmeasured" : i.measured).slice(0, 160)),
            h("td", null, h(Pill, { kind: (i.proof || {}).state === "green" ? "" : "mc-pill-err" },
              (i.proof || {}).state || "unproven")));
        }))),
      h("div", { className: "mc-row-m" },
        h("span", null, "Sentinel workspaces: " + (s.enabled_workspaces || []).join(", ")),
        h("span", null, "custom detections: " + (s.custom_alert_rules == null ? "unmeasured" : s.custom_alert_rules)),
        h("span", null, "automation rules: " + (s.automation_rules == null ? "unmeasured" : s.automation_rules)),
        h("span", null, "connectors: " + (s.connectors == null ? "unmeasured" : s.connectors)),
        h("span", null, "incidents: " + ((s.incidents || {}).total == null ? "unmeasured" : (s.incidents || {}).total))),
      h("div", { className: "mc-row-m" },
        h("span", null, "Defender plans at Standard: " + (f.standard_count == null ? "unmeasured" : f.standard_count)),
        h("span", null, "of " + (f.plans_total == null ? "unmeasured" : f.plans_total) + " priced"),
        h("span", null, "security contacts: " + (f.contacts == null ? "unmeasured" : f.contacts)),
        h("span", null, "automation rules: " + (f.automation_rules == null ? "unmeasured" : f.automation_rules))),
      d.owner_spend_card && d.owner_spend_card.found ? h("div", { className: "mc-row" },
        h("div", { className: "mc-row-t" }, "the spend gate (owner decision)"),
        h("div", { className: "mc-row-m" },
          h(IdChip, { id: d.owner_spend_card.id }),
          h(Pill, { kind: d.owner_spend_card.status === "done" ? "" : "mc-pill-warn" }, d.owner_spend_card.status),
          h("span", { className: "mc-muted" }, "board " + d.owner_spend_card.board + " · " + (d.owner_spend_card.title || "").slice(0, 90))),
        h(CardTools, { item: { id: d.owner_spend_card.id,
                               briefing: "card " + d.owner_spend_card.id + " on board " + d.owner_spend_card.board } })) : null);
  }
