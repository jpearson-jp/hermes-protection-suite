/* Protection Suite — shared core (adapted from Mission Control's, same measured SDK contract).
 *
 * Loaded INSIDE the plugin IIFE (see build.sh): the header defines SDK/React/h, this file adds the
 * helpers, pieces and the two answer surfaces that the pages share, then the page file defines its
 * component and the footer registers it. No module system, no build step beyond `cat`.
 */

  // ---------------------------------------------------------------- API + polling
  var API = "/api/plugins/protection-suite";   // this plugin owns its own backend routes

  function usePoll(path, ms) {
    var [state, set] = useState({ data: null, error: null });
    var load = useCallback(function () {
      fetchJSON(API + path)
        .then(function (d) { set({ data: d, error: null }); })
        .catch(function (e) { set(function (s) { return { data: s.data, error: String((e && e.message) || e) }; }); });
    }, [path]);
    useEffect(function () {
      load();
      var t = setInterval(load, ms);
      return function () { clearInterval(t); };
    }, [load, ms]);
    return { state: state, load: load };
  }

  // ---------------------------------------------------------------- formatting
  function dur(sec) {
    if (sec == null) return "—";
    sec = Math.max(0, Math.floor(sec));
    if (sec < 60) return sec + "s";
    if (sec < 3600) return Math.floor(sec / 60) + "m";
    if (sec < 86400) return Math.floor(sec / 3600) + "h " + Math.floor((sec % 3600) / 60) + "m";
    return Math.floor(sec / 86400) + "d " + Math.floor((sec % 86400) / 3600) + "h";
  }
  function hhmm(iso) {
    if (!iso) return "—";
    try { return new Date(iso).toISOString().slice(5, 16).replace("T", " "); } catch (e) { return "—"; }
  }
  function hourLabel(iso) {
    if (!iso) return "—";
    try { return new Date(iso).toISOString().slice(11, 16); } catch (e) { return "—"; }
  }
  function num(n) {
    if (n == null) return "—";
    return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  }

  // ---------------------------------------------------------------- clipboard + chat handoff
  function copyText(text) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text);
    } catch (e) { /* fall through to the legacy path */ }
    return new Promise(function (resolve, reject) {
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "");
        ta.style.position = "fixed";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.select();
        var ok = document.execCommand("copy");
        document.body.removeChild(ta);
        ok ? resolve() : reject(new Error("execCommand copy refused"));
      } catch (e) { reject(e); }
    });
  }

  /** The dashboard's own chat tab, carrying the profile this page is scoped to. */
  function chatHref() {
    var p = null;
    try { p = new URLSearchParams(window.location.search).get("profile"); } catch (e) { /* ignore */ }
    return "/chat" + (p ? "?profile=" + encodeURIComponent(p) : "");
  }

  function CardTools(props) {
    var it = props.item;
    var [note, setNote] = useState(null);
    function copyOnly(what) {
      var text = what === "id" ? it.id : (it.briefing || it.id);
      copyText(text).then(function () {
        setNote(what === "id" ? "id copied" : "context copied — paste it into the chat");
      }, function (e) { setNote("copy failed: " + e.message); });
    }
    function chatNow() {
      // Open first, inside the click gesture: a popup opened after an await gets blocked.
      try { window.open(chatHref(), "_blank", "noopener"); } catch (e) { /* popup blocked */ }
      copyText(it.briefing || it.id).then(function () {
        setNote("chat opened + context copied → paste with Ctrl-V");
      }, function () { setNote("chat opened — copy the context by hand"); });
    }
    return h("div", { className: "mc-tools" },
      h("span", { className: "mc-id", title: "card id — click to copy", onClick: function () { copyOnly("id"); } }, it.id),
      h("button", { className: "mc-btn", onClick: function () { copyOnly("ctx"); } }, "Copy context"),
      h("button", { className: "mc-btn mc-btn-p", onClick: chatNow }, "Chat about it ↗"),
      props.extra || null,
      note ? h("span", { className: "mc-ok" }, note) : null);
  }

  function IdChip(props) {
    var [done, setDone] = useState(false);
    return h("span", {
      className: "mc-id", title: "click to copy this card id",
      onClick: function () { copyText(props.id).then(function () { setDone(true); setTimeout(function () { setDone(false); }, 1500); }); }
    }, done ? "copied" : props.id);
  }

  // ---------------------------------------------------------------- primitives
  function Pill(props) { return h("span", { className: "mc-pill " + (props.kind || "") }, props.children); }
  function Stat(props) {
    return h("div", { className: "mc-stat" + (props.tone ? " mc-stat-" + props.tone : "") },
      h("div", { className: "mc-stat-k" }, props.k),
      h("div", { className: "mc-stat-v" }, props.v),
      props.n ? h("div", { className: "mc-stat-n" }, props.n) : null);
  }
  function Panel(props) {
    return h("div", { className: "mc-card" + (props.className ? " " + props.className : "") },
      h("div", { className: "mc-card-h" },
        h("div", { className: "mc-card-t" }, props.title),
        props.sub ? h("div", { className: "mc-card-s" }, props.sub) : null,
        props.right || null),
      h("div", { className: "mc-card-c" }, props.children));
  }
  function PageHead(props) {
    return h("div", { className: "mc-head" },
      h("div", { className: "mc-title" }, props.title),
      h("div", { className: "mc-sub" }, props.sub),
      h("div", { className: "mc-spacer" }),
      props.children);
  }

  // ---------------------------------------------------------------- charts (hand-rolled SVG/CSS)
  function Spark(props) {
    var pts = props.points || [];
    if (!pts.length) return h("div", { className: "mc-muted" }, "no activity in window");
    var w = 600, hgt = props.height || 70, max = Math.max(1, pts.reduce(function (m, p) { return Math.max(m, p.count); }, 1));
    var step = pts.length > 1 ? w / (pts.length - 1) : w;
    var coords = pts.map(function (p, i) {
      return [i * step, hgt - (p.count / max) * (hgt - 10) - 5];
    });
    var line = coords.map(function (c) { return c[0].toFixed(1) + "," + c[1].toFixed(1); }).join(" ");
    return h("div", null,
      h("svg", { className: "mc-spark", viewBox: "0 0 " + w + " " + hgt, preserveAspectRatio: "none", role: "img" },
        h("polygon", { points: "0," + hgt + " " + line + " " + w + "," + hgt, className: "mc-spark-area" }),
        h("polyline", { points: line, className: "mc-spark-line" })),
      h("div", { className: "mc-row-m" },
        h("span", null, "peak " + max + " events/10m"),
        h("span", null, pts.length + " buckets"),
        h("span", null, props.label || "")));
  }

  function GroupedBars(props) {
    var rows = props.rows || [], series = props.series || [];
    if (!rows.length) return h("div", { className: "mc-muted" }, "nothing in this window");
    var max = Math.max(1, rows.reduce(function (m, r) {
      return Math.max(m, series.reduce(function (n, s) { return Math.max(n, r[s.key] || 0); }, 0));
    }, 1));
    return h("div", null,
      h("div", { className: "mc-gbars" }, rows.map(function (r, i) {
        return h("div", {
          key: i, className: "mc-gbars-col",
          title: hourLabel(r.t) + " — " + series.map(function (s) { return s.label + " " + (r[s.key] || 0); }).join(", ")
        }, series.map(function (s) {
          return h("div", { key: s.key, className: "mc-gbar " + (s.cls || ""), style: { height: Math.max(1, ((r[s.key] || 0) / max) * 100) + "%" } });
        }));
      })),
      h("div", { className: "mc-legend" }, series.map(function (s, i) {
        return h("span", { key: i, className: "mc-legend-i" }, h("i", { className: "mc-swatch " + (s.cls || "") }), s.label);
      })));
  }

  function StackBar(props) {
    var segs = (props.segments || []).filter(function (s) { return s.value > 0; });
    var total = segs.reduce(function (n, s) { return n + s.value; }, 0) || 1;
    return h("div", null,
      h("div", { className: "mc-stack" }, segs.map(function (s, i) {
        return h("div", { key: i, className: "mc-stack-seg " + (s.cls || ""), style: { width: (s.value / total) * 100 + "%" }, title: s.label + ": " + s.value });
      })),
      h("div", { className: "mc-legend" }, segs.map(function (s, i) {
        return h("span", { key: i, className: "mc-legend-i" }, h("i", { className: "mc-swatch " + (s.cls || "") }), s.label + " " + num(s.value));
      })));
  }

  function HBars(props) {
    var rows = props.rows || [];
    if (!rows.length) return h("div", { className: "mc-muted" }, "nothing to show");
    var max = Math.max(1, rows.reduce(function (m, r) { return Math.max(m, r.value); }, 1));
    return h("div", { className: "mc-hbars" }, rows.map(function (r, i) {
      return h("div", { key: i, className: "mc-hbar" },
        h("div", { className: "mc-hbar-l", title: r.title || r.label }, r.label),
        h("div", { className: "mc-hbar-track" }, h("div", { className: "mc-hbar-fill " + (r.cls || ""), style: { width: Math.max(1, (r.value / max) * 100) + "%" } })),
        h("div", { className: "mc-hbar-v" }, num(r.value), r.sub ? h("span", { className: "mc-muted" }, " " + r.sub) : null));
    }));
  }

  // ---------------------------------------------------------------- answer surface
  function AskRow(props) {
    var item = props.item;
    var [open, setOpen] = useState(false);
    var [choice, setChoice] = useState(item.recommendation || null);
    var [text, setText] = useState("");
    var [busy, setBusy] = useState(false);
    var [msg, setMsg] = useState(null);
    var [err, setErr] = useState(null);

    function send(unblock) {
      setBusy(true); setErr(null); setMsg(null);
      fetchJSON(API + "/answer", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          board: item.board, task_id: item.id, choice: choice,
          option_text: choice ? item.options[choice - 1] : null,
          text: text, unblock: unblock
        })
      }).then(function (r) {
        setBusy(false);
        setMsg("sent — card " + r.status_before + " → " + r.status_after + " (comment #" + r.comment_id + ")");
        setText("");
        if (props.onDone) props.onDone();
      }).catch(function (e) { setBusy(false); setErr(String((e && e.message) || e)); });
    }

    return h("div", { className: "mc-row" + (props.highlight ? " mc-row-hi" : "") },
      h("div", { className: "mc-row-h" },
        h("div", { style: { flex: "1 1 auto" } },
          h("div", { className: "mc-row-t" }, item.title),
          h("div", { className: "mc-row-m" },
            h(Pill, { kind: "mc-pill-me" }, "needs you"),
            h("span", null, "project: " + (item.board_title || item.board)),
            h("span", null, "asked by " + (item.assignee || "unknown")),
            h("span", null, "parked " + dur(item.age_seconds) + " ago"),
            h("span", null, item.comments + " comments"),
            (item.hints || []).map(function (x) { return h(Pill, { key: x, kind: "mc-pill-warn" }, x); }))),
        h("button", { className: "mc-btn", onClick: function () { setOpen(!open); } }, open ? "hide" : "open")),
      h(CardTools, { item: item }),
      item.summary ? h("div", { className: "mc-sum" }, item.summary) : null,
      !open && item.ask ? h("div", { className: "mc-ask" }, item.ask.slice(0, 320) + (item.ask.length > 320 ? "…" : "")) : null,
      open ? h("div", { className: "mc-cards" },
        item.ask ? h("div", { className: "mc-ask" }, item.ask) : null,
        (item.options || []).map(function (o, i) {
          var n = i + 1, rec = item.recommendation === n;
          return h("button", {
            key: n, className: "mc-opt" + (choice === n ? " mc-opt-on" : ""),
            onClick: function () { setChoice(n); }
          },
            h("span", { className: "mc-opt-n" }, n + "."),
            h("span", { style: { flex: "1 1 auto" } }, o),
            rec ? h(Pill, { kind: "mc-pill-rec" }, "recommended") : null);
        }),
        h("textarea", {
          className: "mc-ta", value: text, placeholder: "Answer, nuance, or constraints (optional)…",
          onChange: function (e) { setText(e.target.value); }
        }),
        h("div", { className: "mc-actions" },
          h("button", { className: "mc-btn mc-btn-p", disabled: busy || (choice == null && !text.trim()), onClick: function () { send(true); } },
            busy ? "sending…" : "Answer & re-open card"),
          h("button", { className: "mc-btn", disabled: busy || !text.trim(), onClick: function () { send(false); } },
            "Comment only (stay parked)"),
          !item.framed ? h(Pill, { kind: "mc-pill-warn" }, "no framed options") : null)) : null,
      msg ? h("div", { className: "mc-ok" }, msg) : null,
      err ? h("div", { className: "mc-err" }, err) : null);
  }

  // ---------------------------------------------------------------- card detail
  function CardDetail(props) {
    var ref = props.target;
    var [st, set] = useState({ data: null, error: null });
    useEffect(function () {
      fetchJSON(API + "/card?board=" + encodeURIComponent(ref.board) + "&id=" + encodeURIComponent(ref.id))
        .then(function (d) { set({ data: d, error: null }); })
        .catch(function (e) { set({ data: null, error: String((e && e.message) || e) }); });
    }, [ref.board, ref.id]);
    var right = h("button", { className: "mc-btn", onClick: props.onClose }, "close");
    if (st.error) return h(Panel, { title: "Card " + ref.id, right: right }, h("div", { className: "mc-err" }, st.error));
    if (!st.data) return h(Panel, { title: "Card " + ref.id, right: right }, h("div", { className: "mc-muted" }, "loading…"));
    var d = st.data, t = d.task;
    return h(Panel, {
      title: t.title,
      right: h("div", { className: "mc-actions" },
        h(Pill, null, d.board_title || ref.board), h(Pill, null, t.status),
        t.block_kind ? h(Pill, { kind: "mc-pill-warn" }, t.block_kind) : null, right)
    },
      h("div", { className: "mc-row-m" },
        h(IdChip, { id: t.id }),
        t.assignee ? h("span", null, "assignee " + t.assignee) : null,
        h("span", null, "created " + hhmm(t.created_at)),
        t.branch_name ? h("span", null, t.branch_name) : null,
        d.parents.length ? h("span", null, "parents: " + d.parents.map(function (p) { return p.id + "(" + p.status + ")"; }).join(", ")) : null),
      (d.hints || []).length ? h("div", { className: "mc-row-m" },
        (d.hints || []).map(function (x) { return h(Pill, { key: x, kind: "mc-pill-warn" }, x); })) : null,
      h(CardTools, {
        item: { id: t.id, briefing: d.briefing },
        extra: h("span", { className: "mc-muted" }, "cli: hermes kanban --board " + ref.board + " show " + t.id)
      }),
      h("details", { className: "mc-brief" },
        h("summary", null, "the context block that gets copied (select it by hand if the clipboard is blocked)"),
        h("pre", { className: "mc-brief-pre" }, d.briefing || "")),
      d.frame && d.frame.summary ? h("div", { className: "mc-sum" }, d.frame.summary) : null,
      h("div", { className: "mc-body" }, t.body || "(no body)"),
      h("div", { className: "mc-muted" }, "ask (newest park reason)"),
      h("div", { className: "mc-ask" }, d.ask || "(none recorded)"),
      h("div", { className: "mc-muted" }, "runs: " + d.runs.length + " · comments: " + d.comments.length),
      h("div", { className: "mc-cards" }, d.comments.slice(0, 8).map(function (c) {
        return h("div", { key: c.id, className: "mc-cmt" },
          h("div", { className: "mc-row-m" }, h("span", null, c.author || "?"), h("span", null, hhmm(c.created_at))),
          h("div", { className: "mc-cmt-b" }, c.body.length > 1200 ? c.body.slice(0, 1200) + "…" : c.body));
      })));
  }

  // ---------------------------------------------------------------- shared drawer state
  function useDetail() {
    var [detail, setDetail] = useState(null);
    var node = detail ? h(CardDetail, { target: detail, onClose: function () { setDetail(null); } }) : null;
    return [detail, setDetail, node];
  }
