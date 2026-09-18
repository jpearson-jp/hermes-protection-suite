/* Protection Suite — shared core (adapted from Mission Control's, same measured SDK contract).
 *
 * Loaded INSIDE the plugin IIFE (see build.sh): the header defines SDK/React/h, this file adds the
 * helpers and pieces the page uses, then the page file defines its component and the footer
 * registers it. No module system, no build step beyond `cat`.
 *
 * Everything here is CALLED by pages/suite.js. Copied components that no page renders were removed
 * on purpose: a dead surface (a chart, a detail drawer, an answer form pointed at a route this
 * backend does not define) is a defect with a fuse on it — the render check that caught a bundle
 * still pointing at the mission-control API is what a dead surface costs when someone wires it up.
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
  function num(n) {
    if (n == null) return "—";
    return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  }

  /** A tenant's own hue AND pattern, derived from its name so the same tenant looks the same
   *  everywhere. r4 asks a switch to be VISIBLY changed, not just labelled: a screenshot of a
   *  forwarded dashboard must be unambiguous about which tenant it shows. Two tenants can hash to
   *  neighbouring hues, so the stripe ANGLE is derived from the name too — colour alone would let a
   *  pair like kit/onestack read as "the same red" at a glance. */
  function tenantHue(name) {
    var s = String(name || "all"), h = 0;
    for (var i = 0; i < s.length; i++) { h = (h * 31 + s.charCodeAt(i)) % 360; }
    return h;
  }
  function tenantCss(name) {
    var hue = tenantHue(name);
    var angle = 10 + (hue % 5) * 34;          // five distinct stripe angles
    var stripe = 6 + (hue % 3) * 4;           // three stripe widths
    return {
      borderColor: "hsl(" + hue + ", 60%, 55%)",
      background: "repeating-linear-gradient(" + angle + "deg, hsla(" + hue + ", 60%, 55%, .16) 0 "
        + stripe + "px, transparent " + stripe + "px " + (stripe * 2) + "px)",
      borderLeftWidth: "5px"
    };
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

  // ---------------------------------------------------------------- the owner write path
  // There is deliberately NO ask/answer form in this bundle. The two writes this plugin exposes
  // (POST /answer, POST /comment) are owner-authored console actions for the automation tiers and
  // for tenant-scoped answers; the estate's human ask-inbox is Mission Control's "Waiting on me",
  // which renders the same park rows and posts to its own /answer. A second answer form here would
  // be a second surface for the same question, and the design forbids exactly that (04 §3.4 rule 4:
  // one query layer, or the surfaces will disagree).
