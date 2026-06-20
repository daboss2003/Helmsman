// Minimal client glue. The admin CSP is script-src 'self' (no inline scripts),
// so all behavior lives here. For now this only wires the CSRF token into any
// future htmx requests; htmx/Alpine are vendored in a later milestone (M7).
(function () {
  "use strict";
  var meta = document.querySelector('meta[name="csrf-token"]');
  var token = meta ? meta.getAttribute("content") : "";
  // When htmx is present (vendored in a later milestone), attach the token.
  document.body.addEventListener("htmx:configRequest", function (evt) {
    if (token) evt.detail.headers["X-CSRF-Token"] = token;
  });

  // Lifecycle + log streaming (M4). Buttons carry data-lc-url (POST, streamed
  // response) or data-log-url (GET, SSE). The CSRF token rides the header.
  var logSource = null;

  // showStream reveals a streaming <pre> (logs / deploy output) and ensures a "Close"
  // button sits just above it — so an opened log/output panel can always be dismissed
  // (closing also stops an active SSE log stream).
  function showStream(pre) {
    if (!pre) return;
    pre.hidden = false;
    var prev = pre.previousElementSibling;
    if (prev && prev.classList && prev.classList.contains("stream-close")) {
      prev.hidden = false;
      return;
    }
    var closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.className = "stream-close btn btn-sm btn-ghost";
    closeBtn.textContent = "✕ Close";
    closeBtn.addEventListener("click", function () {
      if (logSource) { logSource.close(); logSource = null; }
      pre.hidden = true;
      pre.textContent = "";
      closeBtn.hidden = true;
    });
    pre.parentNode.insertBefore(closeBtn, pre);
  }

  document.addEventListener("click", function (evt) {
    var btn = evt.target.closest ? evt.target.closest("[data-lc-url],[data-log-url],[data-reveal-url]") : null;
    if (!btn) return;
    evt.preventDefault();

    // Reveal/hide a secret (toggle): audited POST → text/plain. Set textContent
    // (NEVER innerHTML) so a secret value can't become markup (plan §5.5).
    var revURL = btn.getAttribute("data-reveal-url");
    if (revURL) {
      var key = btn.getAttribute("data-reveal-key");
      var span = document.getElementById("reveal-" + key);
      if (!span) return;
      // Already revealed → re-hide by restoring the saved mask. No re-fetch.
      if (btn.getAttribute("data-revealed") === "1") {
        span.textContent = btn.getAttribute("data-mask") || "";
        btn.setAttribute("data-revealed", "0");
        btn.textContent = "reveal";
        return;
      }
      // First reveal: remember the mask so we can restore it on hide.
      if (btn.getAttribute("data-mask") === null) btn.setAttribute("data-mask", span.textContent);
      var body = new URLSearchParams(); body.set("key", key);
      fetch(revURL, {
        method: "POST", credentials: "same-origin",
        headers: { "X-CSRF-Token": token, "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
      }).then(function (r) { return r.ok ? r.text() : null; })
        .then(function (txt) {
          if (txt !== null) {
            span.textContent = txt;
            btn.setAttribute("data-revealed", "1");
            btn.textContent = "hide";
          }
        }).catch(function () {});
      return;
    }

    var logURL = btn.getAttribute("data-log-url");
    if (logURL) {
      var logOut = document.getElementById("log-output");
      if (!logOut) return;
      if (logSource) logSource.close();
      showStream(logOut);
      logOut.textContent = "… connecting to logs …\n";
      logSource = new EventSource(logURL);
      logSource.onmessage = function (e) {
        logOut.textContent += e.data + "\n";
        logOut.scrollTop = logOut.scrollHeight;
      };
      logSource.onerror = function () { logOut.textContent += "\n[log stream ended]\n"; logSource.close(); };
      return;
    }

    var lcURL = btn.getAttribute("data-lc-url");
    if (!lcURL) return;
    var confirmMsg = btn.getAttribute("data-lc-confirm");
    if (confirmMsg && !window.confirm(confirmMsg)) return;
    var out = document.getElementById("deploy-output");
    if (out) { showStream(out); out.textContent = "$ " + lcURL + "\n"; }
    btn.disabled = true;
    fetch(lcURL, {
      method: "POST",
      credentials: "same-origin",
      headers: token ? { "X-CSRF-Token": token } : {},
    }).then(function (resp) {
      var reader = resp.body.getReader();
      var dec = new TextDecoder();
      function pump() {
        return reader.read().then(function (r) {
          if (r.done) { btn.disabled = false; return; }
          if (out) { out.textContent += dec.decode(r.value, { stream: true }); out.scrollTop = out.scrollHeight; }
          return pump();
        });
      }
      return pump();
    }).catch(function (e) {
      if (out) out.textContent += "\n[request failed: " + e + "]\n";
      btn.disabled = false;
    });
  });

  // Config-file preview: POST template+bindings, render with secrets masked
  // server-side, show as textContent (never innerHTML).
  var pv = document.getElementById("cfg-preview-btn");
  if (pv) {
    pv.addEventListener("click", function () {
      var form = pv.closest("form");
      if (!form) return;
      var body = new URLSearchParams();
      body.set("template", form.querySelector("[name=template]").value);
      body.set("bindings", form.querySelector("[name=bindings]").value);
      var out = document.getElementById("cfg-preview");
      fetch(form.getAttribute("action") + "/preview", {
        method: "POST", credentials: "same-origin",
        headers: { "X-CSRF-Token": token, "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
      }).then(function (r) { return r.text(); })
        .then(function (t) { if (out) { showStream(out); out.textContent = t; } })
        .catch(function () {});
    });
  }

  // Draggable tile grid (M7). Tiles carry data-project; on drop we persist the
  // new order to the server (CSRF via header). Delegated so it survives the live
  // poll re-render. Dragging never navigates (we cancel the click after a drag).
  var dragEl = null;
  var didDrag = false;
  document.addEventListener("dragstart", function (e) {
    var tile = e.target.closest ? e.target.closest(".tile[data-project]") : null;
    if (!tile) return;
    dragEl = tile;
    didDrag = true;
    try { e.dataTransfer.effectAllowed = "move"; e.dataTransfer.setData("text/plain", tile.getAttribute("data-project")); } catch (_) {}
  });
  document.addEventListener("dragover", function (e) {
    if (!dragEl) return;
    var grid = dragEl.parentNode;
    var over = e.target.closest ? e.target.closest(".tile[data-project]") : null;
    if (!over || over === dragEl || over.parentNode !== grid) return;
    e.preventDefault();
    var tiles = Array.prototype.slice.call(grid.children);
    if (tiles.indexOf(dragEl) < tiles.indexOf(over)) grid.insertBefore(dragEl, over.nextSibling);
    else grid.insertBefore(dragEl, over);
  });
  document.addEventListener("drop", function (e) {
    if (!dragEl) return;
    e.preventDefault();
    var grid = dragEl.parentNode;
    dragEl = null;
    var order = Array.prototype.map.call(grid.querySelectorAll(".tile[data-project]"), function (t) {
      return t.getAttribute("data-project");
    }).join(",");
    var body = new URLSearchParams(); body.set("order", order);
    fetch("/settings/tile-order", {
      method: "POST", credentials: "same-origin",
      headers: { "X-CSRF-Token": token, "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    }).catch(function () {});
  });
  // Swallow the click that fires at the end of a drag so a reorder doesn't also
  // navigate into the app.
  document.addEventListener("click", function (e) {
    if (!didDrag) return;
    didDrag = false;
    var tile = e.target.closest ? e.target.closest(".tile[data-project]") : null;
    if (tile) { e.preventDefault(); }
  }, true);

  // Provisioning wizard: validate (dry preview). Serialize the whole form and
  // POST it to data-validate-url; show the §5.6 result as text (never innerHTML).
  var pvb = document.getElementById("provision-validate-btn");
  if (pvb) {
    pvb.addEventListener("click", function () {
      var form = document.getElementById("provision-form");
      if (!form) return;
      var out = document.getElementById("provision-preview");
      var body = new URLSearchParams(new FormData(form));
      fetch(pvb.getAttribute("data-validate-url"), {
        method: "POST", credentials: "same-origin",
        headers: { "X-CSRF-Token": token, "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
      }).then(function (r) { return r.text(); })
        .then(function (t) { if (out) { showStream(out); out.textContent = t; } })
        .catch(function () {});
    });
  }

  // Confirm-on-submit for any form carrying data-confirm (CSP-safe; no inline JS).
  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (form && form.getAttribute && form.getAttribute("data-confirm")) {
      if (!window.confirm(form.getAttribute("data-confirm"))) e.preventDefault();
    }
  });

  // pageVisible reports whether the tab is currently being looked at. All the live
  // refreshers below skip work while hidden — there is no reason to fetch (or to
  // wake the server's git poller) for a dashboard nobody is watching.
  function pageVisible() { return document.visibilityState === "visible"; }

  // onVisibleNow runs fn each time the tab becomes visible (and once now if it
  // already is) — so returning to a backgrounded tab refreshes immediately rather
  // than waiting out the interval with stale data on screen.
  function onVisibleNow(fn) {
    if (pageVisible()) fn();
    document.addEventListener("visibilitychange", function () { if (pageVisible()) fn(); });
  }

  // ---- focused-dashboard heartbeat ----
  // Helmsman never auto-deploys, so polling git when nobody is looking is wasted
  // server work. The page pings /dash/ping on load and every ~40s WHILE visible
  // (and immediately on regaining focus); the server's git poller only fetches
  // within a short window after a ping. Hidden tab -> no pings -> no polling.
  (function heartbeat() {
    var ping = function () {
      if (!pageVisible()) return;
      fetch("/dash/ping", { credentials: "same-origin", redirect: "error", headers: { "X-Requested-With": "fetch" } })
        .catch(function () { /* transient; next tick */ });
    };
    onVisibleNow(ping);
    setInterval(ping, 40000);
  })();

  // Lightweight live refresh: any element with data-poll-url is periodically
  // refreshed by fetching that fragment and swapping its innerHTML. Same-origin,
  // GET-only, cookie-authenticated; CSP-safe (this file is script-src 'self').
  // Skipped while hidden; refreshes immediately on regaining focus.
  document.querySelectorAll("[data-poll-url]").forEach(function (el) {
    var url = el.getAttribute("data-poll-url");
    var ms = parseInt(el.getAttribute("data-poll-interval") || "5000", 10);
    if (!url || ms < 1000) return;
    var pull = function () {
      if (!pageVisible()) return;
      fetch(url, { credentials: "same-origin", redirect: "error", headers: { "X-Requested-With": "fetch" } })
        .then(function (r) { return r.ok ? r.text() : null; })
        .then(function (html) { if (html !== null) el.innerHTML = html; })
        .catch(function () { /* transient; try again next tick */ });
    };
    setInterval(pull, ms);
    document.addEventListener("visibilitychange", function () { if (pageVisible()) pull(); });
  });

  // ---- shell: sidebar active link + mobile toggle + topbar title ----
  var layout = document.querySelector("[data-layout]");
  var toggle = document.querySelector("[data-menu-toggle]");
  var scrim = document.querySelector("[data-scrim]");
  if (toggle && layout) toggle.addEventListener("click", function () { layout.classList.toggle("menu-open"); });
  if (scrim && layout) scrim.addEventListener("click", function () { layout.classList.remove("menu-open"); });

  (function markActiveNav() {
    var path = location.pathname;
    document.querySelectorAll("[data-nav]").forEach(function (a) {
      var href = a.getAttribute("href");
      if (!href) return;
      var exact = a.hasAttribute("data-exact");
      var hit = exact ? path === href : (path === href || path.indexOf(href + "/") === 0);
      if (hit) a.classList.add("nav-active");
    });
  })();

  (function setTopbarTitle() {
    var h1 = document.querySelector("main.wrap h1");
    var tt = document.querySelector("[data-page-title]");
    if (h1 && tt) tt.textContent = h1.textContent.trim();
  })();

  // ---- live host charts (CSP-safe: SVG built via the DOM, no inline script) ----
  var SVGNS = "http://www.w3.org/2000/svg";
  function el(name, attrs) {
    var n = document.createElementNS(SVGNS, name);
    for (var k in attrs) n.setAttribute(k, attrs[k]);
    return n;
  }
  // drawArea renders a 0..100 (%) series into an <svg> as a grid + gradient area +
  // line. The line uses non-scaling-stroke so it stays crisp under the stretched
  // viewBox. Returns true when it drew real data, false when the series was empty.
  function drawArea(svg, values) {
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    var W = 300, H = 140;
    svg.setAttribute("viewBox", "0 0 " + W + " " + H);
    svg.setAttribute("preserveAspectRatio", "none");
    [0.25, 0.5, 0.75].forEach(function (g) {
      var y = H - g * H;
      svg.appendChild(el("line", { x1: 0, y1: y, x2: W, y2: y, class: "grid-line", "vector-effect": "non-scaling-stroke" }));
    });
    if (!values || values.length < 2) return false;
    var n = values.length;
    function x(i) { return (i / (n - 1)) * W; }
    function y(v) { var c = v < 0 ? 0 : (v > 100 ? 100 : v); return H - (c / 100) * H; }
    // A vertical gradient for the area fill (its own id per chart).
    var gid = "grad-" + (svg.getAttribute("data-chart") || "x");
    var defs = el("defs");
    var lg = el("linearGradient", { id: gid, x1: "0", y1: "0", x2: "0", y2: "1" });
    lg.appendChild(el("stop", { offset: "0%", "stop-color": "currentColor", "stop-opacity": "0.35" }));
    lg.appendChild(el("stop", { offset: "100%", "stop-color": "currentColor", "stop-opacity": "0.02" }));
    defs.appendChild(lg);
    svg.appendChild(defs);
    var line = "M" + x(0) + " " + y(values[0]);
    for (var i = 1; i < n; i++) line += " L" + x(i) + " " + y(values[i]);
    var area = line + " L" + W + " " + H + " L0 " + H + " Z";
    svg.appendChild(el("path", { d: area, fill: "url(#" + gid + ")", stroke: "none" }));
    svg.appendChild(el("path", { d: line, class: "line", stroke: "currentColor", "vector-effect": "non-scaling-stroke" }));
    return true;
  }
  function pct(used, total) { return total > 0 ? (used / total) * 100 : 0; }
  // Hover read-out: a vertical guide line follows the cursor and the chart's header
  // number shows the exact value at that point (like a real chart's tooltip). Built
  // from SVG attributes only (CSP-safe); the guide uses non-scaling-stroke so it stays
  // crisp under the stretched viewBox.
  function setupChartHover(svg) {
    var W = 300, H = 140;
    var key = svg.getAttribute("data-chart");
    var nowEl = document.querySelector('[data-chart-now="' + key + '"]');
    var restore = function () {
      var g = svg.querySelector(".hover-guide");
      if (g) svg.removeChild(g);
      svg.__hovering = false;
      var vals = svg.__vals;
      if (nowEl) nowEl.textContent = (vals && vals.length) ? Math.round(vals[vals.length - 1]) + "%" : "—";
    };
    svg.addEventListener("mousemove", function (e) {
      var vals = svg.__vals;
      if (!vals || vals.length < 2) return;
      var rect = svg.getBoundingClientRect();
      if (rect.width <= 0) return;
      var frac = (e.clientX - rect.left) / rect.width;
      frac = frac < 0 ? 0 : (frac > 1 ? 1 : frac);
      var idx = Math.round(frac * (vals.length - 1));
      var gx = (idx / (vals.length - 1)) * W;
      var g = svg.querySelector(".hover-guide");
      if (!g) { g = el("line", { class: "hover-guide", "vector-effect": "non-scaling-stroke" }); svg.appendChild(g); }
      g.setAttribute("x1", gx); g.setAttribute("y1", 0); g.setAttribute("x2", gx); g.setAttribute("y2", H);
      svg.__hovering = true;
      if (nowEl) nowEl.textContent = vals[idx].toFixed(1) + "%";
    });
    svg.addEventListener("mouseleave", restore);
  }
  var charts = document.querySelectorAll("[data-chart]");
  if (charts.length) {
    charts.forEach(setupChartHover);
    var refreshCharts = function () {
      if (!pageVisible()) return;
      fetch("/partials/metrics.json", { credentials: "same-origin", redirect: "error", headers: { "X-Requested-With": "fetch" } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (data) {
          var pts = (data && data.points) || [];
          var series = {
            cpu: pts.map(function (p) { return p.cpu; }),
            mem: pts.map(function (p) { return pct(p.memUsed, p.memTotal); }),
            disk: pts.map(function (p) { return pct(p.diskUsed, p.diskTotal); }),
          };
          charts.forEach(function (svg) {
            var key = svg.getAttribute("data-chart");
            var vals = series[key];
            var drew = drawArea(svg, vals);
            svg.__vals = drew ? vals : null; // for hover read-out
            var empty = document.querySelector('[data-chart-empty="' + key + '"]');
            if (empty) empty.style.display = drew ? "none" : "";
            var now = document.querySelector('[data-chart-now="' + key + '"]');
            // Don't clobber the read-out while the cursor is parked on the chart.
            if (now && !svg.__hovering) now.textContent = (drew && vals.length) ? Math.round(vals[vals.length - 1]) + "%" : "—";
          });
        })
        .catch(function () { /* transient */ });
    };
    onVisibleNow(refreshCharts);
    setInterval(refreshCharts, 5000);
  }
})();
