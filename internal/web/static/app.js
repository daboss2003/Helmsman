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
  document.addEventListener("click", function (evt) {
    var btn = evt.target.closest ? evt.target.closest("[data-lc-url],[data-log-url],[data-reveal-url]") : null;
    if (!btn) return;
    evt.preventDefault();

    // Reveal a secret: audited POST → text/plain. Set textContent (NEVER
    // innerHTML) so a secret value can't become markup (plan §5.5).
    var revURL = btn.getAttribute("data-reveal-url");
    if (revURL) {
      var key = btn.getAttribute("data-reveal-key");
      var body = new URLSearchParams(); body.set("key", key);
      fetch(revURL, {
        method: "POST", credentials: "same-origin",
        headers: { "X-CSRF-Token": token, "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
      }).then(function (r) { return r.ok ? r.text() : null; })
        .then(function (txt) {
          var span = document.getElementById("reveal-" + key);
          if (span && txt !== null) span.textContent = txt;
        }).catch(function () {});
      return;
    }

    var logURL = btn.getAttribute("data-log-url");
    if (logURL) {
      var logOut = document.getElementById("log-output");
      if (!logOut) return;
      if (logSource) logSource.close();
      logOut.hidden = false;
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
    if (out) { out.hidden = false; out.textContent = "$ " + lcURL + "\n"; }
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
        .then(function (t) { if (out) { out.hidden = false; out.textContent = t; } })
        .catch(function () {});
    });
  }

  // Lightweight live refresh: any element with data-poll-url is periodically
  // refreshed by fetching that fragment and swapping its innerHTML. Same-origin,
  // GET-only, cookie-authenticated; CSP-safe (this file is script-src 'self').
  document.querySelectorAll("[data-poll-url]").forEach(function (el) {
    var url = el.getAttribute("data-poll-url");
    var ms = parseInt(el.getAttribute("data-poll-interval") || "5000", 10);
    if (!url || ms < 1000) return;
    setInterval(function () {
      fetch(url, { credentials: "same-origin", redirect: "error", headers: { "X-Requested-With": "fetch" } })
        .then(function (r) { return r.ok ? r.text() : null; })
        .then(function (html) { if (html !== null) el.innerHTML = html; })
        .catch(function () { /* transient; try again next tick */ });
    }, ms);
  });
})();
