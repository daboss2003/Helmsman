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
