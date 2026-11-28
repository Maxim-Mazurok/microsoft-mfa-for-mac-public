/* MAIN world: observes two distinct response types; never initiates network traffic. */
(() => {
  "use strict";
  const ORIGINS = new Set(["https://login.microsoftonline.com", "https://login.microsoft.com", "https://login.windows.net"]);
  if (!ORIGINS.has(location.origin) || window.top !== window) return;
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const marker = "microsoft-mfa-mac-selected-context-v1";
  const maxBytes = 65536;
  let selected = null, remoteSelected = null, remoteGeneration = 0;
  const xhrRequests = new WeakMap();
  function endpoint(raw) {
    try {
      const url = new URL(raw, location.href);
      if (!ORIGINS.has(url.origin) || url.origin !== location.origin || url.username || url.password) return "";
      if (/\/(?:[^/]+\/)?SAS\/BeginAuth$/i.test(url.pathname)) return "classic_mfa";
      if (/^\/[^/]+\/GetOneTimeCode$/i.test(url.pathname)) return "remote_ngc";
      return "";
    } catch { return ""; }
  }
  function selectedAccount() {
    // Explicit public-page account field only; never serialize or export $Config.
    const value = window.$Config?.sPOST_Username;
    return typeof value === "string" && value.length <= 254 && /^[^\s<>@\x00-\x1f]+@[^\s<>@\x00-\x1f]+\.[^\s<>@\x00-\x1f]+$/.test(value) ? value.toLowerCase() : "";
  }
  function invalidate(flow) {
    if (flow === "remote_ngc") { remoteGeneration += 1; remoteSelected = null; }
    else selected = null;
    window.postMessage({marker: "microsoft-mfa-mac-context-invalidated-v1", flow}, location.origin);
  }
  function beginRemoteRequest() {
    invalidate("remote_ngc");
    return {generation: remoteGeneration, account: selectedAccount()};
  }
  function publish() {
    const account = selectedAccount();
    if (selected && selected.account === account) window.postMessage({marker, ...selected}, location.origin);
    if (remoteSelected && remoteSelected.account !== account) invalidate("remote_ngc");
    if (remoteSelected && Date.now()/1000 - remoteSelected.observed_at <= 90) {
      window.postMessage({marker, ...remoteSelected}, location.origin);
    } else if (window.$Config?.oGetCredTypeResult?.Credentials?.HasRemoteNGC === true) {
      // Capability/config evidence is detection only. Never hash the initial
      // opaque SessionIdentifier or confuse top-level telemetry sessionId with SAS.
      window.postMessage({marker, flow: "remote_ngc", session_id: "", remote_session_hash: "", number: "", observed_at: Date.now()/1000, account}, location.origin);
    }
  }
  async function consume(value, flow, transaction) {
    if (flow === "remote_ngc") {
      if (!transaction || transaction.generation !== remoteGeneration || !transaction.account || transaction.account !== selectedAccount()) return;
      const parameters = value?.RemoteNgcParams;
      const identifier = parameters?.SessionIdentifier;
      const entropy = typeof parameters?.Entropy === "number" ? String(parameters.Entropy) : parameters?.Entropy;
      if (typeof identifier !== "string" || !/^[A-Za-z0-9_-]{16,16384}$/.test(identifier) || typeof entropy !== "string" || !/^\d{2}$/.test(entropy)) return;
      const generation = transaction.generation;
      const observedAt = Date.now()/1000;
      try {
        const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("remote_ngc\0" + identifier));
        if (generation !== remoteGeneration || transaction.account !== selectedAccount()) return;
        const hash = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
        remoteSelected = {flow: "remote_ngc", session_id: "", remote_session_hash: hash, number: entropy, observed_at: observedAt, account: transaction.account};
        publish();
      } catch { /* Hashing unavailable: no correlation evidence, no raw fallback. */ }
      return;
    }
    if (flow !== "classic_mfa") return;
    if (!value || typeof value !== "object" || Array.isArray(value) || typeof value.SessionId !== "string" || !UUID.test(value.SessionId)) return;
    const entropy = typeof value.Entropy === "number" ? String(value.Entropy) : value.Entropy;
    selected = {flow: "classic_mfa", session_id: value.SessionId.toLowerCase(), number: typeof entropy === "string" && /^\d{2}$/.test(entropy) ? entropy : "", observed_at: Date.now() / 1000, account: selectedAccount()};
    publish();
  }
  async function consumeResponse(response, transaction) {
    try {
      const flow = endpoint(response.url);
      if (!response.ok || !flow) return;
      const length = Number(response.headers.get("content-length")); if (length > maxBytes) return;
      const reader = response.clone().body?.getReader(); if (!reader) return;
      const chunks = []; let size = 0;
      while (true) { const {done, value} = await reader.read(); if (done) break; size += value.length; if (size > maxBytes) { await reader.cancel(); return; } chunks.push(value); }
      const bytes = new Uint8Array(size); let offset = 0; for (const c of chunks) { bytes.set(c, offset); offset += c.length; }
      await consume(JSON.parse(new TextDecoder().decode(bytes)), flow, transaction);
    } catch { /* Unsupported or non-JSON response remains manual. No logs. */ }
  }
  const originalFetch = window.fetch;
  window.fetch = function (...args) {
    const input = args[0];
    const requestURL = typeof input === "string" ? input : input instanceof URL ? input.href : (typeof Request !== "undefined" && input instanceof Request ? input.url : "");
    const transaction = endpoint(requestURL) === "remote_ngc" ? beginRemoteRequest() : null;
    const response = Reflect.apply(originalFetch, this, args);
    // Only the destination URL is inspected; never body, headers, cookies or tokens.
    response.then(value => consumeResponse(value, transaction), () => {}); return response;
  };
  const originalOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (...args) {
    const request = {flow: typeof args[1] === "string" ? endpoint(args[1]) : "", transaction: null};
    xhrRequests.set(this, request);
    if (request.flow) this.addEventListener("load", () => {
      try {
        const flow = endpoint(this.responseURL);
        if (xhrRequests.get(this) !== request || this.status !== 200 || !flow || flow !== request.flow) return;
        if (this.responseType === "json") void consume(this.response, flow, request.transaction);
        else if ((!this.responseType || this.responseType === "text") && this.responseText.length <= maxBytes) void consume(JSON.parse(this.responseText), flow, request.transaction);
      } catch { /* No page data leaves this failure. */ }
    }, {once: true});
    return Reflect.apply(originalOpen, this, args);
  };
  const originalSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function (...args) {
    const request = xhrRequests.get(this);
    if (request?.flow === "remote_ngc") request.transaction = beginRemoteRequest();
    return Reflect.apply(originalSend, this, args);
  };
  window.addEventListener("message", event => {
    if (event.source !== window || event.origin !== location.origin) return;
    if (event.data?.marker === "microsoft-mfa-mac-context-request-v1") publish();
    if (event.data?.marker === "microsoft-mfa-mac-context-reset-v1" && ["classic_mfa", "remote_ngc"].includes(event.data.flow)) invalidate(event.data.flow);
  });
  for (const event of ["popstate", "hashchange", "pagehide"]) window.addEventListener(event, () => { invalidate("classic_mfa"); invalidate("remote_ngc"); });
  document.addEventListener("DOMContentLoaded", publish, {once: true});
})();
