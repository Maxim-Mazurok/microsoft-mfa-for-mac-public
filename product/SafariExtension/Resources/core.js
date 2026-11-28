/* Pure, shared validation. Never accepts full URLs as exported context. */
(function (root) {
  "use strict";
  const ORIGINS = new Set(["https://login.microsoftonline.com", "https://login.microsoft.com", "https://login.windows.net"]);
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const localID = /^[a-zA-Z0-9_-]{1,80}$/;
  const allowedKeys = new Set(["version", "kind", "event_id", "tab_id", "document_id", "origin", "observed_at", "number", "account", "application", "session_id", "request_id", "focused", "flow", "remote_session_hash"]);
  function origin(url) { try { const u = new URL(url); return ORIGINS.has(u.origin) && !u.username && !u.password ? u.origin : null; } catch { return null; } }
  function account(value) { if (typeof value !== "string") return ""; value = value.trim().toLowerCase(); return value.length <= 254 && /^[^\s<>@\x00-\x1f]+@[^\s<>@\x00-\x1f]+\.[^\s<>@\x00-\x1f]+$/.test(value) ? value : ""; }
  function plain(value, limit = 160) { return typeof value === "string" && value.length <= limit && !/[\x00-\x1f<>]/.test(value) ? value.trim() : ""; }
  function identifier(value) { return typeof value === "string" && UUID.test(value) ? value.toLowerCase() : ""; }
  function number(value) { return typeof value === "string" && /^\d{2}$/.test(value.trim()) ? value.trim() : ""; }
  function validEvent(value, now = Date.now() / 1000) {
    if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some(k => !allowedKeys.has(k))) return false;
    if (value.version !== 1 || !["challenge", "withdraw"].includes(value.kind) || !ORIGINS.has(value.origin)) return false;
    if (![value.event_id, value.tab_id, value.document_id].every(x => typeof x === "string" && localID.test(x))) return false;
    if (typeof value.observed_at !== "number" || !Number.isFinite(value.observed_at) || now - value.observed_at > 120 || value.observed_at - now > 5 || typeof value.focused !== "boolean") return false;
    if (value.kind === "withdraw") return value.focused === false && Object.keys(value).every(k => ["version", "kind", "event_id", "tab_id", "document_id", "origin", "observed_at", "focused"].includes(k));
    if (!number(value.number) || !account(value.account) || value.account !== account(value.account) || plain(value.application) !== value.application) return false;
    const flow = value.flow === undefined ? "classic_mfa" : value.flow;
    if (flow === "remote_ngc") return value.session_id === "" && value.request_id === "" && typeof value.remote_session_hash === "string" && /^(?:[a-f0-9]{64})?$/.test(value.remote_session_hash);
    return flow === "classic_mfa" && (value.remote_session_hash === undefined || value.remote_session_hash === "") &&
      typeof value.session_id === "string" && typeof value.request_id === "string" &&
      (!value.session_id || !!identifier(value.session_id)) && (!value.request_id || !!identifier(value.request_id)) && !!(value.session_id || value.request_id);
  }
  function visibleValues(document, selectors, parse) {
    const found = new Set();
    for (const selector of selectors) for (const element of document.querySelectorAll(selector)) {
      if (!visibleElement(element)) continue;
      const result = parse(element.textContent || ""); if (result) found.add(result);
    }
    return found;
  }
  function visibleElement(element) {
    if (!element.getClientRects().length) return false;
    let ancestor = element, depth = 0;
    while (ancestor && depth++ < 64) {
      if (ancestor.hidden || ancestor.getAttribute("aria-hidden") === "true") return false;
      const style = element.ownerDocument.defaultView.getComputedStyle(ancestor);
      if (style.display === "none" || ["hidden", "collapse"].includes(style.visibility) || (style.opacity && Number(style.opacity) === 0)) return false;
      ancestor = ancestor.parentElement;
    }
    return !ancestor;
  }
  function selectVisible(document, selectors, parse) {
    const found = visibleValues(document, selectors, parse);
    return found.size === 1 ? [...found][0] : "";
  }
  function detectFlow(document) {
    const classic = [...document.querySelectorAll("#idRichContext_DisplaySign")].some(visibleElement);
    const remote = [...document.querySelectorAll("#idRemoteNGC_DisplaySign")].some(visibleElement);
    return classic === remote ? "" : remote ? "remote_ngc" : "classic_mfa";
  }
  function readPage(document, metadata = {}) {
    const flow = detectFlow(document);
    if (!flow || (metadata.flow === undefined ? "classic_mfa" : metadata.flow) !== flow) return null;
    const displayed = selectVisible(document, [flow === "remote_ngc" ? "#idRemoteNGC_DisplaySign" : "#idRichContext_DisplaySign"], number);
    const accounts = visibleValues(document, ["#displayName", "#idDiv_SAOTCAS_Description [data-account]", "[data-testid='user-display-name']"], account);
    if (accounts.size > 1) return null;
    const domAccount = accounts.size === 1 ? [...accounts][0] : "";
    const selectedAccount = account(metadata.account);
    if (domAccount && selectedAccount && domAccount !== selectedAccount) return null;
    const user = domAccount || selectedAccount;
    if (!displayed || !user || (metadata.number && displayed !== metadata.number)) return null;
    const context = {flow, number: displayed, account: user, application: selectVisible(document, ["#appDisplayName"], plain)};
    if (flow === "remote_ngc") {
      const hash = metadata.remote_session_hash ?? "";
      if (typeof hash !== "string" || !/^(?:[a-f0-9]{64})?$/.test(hash) || (hash && (!number(metadata.number) || metadata.number !== displayed))) return null;
      return {...context, session_id: "", request_id: "", remote_session_hash: hash};
    }
    const session = identifier(metadata.session_id);
    if (!session || metadata.remote_session_hash) return null;
    return {...context, session_id: session, request_id: ""};
  }
  const api = {ORIGINS, UUID, origin, account, plain, identifier, number, validEvent, detectFlow, readPage};
  root.MFAMac = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(globalThis);
