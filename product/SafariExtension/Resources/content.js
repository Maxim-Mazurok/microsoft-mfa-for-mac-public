(() => {
  "use strict";
  if (window.top !== window || !MFAMac.ORIGINS.has(location.origin)) return;
  const documentNonce = crypto.randomUUID();
  const metadata = {classic_mfa: {}, remote_ngc: {}};
  let currentKey = "", observedAt = 0, scheduled = false, lastContextRequest = 0, priorFlow = "";
  let suspended = false;
  let deliveryGeneration = 0;
  let nativeStatus = "waiting_for_challenge";
  const MAX_AGE_SECONDS = 90;
  async function send(payload, retry = 0, generation = deliveryGeneration) {
    let accepted = false;
    try { const reply = await browser.runtime.sendMessage({type: "observation", document_nonce: documentNonce, ...payload}); nativeStatus = reply?.status || "app_unavailable"; accepted = reply?.ok === true; }
    catch { nativeStatus = "app_unavailable"; }
    // Bounded local app-delivery retries only. Original observation time and
    // context are unchanged; no Google/Microsoft requests occur in this layer.
    if (!accepted && nativeStatus === "app_unavailable" && payload.kind === "challenge" && retry < 3) {
      setTimeout(() => {
        if (!suspended && currentKey && generation === deliveryGeneration && Date.now()/1000 - payload.observed_at <= MAX_AGE_SECONDS) void send(payload, retry + 1, generation);
      }, [2000, 5000, 10000][retry]);
    }
  }
  function scan() {
    scheduled = false;
    if (suspended) return;
    const now = Date.now() / 1000;
    const focused = document.visibilityState === "visible" && document.hasFocus();
    const flow = MFAMac.detectFlow(document);
    if (priorFlow && priorFlow !== flow) {
      metadata[priorFlow] = {};
      window.postMessage({marker: "microsoft-mfa-mac-context-reset-v1", flow: priorFlow}, location.origin);
    }
    priorFlow = flow;
    const selected = metadata[flow] || {};
    if (flow === "remote_ngc" && (!selected.observed_at || now - selected.observed_at > MAX_AGE_SECONDS) && now - lastContextRequest > 1) {
      lastContextRequest = now;
      window.postMessage({marker: "microsoft-mfa-mac-context-request-v1"}, location.origin);
    }
    const page = selected.observed_at && now - selected.observed_at <= MAX_AGE_SECONDS ? MFAMac.readPage(document, selected) : null;
    if (!page || document.visibilityState !== "visible") {
      if (currentKey) { currentKey = ""; send({kind: "withdraw"}); }
      return;
    }
    // A genuine macOS verification sheet may take foreground focus. Preserve an
    // already captured event at its original time, but never capture while blurred.
    if (!focused) return;
    const key = JSON.stringify(page);
    if (currentKey === key) return;
    currentKey = key; observedAt = selected.observed_at; deliveryGeneration += 1;
    send({kind: "challenge", observed_at: observedAt, focused: true, ...page});
  }
  function queue() { if (!suspended && !scheduled) { scheduled = true; queueMicrotask(scan); } }
  window.addEventListener("message", event => {
    if (event.source !== window || event.origin !== location.origin) return;
    if (event.data?.marker === "microsoft-mfa-mac-context-invalidated-v1" && ["classic_mfa", "remote_ngc"].includes(event.data.flow) && Object.keys(event.data).every(k => ["marker", "flow"].includes(k))) {
      metadata[event.data.flow] = {};
      deliveryGeneration += 1;
      if (currentKey && priorFlow === event.data.flow) { currentKey = ""; void send({kind: "withdraw"}); }
      queue(); return;
    }
    if (event.data?.marker !== "microsoft-mfa-mac-selected-context-v1") return;
    const m = event.data;
    if (Object.keys(m).some(k => !["marker", "flow", "session_id", "remote_session_hash", "number", "account", "observed_at"].includes(k))) return;
    if (typeof m.observed_at !== "number" || !Number.isFinite(m.observed_at) || m.observed_at > Date.now()/1000 + 5 || Date.now()/1000 - m.observed_at > MAX_AGE_SECONDS) return;
    const flow = m.flow === undefined ? "classic_mfa" : m.flow;
    if (flow === "classic_mfa") {
      if (!MFAMac.identifier(m.session_id) || m.remote_session_hash) return;
      metadata.classic_mfa = {flow, session_id: MFAMac.identifier(m.session_id), number: MFAMac.number(m.number), account: MFAMac.account(m.account), observed_at: m.observed_at};
    } else if (flow === "remote_ngc") {
      if (m.session_id !== "" || typeof m.remote_session_hash !== "string" || !/^(?:[a-f0-9]{64})?$/.test(m.remote_session_hash) || (m.remote_session_hash && !MFAMac.number(m.number))) return;
      metadata.remote_ngc = {flow, session_id: "", remote_session_hash: m.remote_session_hash, number: MFAMac.number(m.number), account: MFAMac.account(m.account), observed_at: m.observed_at};
    } else return;
    queue();
  });
  const observer = new MutationObserver(queue);
  const observerOptions = {childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ["hidden", "aria-hidden", "style", "class"]};
  observer.observe(document, observerOptions);
  for (const event of ["focus", "blur", "popstate", "hashchange"]) window.addEventListener(event, queue);
  document.addEventListener("visibilitychange", queue);
  window.addEventListener("pagehide", () => { suspended = true; observer.disconnect(); metadata.classic_mfa = {}; metadata.remote_ngc = {}; currentKey = ""; deliveryGeneration += 1; send({kind: "withdraw"}); });
  window.addEventListener("pageshow", () => { suspended = false; observer.observe(document, observerOptions); queue(); });
  // Local lifetime sweep only: no provider/server requests or resend of approvals.
  setInterval(queue, 1000);
  browser.runtime.onMessage.addListener(message => {
    if (message?.type === "rescan") { currentKey = ""; queue(); }
    if (message?.type === "page_status") return Promise.resolve({status: nativeStatus, challenge: !!currentKey});
  });
  window.postMessage({marker: "microsoft-mfa-mac-context-request-v1"}, location.origin);
  queue();
})();
