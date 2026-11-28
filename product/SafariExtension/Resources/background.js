/* Safari background: all browser identity comes from extension APIs. */
(() => {
  "use strict";
  const documents = new Map();
  const sessionKey = "mfa_documents_v1";
  let storageOK = true, storageQueue = Promise.resolve();
  // Only local routing IDs and allowlisted origin survive background suspension.
  // Session storage is browser-memory-only, with no account/number/server IDs.
  const restored = (async () => {
    try {
      await browser.storage.session.setAccessLevel({accessLevel: "TRUSTED_CONTEXTS"});
      const stored = (await browser.storage.session.get(sessionKey))[sessionKey];
      if (stored !== undefined && (!Array.isArray(stored) || stored.length > 32)) throw new Error();
      for (const row of stored || []) {
        if (!row || Object.keys(row).some(k => !["browserTab", "sourceDocument", "tab", "document", "origin", "hasEvent"].includes(k)) ||
            !Number.isInteger(row.browserTab) || row.browserTab < 0 || typeof row.sourceDocument !== "string" || !/^[a-zA-Z0-9_-]{1,128}$/.test(row.sourceDocument) ||
            !MFAMac.UUID.test(row.tab) || !MFAMac.UUID.test(row.document) || !MFAMac.ORIGINS.has(row.origin) || typeof row.hasEvent !== "boolean") throw new Error();
        documents.set(row.browserTab, {sourceDocument: row.sourceDocument, tab: row.tab, document: row.document, origin: row.origin, event: row.hasEvent, key: ""});
      }
      return true;
    } catch { storageOK = false; documents.clear(); return false; }
  })();
  function persist() {
    const rows = [...documents.entries()].map(([browserTab, state]) => ({browserTab, sourceDocument: state.sourceDocument, tab: state.tab, document: state.document, origin: state.origin, hasEvent: !!state.event}));
    const result = storageQueue.then(() => browser.storage.session.set({[sessionKey]: rows})).then(() => true, () => { storageOK = false; return false; });
    storageQueue = result; return result;
  }
  let lastStatus = "app_unavailable";
  let nativeQueue = Promise.resolve();
  const appID = "org.example.microsoftmfamac";
  const statuses = new Set(["delivered", "ready", "app_unavailable", "shared_container_unavailable", "queue_full", "invalid_message", "local_io_failure", "inactive_tab", "unsupported_page", "waiting_for_challenge"]);
  async function deliver(message) {
    try {
      const reply = await browser.runtime.sendNativeMessage(appID, message);
      lastStatus = statuses.has(reply?.status) ? reply.status : "app_unavailable";
      return {ok: reply?.ok === true, status: lastStatus};
    } catch { lastStatus = "app_unavailable"; return {ok: false, status: lastStatus}; }
  }
  function native(message) {
    // Preserve challenge/withdraw ordering even if native extension invocations overlap.
    const result = nativeQueue.then(() => deliver(message));
    nativeQueue = result.catch(() => {}); return result;
  }
  async function withdraw(tabID) {
    const state = documents.get(tabID); documents.delete(tabID);
    await persist();
    if (!state?.event) return;
    const event = {version: 1, kind: "withdraw", event_id: crypto.randomUUID(), tab_id: state.tab, document_id: state.document, origin: state.origin, observed_at: Date.now()/1000, focused: false};
    await native({version: 1, command: "browser_event", browser: event});
  }
  async function observation(message, sender) {
    if (!await restored || !storageOK) return {ok: false, status: "local_io_failure"};
    if (!sender.tab || sender.frameId !== 0 || !Number.isInteger(sender.tab.id)) return {ok: false, status: "unsupported_page"};
    const sourceOrigin = MFAMac.origin(sender.url);
    if (!sourceOrigin || typeof message.document_nonce !== "string" || !MFAMac.UUID.test(message.document_nonce)) return {ok: false, status: "invalid_message"};
    const keys = new Set(["type", "document_nonce", "kind", "observed_at", "focused", "number", "account", "application", "session_id", "request_id", "flow", "remote_session_hash"]);
    if (Object.keys(message).some(key => !keys.has(key))) return {ok: false, status: "invalid_message"};
    if (message.kind === "withdraw") { await withdraw(sender.tab.id); return {ok: true, status: "waiting_for_challenge"}; }
    if (message.kind !== "challenge") return {ok: false, status: "invalid_message"};
    const apiDocument = sender.documentId || message.document_nonce;
    let state = documents.get(sender.tab.id);
    if (state && (state.sourceDocument !== apiDocument || state.origin !== sourceOrigin)) { await withdraw(sender.tab.id); state = null; }
    if (!state) {
      if (documents.size >= 32) return {ok: false, status: "queue_full"};
      state = {sourceDocument: apiDocument, origin: sourceOrigin, tab: crypto.randomUUID(), document: crypto.randomUUID(), event: null, key: ""};
      documents.set(sender.tab.id, state);
    }
    let tab, windowInfo;
    try { tab = await browser.tabs.get(sender.tab.id); windowInfo = await browser.windows.get(tab.windowId); }
    catch { await withdraw(sender.tab.id); return {ok: false, status: "inactive_tab"}; }
    if (documents.get(sender.tab.id) !== state) return {ok: false, status: "inactive_tab"};
    if (!tab.active || !windowInfo.focused || MFAMac.origin(tab.url) !== sourceOrigin || message.focused !== true) { await withdraw(sender.tab.id); return {ok: false, status: "inactive_tab"}; }
    const event = {version: 1, kind: "challenge", event_id: crypto.randomUUID(), tab_id: state.tab, document_id: state.document, origin: sourceOrigin,
      observed_at: message.observed_at, number: message.number, account: message.account, application: message.application,
      session_id: message.session_id, request_id: message.request_id, focused: true};
    if (message.flow !== undefined) event.flow = message.flow;
    if (message.remote_session_hash !== undefined) event.remote_session_hash = message.remote_session_hash;
    if (!MFAMac.validEvent(event)) return {ok: false, status: "invalid_message"};
    const key = JSON.stringify([event.flow ?? "classic_mfa", event.number, event.account, event.application, event.session_id, event.request_id, event.remote_session_hash ?? ""]);
    if (state.key === key && state.event) return {ok: true, status: "delivered"};
    state.key = key; state.event = event;
    if (!await persist()) { await withdraw(sender.tab.id); return {ok: false, status: "local_io_failure"}; }
    if (documents.get(sender.tab.id) !== state) return {ok: false, status: "inactive_tab"};
    const result = await native({version: 1, command: "browser_event", browser: event});
    if (!result.ok && documents.get(sender.tab.id) === state) { state.event = null; state.key = ""; await persist(); }
    return result;
  }
  browser.runtime.onMessage.addListener((message, sender) => {
    if (message?.type === "observation") return observation(message, sender);
    // The popup gets only fixed statuses; content pages cannot call this path.
    if (!sender.tab && sender.url?.startsWith(browser.runtime.getURL("")) && message?.type === "status") return native({version: 1, command: "status"});
    if (!sender.tab && sender.url?.startsWith(browser.runtime.getURL("")) && message?.type === "rescan") {
      return browser.tabs.query({active: true, currentWindow: true}).then(async tabs => {
        const tab = tabs[0]; if (!tab || !MFAMac.origin(tab.url)) return {ok: false, status: "unsupported_page"};
        try { await browser.tabs.sendMessage(tab.id, {type: "rescan"}); return {ok: true, status: lastStatus}; }
        catch { return {ok: false, status: "unsupported_page"}; }
      });
    }
    return Promise.resolve({ok: false, status: "invalid_message"});
  });
  browser.tabs.onRemoved.addListener(tabID => { void restored.then(() => withdraw(tabID)); });
  browser.tabs.onUpdated.addListener((tabID, change) => { if (change.status === "loading" || Object.hasOwn(change, "url")) void restored.then(() => withdraw(tabID)); });
  browser.tabs.onActivated.addListener(async active => {
    await restored;
    for (const tabID of [...documents.keys()]) if (tabID !== active.tabId) await withdraw(tabID);
    browser.tabs.sendMessage(active.tabId, {type: "rescan"}).catch(() => {});
  });
  browser.windows.onFocusChanged.addListener(() => {
    // Window blur alone is expected during real LocalAuthentication. Original
    // capture time is retained; tab/navigation invalidations still withdraw.
    browser.tabs.query({active: true, lastFocusedWindow: true}).then(tabs => { if (tabs[0]) browser.tabs.sendMessage(tabs[0].id, {type: "rescan"}).catch(() => {}); }).catch(() => {});
  });
})();
