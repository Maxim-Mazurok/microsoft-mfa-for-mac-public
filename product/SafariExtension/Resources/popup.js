"use strict";
const copy = {
  ready: "The app is ready. Open your Microsoft sign-in page.",
  delivered: "This page was passed to the app for matching.",
  app_unavailable: "Open Microsoft MFA for Mac, then check this page again.",
  shared_container_unavailable: "The app connection needs setup. See the local setup guide.",
  queue_full: "The app is busy. Open it to check its status.",
  invalid_message: "This page is not supported for automatic handling.",
  local_io_failure: "The local app connection failed. Open the app to check its status.",
  unsupported_page: "Open a supported Microsoft sign-in page in this tab.",
  inactive_tab: "Keep the Microsoft sign-in tab visible and active.",
  waiting_for_challenge: "Waiting for a supported number-match page."
};
async function check(type) {
  const button = document.getElementById("check"); button.disabled = true;
  try { const result = await browser.runtime.sendMessage({type}); document.getElementById("status").textContent = copy[result?.status] || copy.app_unavailable; }
  catch { document.getElementById("status").textContent = copy.app_unavailable; }
  finally { button.disabled = false; }
}
document.getElementById("check").addEventListener("click", () => check("rescan"));
void check("status");
