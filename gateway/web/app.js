"use strict";
// Tokens are deliberately never displayed, logged, or persisted by this demo.
const statusNode = document.getElementById("status");
const detailNode = document.getElementById("detail");
let accessToken = null;
let expirationTimer;
function clearCredential() { accessToken = null; clearTimeout(expirationTimer); }
document.getElementById("demo").onclick = () => {
  statusNode.textContent = "Demo session verified";
  detailNode.textContent = "Synthetic preview only · 300-second token · no network request made.";
};
document.getElementById("exchange").onclick = async () => {
  clearCredential();
  try {
    const response = await fetch("/session/ha", {method: "POST", credentials: "same-origin", cache: "no-store"});
    if (!response.ok) throw new Error(String(response.status));
    const session = await response.json();
    if (session.contract_version !== 1 || typeof session.access_token !== "string" ||
        !Number.isInteger(session.expires_in) || session.expires_in < 1 || session.expires_in > 300) throw new Error("contract");
    accessToken = session.access_token;
    expirationTimer = setTimeout(() => { clearCredential(); statusNode.textContent = "Session expired"; }, session.expires_in * 1000);
    statusNode.textContent = "Home Assistant session created";
    detailNode.textContent = "Credential held only in memory. This demo makes no device calls.";
    document.getElementById("lifetime").textContent = session.expires_in + " seconds";
  } catch {
    statusNode.textContent = "Session unavailable";
    detailNode.textContent = "Check Access configuration and the HA integration. No credential was retained.";
  }
};
document.getElementById("revoke").onclick = async () => {
  clearCredential();
  try {
    const response = await fetch("/session/ha?revoke=1", {method: "POST", credentials: "same-origin", cache: "no-store"});
    if (response.status !== 204) throw new Error("revoke");
    statusNode.textContent = "Session revoked";
    detailNode.textContent = "Sign out of your identity provider and sign in again to obtain a fresh assertion.";
  } catch {
    statusNode.textContent = "Local credential cleared";
    detailNode.textContent = "Server revocation could not be confirmed. Use your HA profile to revoke managed refresh tokens.";
  }
};
window.addEventListener("pagehide", clearCredential);
