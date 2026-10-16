"use strict";
// Tokens are deliberately never displayed, logged, or persisted by this demo.
const statusNode = document.getElementById("status");
const detailNode = document.getElementById("detail");
let accessToken = null;
let expirationTimer;
let operation = 0;
function clearCredential() { accessToken = null; clearTimeout(expirationTimer); }
document.getElementById("demo").onclick = () => {
  operation += 1;
  clearCredential();
  statusNode.textContent = "Demo session verified";
  detailNode.textContent = "Synthetic preview only · 300-second token · no network request made.";
};
document.getElementById("exchange").onclick = async () => {
  const current = ++operation;
  clearCredential();
  try {
    const response = await fetch("/session/ha", {method: "POST", credentials: "same-origin", cache: "no-store"});
    if (current !== operation) return;
    if (!response.ok) throw new Error(String(response.status));
    const session = await response.json();
    if (current !== operation) return;
    if (session.contract_version !== 1 || typeof session.access_token !== "string" || !session.access_token.trim() ||
        !Number.isInteger(session.expires_in) || session.expires_in < 1 || session.expires_in > 300) throw new Error("contract");
    accessToken = session.access_token;
    expirationTimer = setTimeout(() => {
      if (current !== operation) return;
      clearCredential();
      statusNode.textContent = "Session expired";
      detailNode.textContent = "No credential is retained. Create a new session to continue.";
    }, session.expires_in * 1000);
    statusNode.textContent = "Home Assistant session created";
    detailNode.textContent = "Credential held only in memory. This demo makes no device calls.";
    document.getElementById("lifetime").textContent = session.expires_in + " seconds";
  } catch {
    if (current !== operation) return;
    statusNode.textContent = "Session unavailable";
    detailNode.textContent = "Check Access configuration and the HA integration. No credential was retained.";
  }
};
document.getElementById("revoke").onclick = async () => {
  const current = ++operation;
  clearCredential();
  try {
    const response = await fetch("/session/ha?revoke=1", {method: "POST", credentials: "same-origin", cache: "no-store"});
    // Revocation still reaches the server if a newer UI operation supersedes it.
    if (current !== operation) return;
    if (response.status !== 204) throw new Error("revoke");
    statusNode.textContent = "Session revoked";
    detailNode.textContent = "Sign out of your identity provider and sign in again to obtain a fresh assertion.";
  } catch {
    if (current !== operation) return;
    statusNode.textContent = "Local credential cleared";
    detailNode.textContent = "Server revocation could not be confirmed. Use your HA profile to revoke managed refresh tokens.";
  }
};
window.addEventListener("pagehide", () => { operation += 1; clearCredential(); });
