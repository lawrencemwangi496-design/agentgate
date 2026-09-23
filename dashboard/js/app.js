import { api, state, setConnection, startSseStream, stopSseStream } from "./api.js";
import { handleHeartbeat, handleAuditEntry, toggleEmergencyLockdown, restartHostDaemon, killExecutionProcess, metrics } from "./telemetry.js";
import { loadPoliciesAndFiles, initDropZone, selectPolicyForEdit, saveEditorFile, exportActivePolicyToPc, deleteActivePolicy, lintEditorYaml, confirmStagedUpload, cancelStagedUpload } from "./policies.js";
import { loadTokensList, handleCreateTokenSubmit, revokeToken, copyGeneratedToken } from "./tokens.js";
import { executeConsoleCommand, initConsoleKeybindings } from "./console.js";
import { renderChatMessages, sendChatMessage, saveAiSettings, deployAiYamlToServer, loadAiYamlIntoEditor, copyAiYaml, aiConfig } from "./ai-assistant.js";

// Global Window Bindings for HTML Attributes
window.switchTab = switchTab;
window.showToast = showToast;
window.openModal = openModal;
window.closeModal = closeModal;
window.toggleLockdown = toggleEmergencyLockdown;
window.restartDaemon = restartHostDaemon;
window.killExecution = killExecutionProcess;
window.selectPolicyForEdit = selectPolicyForEdit;
window.saveEditorFile = saveEditorFile;
window.exportPolicyToPc = exportActivePolicyToPc;
window.deleteActivePolicy = deleteActivePolicy;
window.lintEditorYaml = lintEditorYaml;
window.confirmStagedUpload = confirmStagedUpload;
window.cancelStagedUpload = cancelStagedUpload;
window.revokeToken = revokeToken;
window.copyGeneratedToken = copyGeneratedToken;
window.runConsoleCmd = executeConsoleCommand;
window.copyAiYaml = copyAiYaml;
window.loadAiYamlIntoEditor = loadAiYamlIntoEditor;
window.deployAiYamlToServer = deployAiYamlToServer;
window.openAiSettingsModal = () => openModal("aiSettingsModal");

// Auth Gate Bindings
window.switchAuthTab = switchAuthTab;
window.submitTotpAuth = submitTotpAuth;
window.submitTotpSetupConfirm = submitTotpSetupConfirm;
window.submitTokenAuth = submitTokenAuth;
window.copySetupSecretKey = copySetupSecretKey;
window.logoutConsole = logoutConsole;
window.submitSynthesizer = submitSynthesizer;

let currentSetupSecret = "";

document.addEventListener("DOMContentLoaded", () => {
  initApp();
});

async function initApp() {
  initDropZone();
  initConsoleKeybindings();
  initFormListeners();
  renderChatMessages();

  const hostInput = document.getElementById("authGateHost");
  if (hostInput) hostInput.value = state.host;

  // If token is saved, try to validate and unlock console
  if (state.token) {
    tryUnlockWithExistingToken();
  } else {
    showAuthGate();
  }
}

function showAuthGate() {
  const gate = document.getElementById("authGate");
  const app = document.getElementById("appWorkspace");
  if (gate) gate.style.display = "flex";
  if (app) app.style.display = "none";
}

function unlockConsole(statusData) {
  const gate = document.getElementById("authGate");
  const app = document.getElementById("appWorkspace");
  if (gate) gate.style.display = "none";
  if (app) app.style.display = "flex";

  state.connected = true;
  state.version = statusData.version || "0.2.0";
  state.isLockdown = statusData.lockdown;

  const versionEl = document.getElementById("dashboardVersionPill");
  if (versionEl) versionEl.innerText = `v${state.version}`;

  const hostLabel = document.getElementById("connLabel");
  if (hostLabel) hostLabel.innerText = state.host.replace(/^https?:\/\//, "");

  updateConnectionBadge(true);
  showToast(`Authenticated to AgentGate Daemon v${state.version}`);

  // Start Real-Time SSE Stream
  startSseStream(
    (entry) => handleAuditEntry(entry),
    (heartbeat) => handleHeartbeat(heartbeat),
    () => updateConnectionBadge(false)
  );

  // Initial Data Fetch
  loadPoliciesAndFiles();
  loadTokensList();
  populateTokenPolicyOptions();
}

async function tryUnlockWithExistingToken() {
  try {
    const statusData = await api.getStatus();
    unlockConsole(statusData);
  } catch (err) {
    console.warn("Existing token validation failed:", err);
    state.token = "";
    localStorage.removeItem("ag_token");
    showAuthGate();
    showAuthError("Session expired or invalid. Please authenticate.");
  }
}

export function switchAuthTab(tab) {
  ["totp", "setup", "token"].forEach(t => {
    const btn = document.getElementById(`authTab${t.charAt(0).toUpperCase() + t.slice(1)}Btn`);
    const panel = document.getElementById(`authPanel${t.charAt(0).toUpperCase() + t.slice(1)}`);
    if (btn) btn.classList.toggle("active", t === tab);
    if (panel) panel.style.display = (t === tab) ? "block" : "none";
  });

  clearAuthError();

  if (tab === "setup") {
    loadTotpSetupWizard();
  } else if (tab === "totp") {
    setTimeout(() => {
      const input = document.getElementById("authTotpInput");
      if (input) input.focus();
    }, 50);
  }
}

async function loadTotpSetupWizard() {
  const hostInput = document.getElementById("authGateHost");
  if (hostInput && hostInput.value.trim()) {
    state.host = hostInput.value.trim().replace(/\/$/, "");
  }

  const loadingEl = document.getElementById("authSetupLoading");
  const alreadyEl = document.getElementById("authSetupAlreadyConfigured");
  const availEl = document.getElementById("authSetupAvailable");

  if (loadingEl) loadingEl.style.display = "block";
  if (alreadyEl) alreadyEl.style.display = "none";
  if (availEl) availEl.style.display = "none";

  try {
    const data = await api.getTotpSetup();
    currentSetupSecret = data.secret;
    const textEl = document.getElementById("setupSecretText");
    const uriBtn = document.getElementById("setupOtpauthUriBtn");
    if (textEl) textEl.innerText = data.secret;
    if (uriBtn) uriBtn.href = data.uri || "#";

    if (loadingEl) loadingEl.style.display = "none";
    if (availEl) availEl.style.display = "block";
  } catch (err) {
    if (loadingEl) loadingEl.style.display = "none";
    if (err.data && err.data.error === "already_configured") {
      if (alreadyEl) alreadyEl.style.display = "block";
    } else {
      showAuthError(`Setup query failed: ${err.message}`);
    }
  }
}

export async function submitTotpAuth(e) {
  e.preventDefault();
  clearAuthError();

  const hostInput = document.getElementById("authGateHost");
  const codeInput = document.getElementById("authTotpInput");
  const submitBtn = document.getElementById("authTotpSubmitBtn");

  const host = hostInput ? hostInput.value.trim() : state.host;
  const code = codeInput ? codeInput.value.trim() : "";

  if (!code || code.length !== 6) {
    showAuthError("Please enter a valid 6-digit TOTP verification code.");
    return;
  }

  setConnection(host, "");
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerText = "Verifying Code...";
  }

  try {
    const authRes = await api.verifyTotp(code);
    if (!authRes.token) {
      throw new Error("No token returned by daemon");
    }

    setConnection(host, authRes.token);
    const statusData = await api.getStatus();
    unlockConsole(statusData);
  } catch (err) {
    if (err.data && err.data.error === "totp_not_configured") {
      showAuthError("TOTP is not configured on this host. Run 'sudo agentgated totp setup' on the host, or click the 2FA Setup tab.");
    } else if (err.data && err.data.error === "invalid_code") {
      showAuthError("Invalid or expired 6-digit TOTP code. Check your authenticator app time skew.");
    } else {
      showAuthError(`Authentication failed: ${err.message}`);
    }
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerText = "Verify Code & Unlock Console";
    }
  }
}

export async function submitTotpSetupConfirm(e) {
  e.preventDefault();
  clearAuthError();

  const hostInput = document.getElementById("authGateHost");
  const codeInput = document.getElementById("setupConfirmCodeInput");

  const host = hostInput ? hostInput.value.trim() : state.host;
  const code = codeInput ? codeInput.value.trim() : "";

  if (!code || code.length !== 6) {
    showAuthError("Please enter the 6-digit code from your authenticator app.");
    return;
  }

  setConnection(host, "");

  try {
    const res = await api.confirmTotpSetup(currentSetupSecret, code);
    if (!res.token) throw new Error("No session token received.");

    setConnection(host, res.token);
    const statusData = await api.getStatus();
    unlockConsole(statusData);
  } catch (err) {
    showAuthError(`Setup confirmation failed: ${err.message}`);
  }
}

export async function submitTokenAuth(e) {
  e.preventDefault();
  clearAuthError();

  const hostInput = document.getElementById("authGateHost");
  const tokenInput = document.getElementById("authTokenInput");

  const host = hostInput ? hostInput.value.trim() : state.host;
  const token = tokenInput ? tokenInput.value.trim() : "";

  if (!token) {
    showAuthError("Please enter an admin bearer token.");
    return;
  }

  setConnection(host, token);

  try {
    const statusData = await api.getStatus();
    unlockConsole(statusData);
  } catch (err) {
    showAuthError(`Token authentication failed: ${err.message}`);
  }
}

function showAuthError(msg) {
  const el = document.getElementById("authGateError");
  if (el) {
    el.innerText = msg;
    el.style.display = "block";
  }
}

function clearAuthError() {
  const el = document.getElementById("authGateError");
  if (el) {
    el.innerText = "";
    el.style.display = "none";
  }
}

export function copySetupSecretKey() {
  if (currentSetupSecret) {
    navigator.clipboard.writeText(currentSetupSecret);
    showToast("Base32 secret key copied to clipboard.");
  }
}

export function logoutConsole() {
  stopSseStream();
  state.token = "";
  localStorage.removeItem("ag_token");
  showAuthGate();
  showToast("Console locked. Operator session cleared.");
}

function updateConnectionBadge(isOnline) {
  const dot = document.getElementById("connDot");
  const badge = document.getElementById("systemStateBadge");

  if (dot) {
    dot.className = "conn-dot " + (isOnline ? "online" : "offline");
  }
  if (badge) {
    badge.className = "badge " + (isOnline ? "badge-green" : "badge-red");
    badge.innerText = isOnline ? "OPERATIONAL" : "OFFLINE";
  }
}

export function switchTab(tabId) {
  document.querySelectorAll(".rail-btn").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === tabId);
  });

  document.querySelectorAll(".tab-pane").forEach(pane => {
    pane.classList.toggle("active", pane.id === `tab-${tabId}`);
  });

  const titleEl = document.getElementById("activeViewTitle");
  if (titleEl) {
    const titles = {
      overview: "SYSTEM OVERVIEW",
      processes: "ACTIVE HOST PROCESSES",
      policies: "POLICY WORKSPACE & FILE MANAGER",
      tokens: "ACCESS TOKENS & SECURITY TIERS",
      audit: "LIVE SSE AUDIT TELEMETRY",
      console: "DIRECT COMMAND DISPATCHER",
    };
    titleEl.innerText = titles[tabId] || tabId.toUpperCase();
  }

  if (tabId === "policies") {
    loadPoliciesAndFiles();
  } else if (tabId === "tokens") {
    loadTokensList();
    populateTokenPolicyOptions();
  } else if (tabId === "processes") {
    loadProcessList();
  }
}

function loadProcessList() {
  const body = document.getElementById("processesTableBody");
  if (!body) return;
  body.innerHTML = `<tr><td colspan="7" class="empty-cell">No active processes running on host.</td></tr>`;
}

function populateTokenPolicyOptions() {
  const select = document.getElementById("newTokenPolicy");
  if (!select) return;

  const policies = document.querySelectorAll("#policyCardsGrid .card-title span:last-child");
  if (policies.length === 0) return;

  const names = Array.from(policies).map(el => el.innerText.trim());
  select.innerHTML = names.map(n => `<option value="${n}">${n}</option>`).join("");
}

export function submitSynthesizer(e) {
  e.preventDefault();
  const input = document.getElementById("aiChatInput");
  if (input && input.value.trim()) {
    sendChatMessage(input.value.trim());
  }
}

function initFormListeners() {
  // Token creation form
  const tokenForm = document.getElementById("createTokenForm");
  if (tokenForm) {
    tokenForm.addEventListener("submit", handleCreateTokenSubmit);
  }

  // Model settings form
  const aiSettingsForm = document.getElementById("aiSettingsForm");
  if (aiSettingsForm) {
    aiSettingsForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const provider = document.getElementById("aiProviderSelect").value;
      const apiKey = document.getElementById("aiApiKeyInput").value;
      const model = document.getElementById("aiModelInput").value;
      const endpoint = document.getElementById("aiEndpointInput").value;
      saveAiSettings(provider, apiKey, model, endpoint);
      closeModal("aiSettingsModal");
    });
  }
}

export function openModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.add("open");
}

export function closeModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.remove("open");
}

export function showToast(message, isError = false) {
  const container = document.getElementById("toastContainer");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = "toast" + (isError ? " toast-error" : "");

  toast.innerHTML = `
    <span class="badge ${isError ? 'badge-red' : 'badge-green'}">${isError ? 'ERR' : 'OK'}</span>
    <span>${message}</span>
  `;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 150);
  }, 3500);
}
