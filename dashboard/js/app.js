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

document.addEventListener("DOMContentLoaded", () => {
  initApp();
});

async function initApp() {
  initDropZone();
  initConsoleKeybindings();
  initFormListeners();
  renderChatMessages();

  // Load connection inputs from state
  const hostInput = document.getElementById("connHostInput");
  const tokenInput = document.getElementById("connTokenInput");
  if (hostInput) hostInput.value = state.host;
  if (tokenInput) tokenInput.value = state.token;

  // Auto connect if token exists
  if (state.token) {
    connectToDaemon();
  } else {
    updateConnectionUI(false, "Disconnected");
    openModal("connectionModal");
  }
}

export async function connectToDaemon() {
  const hostInput = document.getElementById("connHostInput");
  const tokenInput = document.getElementById("connTokenInput");

  const host = hostInput ? hostInput.value.trim() : state.host;
  const token = tokenInput ? tokenInput.value.trim() : state.token;

  setConnection(host, token);
  updateConnectionUI(false, "Connecting...", "connecting");

  try {
    const statusData = await api.getStatus();
    state.connected = true;
    state.version = statusData.version || "0.1.9";
    state.isLockdown = statusData.lockdown;

    updateConnectionUI(true, `${state.host}`);
    closeModal("connectionModal");
    showToast(`Connected to AgentGate Daemon v${state.version}`);

    // Start Real-Time SSE Stream
    startSseStream(
      (entry) => handleAuditEntry(entry),
      (heartbeat) => handleHeartbeat(heartbeat),
      () => updateConnectionUI(false, "Reconnecting...", "connecting")
    );

    // Initial Data Fetch
    await Promise.all([
      loadPoliciesAndFiles(),
      loadTokensList(),
    ]);

    // Populate token policy select dropdown
    populateTokenPolicyOptions();
  } catch (err) {
    state.connected = false;
    stopSseStream();
    updateConnectionUI(false, "Offline / Auth Failed", "offline");
    showToast(`Connection failed: ${err.message}`, true);
  }
}

function updateConnectionUI(isOnline, label, statusClass = null) {
  const badge = document.getElementById("connPill");
  const dot = document.getElementById("connDot");
  const labelEl = document.getElementById("connLabel");

  if (dot) {
    dot.className = "conn-dot " + (statusClass || (isOnline ? "online" : "offline"));
  }
  if (labelEl) {
    labelEl.innerText = label;
  }
}

export function switchTab(tabId) {
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === tabId);
  });

  document.querySelectorAll(".tab-pane").forEach(pane => {
    pane.classList.toggle("active", pane.id === `tab-${tabId}`);
  });

  if (tabId === "policies") {
    loadPoliciesAndFiles();
  } else if (tabId === "tokens") {
    loadTokensList();
    populateTokenPolicyOptions();
  }
}

function populateTokenPolicyOptions() {
  const select = document.getElementById("newTokenPolicy");
  if (!select) return;

  const policies = document.querySelectorAll("#policyCardsGrid .card-title span:last-child");
  if (policies.length === 0) return;

  const names = Array.from(policies).map(el => el.innerText.trim());
  select.innerHTML = names.map(n => `<option value="${n}">${n}</option>`).join("");
}

function initFormListeners() {
  // Connection Form
  const connForm = document.getElementById("connectionForm");
  if (connForm) {
    connForm.addEventListener("submit", (e) => {
      e.preventDefault();
      connectToDaemon();
    });
  }

  // Token Form
  const tokenForm = document.getElementById("createTokenForm");
  if (tokenForm) {
    tokenForm.addEventListener("submit", handleCreateTokenSubmit);
  }

  // AI Chat Form
  const aiForm = document.getElementById("aiChatForm");
  if (aiForm) {
    aiForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const input = document.getElementById("aiChatInput");
      if (input && input.value.trim()) {
        sendChatMessage(input.value.trim());
      }
    });
  }

  // AI Settings Form
  const aiSettingsForm = document.getElementById("aiSettingsForm");
  if (aiSettingsForm) {
    aiSettingsForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const prov = document.getElementById("aiProviderSelect").value;
      const key = document.getElementById("aiApiKeyInput").value;
      const model = document.getElementById("aiModelInput").value;
      const endpoint = document.getElementById("aiEndpointInput").value;
      saveAiSettings(prov, key, model, endpoint);
      closeModal("aiSettingsModal");
    });
  }

  // Terminal Filter and Search
  const filterSelect = document.getElementById("logFilterSelect");
  if (filterSelect) {
    filterSelect.addEventListener("change", (e) => {
      metrics.filter = e.target.value;
      renderLogStream();
    });
  }

  const searchInput = document.getElementById("logSearchInput");
  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      metrics.searchQuery = e.target.value;
      renderLogStream();
    });
  }
}

function renderLogStream() {
  const container = document.getElementById("terminalStream");
  if (!container) return;
  container.innerHTML = "";
  metrics.logs.forEach(entry => window.appendLogToDom(entry));
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
  toast.className = "toast";
  if (isError) toast.style.borderColor = "var(--color-red)";

  toast.innerHTML = `
    <span class="badge ${isError ? 'badge-red' : 'badge-green'}">${isError ? 'ERR' : 'OK'}</span>
    <span>${message}</span>
  `;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 200);
  }, 3500);
}
