import { api, state } from "./api.js";

export const metrics = {
  totalAudits: 0,
  allowedCount: 0,
  deniedCount: 0,
  blockedCount: 0,
  errorCount: 0,
  activeExecutions: [],
  logs: [],
  autoScroll: true,
  filter: "all",
  searchQuery: "",
};

export function formatUptime(seconds) {
  if (seconds === undefined || seconds === null) return "--:--:--";
  const h = Math.floor(seconds / 3600).toString().padStart(2, "0");
  const m = Math.floor((seconds % 3600) / 60).toString().padStart(2, "0");
  const s = Math.floor(seconds % 60).toString().padStart(2, "0");
  return `${h}:${m}:${s}`;
}

export function handleHeartbeat(data) {
  if (data.uptime_seconds !== undefined) {
    const el = document.getElementById("metricUptime");
    if (el) el.innerText = formatUptime(data.uptime_seconds);
  }
  if (data.active_executions !== undefined) {
    const el = document.getElementById("metricActiveProcs");
    if (el) el.innerText = data.active_executions.length;
    metrics.activeExecutions = data.active_executions;
    renderExecutionsTable(data.active_executions);
  }
  if (data.lockdown !== undefined) {
    updateLockdownUI(data.lockdown);
  }
}

export function handleAuditEntry(entry) {
  metrics.totalAudits++;
  const res = (entry.result || "").toLowerCase();

  if (res === "allowed") {
    metrics.allowedCount++;
  } else if (res.includes("blocked")) {
    metrics.blockedCount++;
  } else if (res === "denied") {
    metrics.deniedCount++;
  } else if (res === "error") {
    metrics.errorCount++;
  }

  updateMetricsUI();
  metrics.logs.push(entry);
  if (metrics.logs.length > 500) {
    metrics.logs.shift();
  }

  appendLogToDom(entry);
}

export function updateMetricsUI() {
  const allowedEl = document.getElementById("metricAllowed");
  const deniedEl = document.getElementById("metricDenied");
  const blockedEl = document.getElementById("metricBlocked");
  const totalEl = document.getElementById("metricTotalAudits");

  if (allowedEl) allowedEl.innerText = metrics.allowedCount;
  if (deniedEl) deniedEl.innerText = metrics.deniedCount;
  if (blockedEl) blockedEl.innerText = metrics.blockedCount;
  if (totalEl) totalEl.innerText = metrics.totalAudits;
}

export function appendLogToDom(entry) {
  const container = document.getElementById("terminalStream");
  if (!container) return;

  const resType = (entry.result || "").toLowerCase();
  if (metrics.filter === "allowed" && resType !== "allowed") return;
  if (metrics.filter === "denied" && resType !== "denied") return;
  if (metrics.filter === "blocked" && !resType.includes("blocked")) return;

  if (metrics.searchQuery) {
    const q = metrics.searchQuery.toLowerCase();
    const str = `${entry.command || ""} ${entry.token_name || ""} ${entry.reason || ""}`.toLowerCase();
    if (!str.includes(q)) return;
  }

  const row = document.createElement("div");
  row.className = "log-row";

  let badgeClass = "badge-slate";
  if (resType === "allowed") badgeClass = "badge-green";
  else if (resType.includes("blocked") || resType === "denied") badgeClass = "badge-red";
  else if (resType === "error") badgeClass = "badge-amber";

  const timeStr = new Date(entry.timestamp || Date.now()).toLocaleTimeString();

  row.innerHTML = `
    <span class="log-time">${timeStr}</span>
    <span class="badge ${badgeClass}">${(entry.result || "").toUpperCase()}</span>
    <span class="log-cmd">
      <strong style="color: var(--color-blue);">${escapeHtml(entry.token_name || "unknown")}</strong>:
      <span>${escapeHtml(entry.command || "")}</span>
      <span style="color: var(--text-muted); font-size: 10px;">
        (${entry.duration_ms || 0}ms${entry.exit_code !== undefined && entry.exit_code !== null ? `, exit ${entry.exit_code}` : ""})
        ${entry.reason ? ` - ${escapeHtml(entry.reason)}` : ""}
      </span>
    </span>
  `;

  container.appendChild(row);
  if (metrics.autoScroll) {
    container.scrollTop = container.scrollHeight;
  }
}

export function renderExecutionsTable(list) {
  const tbody = document.getElementById("executionsTableBody");
  if (!tbody) return;

  if (!list || list.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">No active processes running on host.</td></tr>`;
    return;
  }

  tbody.innerHTML = list.map(item => `
    <tr>
      <td><code>${escapeHtml(item.id || "-")}</code></td>
      <td><span class="badge badge-purple">${item.pid}</span></td>
      <td><strong>${escapeHtml(item.token_name || "default")}</strong></td>
      <td>${escapeHtml(item.client_ip || "127.0.0.1")}</td>
      <td><code style="color: var(--color-green);">${escapeHtml(item.command || "")}</code></td>
      <td>${new Date(item.started_at).toLocaleTimeString()}</td>
      <td style="text-align: right;">
        <button class="btn btn-sm btn-danger" onclick="window.killExecution('${escapeHtml(item.id)}')">Kill</button>
      </td>
    </tr>
  `).join("");
}

export function updateLockdownUI(isLockdown) {
  const badge = document.getElementById("systemStateBadge");
  const btn = document.getElementById("lockdownBtn");
  const btnText = document.getElementById("lockdownBtnText");

  if (isLockdown) {
    if (badge) {
      badge.className = "badge badge-red";
      badge.innerText = "LOCKED DOWN";
    }
    if (btn) btn.className = "btn btn-sm btn-success";
    if (btnText) btnText.innerText = "Release Lockdown";
  } else {
    if (badge) {
      badge.className = "badge badge-green";
      badge.innerText = "OPERATIONAL";
    }
    if (btn) btn.className = "btn btn-sm btn-warning";
    if (btnText) btnText.innerText = "Emergency Lockdown";
  }
}

export async function toggleEmergencyLockdown() {
  const nextState = !state.isLockdown;
  try {
    await api.toggleLockdown(nextState);
    state.isLockdown = nextState;
    updateLockdownUI(nextState);
    window.showToast(nextState ? "System Emergency Lockdown activated!" : "Emergency Lockdown released.");
  } catch (err) {
    window.showToast(`Lockdown toggle failed: ${err.message}`, true);
  }
}

export async function restartHostDaemon() {
  if (!confirm("Are you sure you want to restart the host daemon? All connected sessions will briefly disconnect.")) {
    return;
  }
  try {
    await api.restartDaemon();
    window.showToast("Daemon restart signal sent. Reconnecting in 2s...");
    setTimeout(() => {
      window.location.reload();
    }, 2500);
  } catch (err) {
    window.showToast(`Restart failed: ${err.message}`, true);
  }
}

export async function killExecutionProcess(id) {
  if (!confirm(`Terminate active execution process ${id}?`)) return;
  try {
    await api.killExecution(id);
    window.showToast(`Process ${id} terminated.`);
  } catch (err) {
    window.showToast(`Failed to kill process: ${err.message}`, true);
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
