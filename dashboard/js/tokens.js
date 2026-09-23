import { api } from "./api.js";

export let latestGeneratedToken = "";

export async function loadTokensList() {
  const tbody = document.getElementById("tokensTableBody");
  if (!tbody) return;

  try {
    const tokens = await api.getTokens();
    const countEl = document.getElementById("metricTokens");
    if (countEl) countEl.innerText = tokens.length;

    if (tokens.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 2rem;">No tokens configured. Click 'Create Token' to generate one.</td></tr>`;
      return;
    }

    tbody.innerHTML = tokens.map(t => {
      const createdStr = t.created_at ? new Date(t.created_at).toLocaleDateString() : "-";
      const expiresStr = t.expires_at ? new Date(t.expires_at).toLocaleDateString() : "Never";
      const lastUsedStr = t.last_used_at ? new Date(t.last_used_at).toLocaleTimeString() : "Never";

      return `
        <tr>
          <td><strong>${escapeHtml(t.name)}</strong></td>
          <td><span class="badge badge-blue">${escapeHtml(t.policy)}</span></td>
          <td>${t.os_user ? `<code style="color:var(--color-purple);">${escapeHtml(t.os_user)}</code>` : '<span style="color:var(--text-muted);">Default</span>'}</td>
          <td>${t.tier ? `<span class="badge badge-slate">${escapeHtml(t.tier)}</span>` : '<span style="color:var(--text-muted);">-</span>'}</td>
          <td>${createdStr}</td>
          <td>${expiresStr}</td>
          <td>${lastUsedStr}</td>
          <td style="text-align: right;">
            <button class="btn btn-sm btn-danger" onclick="window.revokeToken('${escapeHtml(t.name)}')">Revoke</button>
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--color-red); padding: 1.5rem;">Failed to load tokens: ${escapeHtml(err.message)}</td></tr>`;
  }
}

export async function handleCreateTokenSubmit(e) {
  e.preventDefault();
  const name = document.getElementById("newTokenName").value.trim();
  const policy = document.getElementById("newTokenPolicy").value;
  const days = parseInt(document.getElementById("newTokenExpiry").value, 10);
  const osUser = document.getElementById("newTokenOsUser").value.trim() || null;
  const tier = document.getElementById("newTokenTier").value || null;

  try {
    const payload = {
      name,
      policy,
      expires_days: days > 0 ? days : null,
      os_user: osUser,
      tier: tier === "none" ? null : tier,
    };

    const res = await api.createToken(payload);
    if (res && res.token) {
      latestGeneratedToken = res.token;
      document.getElementById("generatedTokenDisplay").innerText = res.token;
      document.getElementById("tokenResultModal").classList.add("open");
      document.getElementById("createTokenForm").reset();
      window.closeModal("createTokenModal");
      window.showToast(`Token '${name}' created successfully.`);
      await loadTokensList();
    }
  } catch (err) {
    window.showToast(`Token creation failed: ${err.message}`, true);
  }
}

export async function revokeToken(name) {
  if (!confirm(`Are you sure you want to revoke token '${name}'? Connected agents using this token will be instantly disconnected.`)) {
    return;
  }

  try {
    await api.revokeToken(name);
    window.showToast(`Token '${name}' revoked.`);
    await loadTokensList();
  } catch (err) {
    window.showToast(`Revocation failed: ${err.message}`, true);
  }
}

export function copyGeneratedToken() {
  if (!latestGeneratedToken) return;
  navigator.clipboard.writeText(latestGeneratedToken).then(() => {
    window.showToast("Token copied to clipboard!");
  });
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
