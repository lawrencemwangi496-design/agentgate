import { api } from "./api.js";

export const policyState = {
  policies: [],
  files: [],
  activeFilePath: null,
  stagedUpload: null, // { filename, content, parsed }
};

export async function loadPoliciesAndFiles() {
  const container = document.getElementById("policyCardsGrid");
  if (!container) return;

  try {
    const [policies, files] = await Promise.all([
      api.getPolicies().catch(() => []),
      api.getFiles().catch(() => []),
    ]);

    policyState.policies = policies;
    policyState.files = files;

    renderPolicyCards(policies, files);
    renderPolicyFilesList(files);

    const countEl = document.getElementById("metricPolicies");
    if (countEl) countEl.innerText = policies.length;
  } catch (err) {
    console.error("Failed to load policies:", err);
  }
}

export function renderPolicyCards(policies, files) {
  const container = document.getElementById("policyCardsGrid");
  if (!container) return;

  if (policies.length === 0) {
    container.innerHTML = `
      <div style="grid-column: 1 / -1; text-align: center; color: var(--text-muted); padding: 2rem;">
        No policies found on daemon. Drag and drop a YAML file above to create one.
      </div>
    `;
    return;
  }

  container.innerHTML = policies.map(p => {
    const allowCount = p.rules ? p.rules.length : 0;
    const denyCount = p.deny ? p.deny.length : 0;
    const actionCount = p.actions ? Object.keys(p.actions).length : 0;
    const filename = `policies/${p.name}.yaml`;

    return `
      <div class="card" style="margin-bottom: 0;">
        <div class="card-header">
          <div class="card-title">
            <svg class="icon icon-sm" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <span>${escapeHtml(p.name)}</span>
          </div>
          <div style="display: flex; gap: 4px;">
            <button class="btn btn-sm" onclick="window.selectPolicyForEdit('${escapeHtml(filename)}')">Inspect</button>
            <button class="btn btn-sm" onclick="window.exportPolicyToPc('${escapeHtml(filename)}')">Export</button>
          </div>
        </div>
        <div class="card-body">
          <p style="color: var(--text-secondary); font-size: 11px; margin-bottom: 8px;">
            ${escapeHtml(p.description || "No description provided.")}
          </p>
          <div style="display: flex; flex-wrap: wrap; gap: 6px;">
            <span class="badge ${allowCount > 0 ? "badge-green" : "badge-slate"}">${allowCount} ALLOW</span>
            ${denyCount > 0 ? `<span class="badge badge-red">${denyCount} DENY</span>` : ""}
            ${actionCount > 0 ? `<span class="badge badge-blue">${actionCount} ACTIONS</span>` : ""}
            <span class="badge ${p.guardrails !== false ? "badge-blue" : "badge-amber"}">
              ${p.guardrails !== false ? "GUARDRAILS ON" : "GUARDRAILS OFF"}
            </span>
          </div>
        </div>
      </div>
    `;
  }).join("");
}

export function renderPolicyFilesList(files) {
  const container = document.getElementById("filesTreeList");
  if (!container) return;

  if (files.length === 0) {
    container.innerHTML = `<div style="color: var(--text-muted); padding: 10px; font-size: 11px;">No policy files found.</div>`;
    return;
  }

  container.innerHTML = files.map(f => {
    const isSelected = policyState.activeFilePath === f.path;
    const sizeKb = (f.size_bytes / 1024).toFixed(1);
    const isProtected = f.path === "config.yaml" || f.path === "tokens.yaml";

    return `
      <div onclick="window.selectPolicyForEdit('${escapeHtml(f.path)}')"
           style="display: flex; align-items: center; justify-content: space-between; padding: 6px 10px; border-radius: var(--radius-sm); cursor: pointer; margin-bottom: 2px; background: ${isSelected ? "var(--bg-overlay)" : "transparent"};">
        <div style="display: flex; align-items: center; gap: 8px; overflow: hidden;">
          <svg class="icon icon-sm" viewBox="0 0 24 24" style="color: ${f.path.startsWith('policies/') ? 'var(--color-blue)' : 'var(--text-muted)'};"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
          <span style="font-family: var(--font-mono); font-size: 11px; white-space: nowrap; text-overflow: ellipsis; overflow: hidden; color: var(--text-primary);">
            ${escapeHtml(f.path)}
          </span>
        </div>
        <span style="color: var(--text-muted); font-size: 10px; font-family: var(--font-mono);">${sizeKb} KB</span>
      </div>
    `;
  }).join("");
}

// --- Drag & Drop PC File Upload Handler ---

export function initDropZone() {
  const dropZone = document.getElementById("policyDropZone");
  const fileInput = document.getElementById("policyFileInput");

  if (!dropZone || !fileInput) return;

  ["dragenter", "dragover"].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add("drag-over");
    });
  });

  ["dragleave", "drop"].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove("drag-over");
    });
  });

  dropZone.addEventListener("drop", (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handlePickedFile(files[0]);
    }
  });

  fileInput.addEventListener("change", (e) => {
    if (e.target.files.length > 0) {
      handlePickedFile(e.target.files[0]);
    }
    e.target.value = "";
  });
}

export function handlePickedFile(file) {
  if (!file.name.endsWith(".yaml") && !file.name.endsWith(".yml")) {
    window.showToast("Please upload a valid .yaml or .yml policy file.", true);
    return;
  }

  const reader = new FileReader();
  reader.onload = (e) => {
    const content = e.target.result;
    stageUploadedPolicy(file.name, content);
  };
  reader.readAsText(file);
}

export function stageUploadedPolicy(filename, content) {
  // Simple heuristic parsing of YAML structure
  const nameMatch = content.match(/^name\s*:\s*["']?([a-zA-Z0-9_-]+)["']?/m);
  const descMatch = content.match(/^description\s*:\s*["']?([^"'\n\r]+)["']?/m);
  const allowMatches = content.match(/^\s*-\s*command\s*:/gm);
  const denyMatches = content.match(/^\s*-\s*command\s*:\s*(rm|mkfs|dd|chmod|shutdown)/gm);

  const policyName = nameMatch ? nameMatch[1] : filename.replace(/\.ya?ml$/, "");
  const ruleCount = allowMatches ? allowMatches.length : 0;
  const targetPath = `policies/${policyName}.yaml`;

  policyState.stagedUpload = {
    targetPath,
    filename,
    content,
    name: policyName,
    description: descMatch ? descMatch[1] : "",
    ruleCount,
  };

  const stagingEl = document.getElementById("stagedPolicyContainer");
  if (!stagingEl) return;

  stagingEl.style.display = "block";
  stagingEl.innerHTML = `
    <div class="staged-policy-card">
      <div style="display: flex; align-items: center; gap: 12px;">
        <svg class="icon icon-lg" viewBox="0 0 24 24" style="color: var(--color-blue);"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
        <div>
          <div style="font-weight: 600; color: var(--text-white); font-size: 13px;">
            ${escapeHtml(filename)} &rarr; <span style="color: var(--color-blue); font-family: var(--font-mono);">${escapeHtml(targetPath)}</span>
          </div>
          <div style="color: var(--text-secondary); font-size: 11px; margin-top: 2px;">
            Policy: <strong>${escapeHtml(policyName)}</strong> | Rules: ${ruleCount} | Size: ${(content.length / 1024).toFixed(1)} KB
          </div>
        </div>
      </div>
      <div style="display: flex; gap: 6px;">
        <button class="btn btn-sm btn-primary" onclick="window.confirmStagedUpload()">Upload to Host</button>
        <button class="btn btn-sm" onclick="window.cancelStagedUpload()">Cancel</button>
      </div>
    </div>
  `;

  window.showToast(`Loaded '${filename}' from your PC. Click 'Upload to Host Daemon' to deploy.`);
}

export async function confirmStagedUpload() {
  if (!policyState.stagedUpload) return;
  const { targetPath, content, name } = policyState.stagedUpload;

  try {
    await api.writeFile(targetPath, content);
    window.showToast(`Policy '${name}' deployed to host daemon successfully!`);
    cancelStagedUpload();
    await loadPoliciesAndFiles();
  } catch (err) {
    window.showToast(`Upload failed: ${err.message}`, true);
  }
}

export function cancelStagedUpload() {
  policyState.stagedUpload = null;
  const stagingEl = document.getElementById("stagedPolicyContainer");
  if (stagingEl) {
    stagingEl.style.display = "none";
    stagingEl.innerHTML = "";
  }
}

// --- Policy Code & Visual Editor ---

export async function selectPolicyForEdit(path) {
  policyState.activeFilePath = path;
  const titleEl = document.getElementById("editorFilePath");
  const editor = document.getElementById("policyEditorTextarea");
  const saveBtn = document.getElementById("editorSaveBtn");
  const exportBtn = document.getElementById("editorExportBtn");
  const deleteBtn = document.getElementById("editorDeleteBtn");

  if (titleEl) titleEl.innerText = path;
  if (editor) editor.value = "Loading file content from host...";

  try {
    const data = await api.readFile(path);
    if (editor) editor.value = data.content || "";
    if (saveBtn) saveBtn.style.display = "inline-flex";
    if (exportBtn) exportBtn.style.display = "inline-flex";

    const isProtected = path === "config.yaml" || path === "tokens.yaml";
    if (deleteBtn) deleteBtn.style.display = isProtected ? "none" : "inline-flex";

    lintEditorYaml();
    renderPolicyFilesList(policyState.files);

    // Switch to editor tab if not visible
    const editorTab = document.getElementById("policyEditorCard");
    if (editorTab) editorTab.scrollIntoView({ behavior: "smooth" });
  } catch (err) {
    if (editor) editor.value = `Error loading ${path}: ${err.message}`;
    window.showToast(`Failed to read file: ${err.message}`, true);
  }
}

export async function saveEditorFile() {
  if (!policyState.activeFilePath) return;
  const editor = document.getElementById("policyEditorTextarea");
  const content = editor ? editor.value : "";

  try {
    await api.writeFile(policyState.activeFilePath, content);
    window.showToast(`Saved '${policyState.activeFilePath}' to host daemon.`);
    await loadPoliciesAndFiles();
  } catch (err) {
    window.showToast(`Save failed: ${err.message}`, true);
  }
}

export function exportActivePolicyToPc(path = null) {
  const filePath = path || policyState.activeFilePath;
  const editor = document.getElementById("policyEditorTextarea");
  const content = editor ? editor.value : "";

  if (!content) {
    window.showToast("Editor is empty. Nothing to export.", true);
    return;
  }

  const filename = filePath ? filePath.split("/").pop() : "policy.yaml";
  const blob = new Blob([content], { type: "text/yaml;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  window.showToast(`Downloaded '${filename}' to your computer.`);
}

export async function deleteActivePolicy() {
  if (!policyState.activeFilePath) return;
  if (!confirm(`Are you sure you want to delete '${policyState.activeFilePath}' from host daemon?`)) return;

  try {
    await api.deleteFile(policyState.activeFilePath);
    window.showToast(`Deleted '${policyState.activeFilePath}'.`);
    policyState.activeFilePath = null;
    const editor = document.getElementById("policyEditorTextarea");
    if (editor) editor.value = "";
    await loadPoliciesAndFiles();
  } catch (err) {
    window.showToast(`Delete failed: ${err.message}`, true);
  }
}

export function lintEditorYaml() {
  const badge = document.getElementById("editorLinterBadge");
  const editor = document.getElementById("policyEditorTextarea");
  if (!badge || !editor) return;

  const content = editor.value;
  if (!content.trim()) {
    badge.style.display = "none";
    return;
  }

  badge.style.display = "inline-flex";

  if (/^\t+/m.test(content)) {
    badge.className = "badge badge-red";
    badge.innerText = "SYNTAX ERROR: Tabs used for indentation";
    return;
  }

  const hasName = /^name\s*:\s*(\S+)/m.test(content);
  if (!hasName) {
    badge.className = "badge badge-amber";
    badge.innerText = "SCHEMA WARNING: Missing 'name:' field";
    return;
  }

  const allowMatches = content.match(/^\s*-\s*command\s*:/gm);
  const ruleCount = allowMatches ? allowMatches.length : 0;
  const guardrailsDisabled = /guardrails\s*:\s*false/i.test(content);

  const dangerousPatterns = [
    /\brm\s+-rf\b/,
    /\bmkfs\b/,
    /\bdd\s+if=/,
    /\bchmod\s+777\b/,
    /\|\s*(bash|sh)\b/,
  ];

  let foundDangerous = false;
  for (const pat of dangerousPatterns) {
    if (pat.test(content)) {
      foundDangerous = true;
      break;
    }
  }

  if (foundDangerous && guardrailsDisabled) {
    badge.className = "badge badge-red";
    badge.innerText = "SECURITY RISK: Guardrails disabled with destructive commands";
  } else if (foundDangerous) {
    badge.className = "badge badge-amber";
    badge.innerText = `SECURITY NOTICE: ${ruleCount} rules (High-risk commands detected)`;
  } else {
    badge.className = "badge badge-green";
    badge.innerText = `VALID SCHEMA (${ruleCount} allow rules)`;
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
