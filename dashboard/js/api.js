// AgentGate API Client & SSE Stream Manager

export const state = {
  host: localStorage.getItem("ag_host") || "http://127.0.0.1:7991",
  token: localStorage.getItem("ag_token") || "",
  connected: false,
  version: "0.1.9",
  isLockdown: false,
  uptimeSeconds: 0,
  activeExecutions: [],
  sseSource: null,
};

export function setConnection(host, token) {
  state.host = host.replace(/\/$/, "");
  state.token = token.trim();
  localStorage.setItem("ag_host", state.host);
  localStorage.setItem("ag_token", state.token);
}

export function getHeaders() {
  const headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
  };
  if (state.token) {
    headers["Authorization"] = `Bearer ${state.token}`;
  }
  return headers;
}

export async function request(path, options = {}) {
  const url = `${state.host}${path}`;
  const opts = {
    ...options,
    headers: {
      ...getHeaders(),
      ...(options.headers || {}),
    },
  };

  try {
    const res = await fetch(url, opts);
    let data;
    const contentType = res.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      data = await res.json();
    } else {
      data = await res.text();
    }

    if (!res.ok) {
      const err = new Error(typeof data === "object" ? (data.message || data.error || `HTTP ${res.status}`) : data);
      err.status = res.status;
      err.data = data;
      throw err;
    }

    return data;
  } catch (err) {
    console.error(`API Error on ${path}:`, err);
    throw err;
  }
}

// Daemon Endpoints
export const api = {
  getStatus: () => request("/v1/admin/status"),
  getPolicies: () => request("/v1/policies"),
  getFiles: () => request("/v1/admin/files"),
  readFile: (path) => request(`/v1/admin/files/${encodeURIComponent(path)}`),
  writeFile: (path, content) => request(`/v1/admin/files/${encodeURIComponent(path)}`, {
    method: "PUT",
    body: JSON.stringify({ content }),
  }),
  deleteFile: (path) => request(`/v1/admin/files/${encodeURIComponent(path)}`, {
    method: "DELETE",
  }),
  getTokens: () => request("/v1/admin/tokens"),
  createToken: (payload) => request("/v1/admin/tokens", {
    method: "POST",
    body: JSON.stringify(payload),
  }),
  revokeToken: (name) => request(`/v1/admin/tokens/revoke/${encodeURIComponent(name)}`, {
    method: "POST",
  }),
  getExecutions: () => request("/v1/admin/executions"),
  killExecution: (id) => request(`/v1/admin/executions/kill/${encodeURIComponent(id)}`, {
    method: "POST",
  }),
  toggleLockdown: (enable) => request(enable ? "/v1/admin/lockdown" : "/v1/admin/unlock", {
    method: "POST",
  }),
  restartDaemon: () => request("/v1/admin/restart", {
    method: "POST",
  }),
  execCommand: (command, cwd = null) => request("/v1/exec", {
    method: "POST",
    body: JSON.stringify({ command, ...(cwd ? { cwd } : {}) }),
  }),
};

export function startSseStream(onAudit, onHeartbeat, onError) {
  if (state.sseSource) {
    state.sseSource.close();
    state.sseSource = null;
  }

  const streamUrl = `${state.host}/v1/admin/stream?token=${encodeURIComponent(state.token)}`;
  const sse = new EventSource(streamUrl);
  state.sseSource = sse;

  sse.onopen = () => {
    state.connected = true;
    if (onHeartbeat) onHeartbeat({ connected: true });
  };

  sse.addEventListener("audit", (e) => {
    try {
      const entry = JSON.parse(e.data);
      if (onAudit) onAudit(entry);
    } catch (_) {}
  });

  sse.addEventListener("heartbeat", (e) => {
    try {
      const data = JSON.parse(e.data);
      state.isLockdown = data.lockdown;
      state.uptimeSeconds = data.uptime_seconds;
      state.activeExecutions = data.active_executions || [];
      if (onHeartbeat) onHeartbeat(data);
    } catch (_) {}
  });

  sse.onerror = (err) => {
    state.connected = false;
    if (onError) onError(err);
  };
}

export function stopSseStream() {
  if (state.sseSource) {
    state.sseSource.close();
    state.sseSource = null;
    state.connected = false;
  }
}
