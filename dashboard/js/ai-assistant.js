import { api } from "./api.js";
import { loadPoliciesAndFiles, selectPolicyForEdit } from "./policies.js";

export const aiConfig = {
  provider: localStorage.getItem("ag_llm_provider") || "openai",
  apiKey: localStorage.getItem("ag_llm_key") || "",
  model: localStorage.getItem("ag_llm_model") || "gpt-4o-mini",
  endpoint: localStorage.getItem("ag_llm_endpoint") || "http://localhost:11434/v1",
};

export const chatState = {
  messages: [
    {
      role: "assistant",
      content: "Hello! I am your **AgentGate Policy Architect**. Describe the agent role, permissions, or boundaries you need, and I will generate a hardened YAML policy ready to deploy.",
    }
  ],
  isGenerating: false,
};

const SYSTEM_PROMPT = `You are the AgentGate Security Policy Architect.
Your task is to generate valid, hardened YAML policies for AgentGate.

AgentGate Policy YAML Specification:
1. Root fields:
   name: <lowercase-identifier>
   description: <clear summary>
   guardrails: true # Always true unless explicitly told otherwise
   allow:
     - command: <binary or full path, or "*">
       args: ["exact-arg", "*"]
   deny:
     - command: <binary>
       args: ["..."]
   actions: # optional named actions
     <action_name>:
       description: "..."
       steps:
         - "/usr/bin/git pull"
       stop_on_failure: true

Security Rules:
- Prohibit GTFOBins escapes (vim, less, nano, python as root, bash without user mode).
- Ensure destructive commands (rm -rf, dd, mkfs, shutdown, /etc/shadow) are either in deny or guardrails: true.
- Output a clear explanation followed by the complete, valid YAML inside a markdown \`\`\`yaml code block.
- Keep policies principle-of-least-privilege.`;

export function saveAiSettings(provider, apiKey, model, endpoint) {
  aiConfig.provider = provider;
  aiConfig.apiKey = apiKey.trim();
  aiConfig.model = model.trim();
  aiConfig.endpoint = endpoint.trim();

  localStorage.setItem("ag_llm_provider", aiConfig.provider);
  localStorage.setItem("ag_llm_key", aiConfig.apiKey);
  localStorage.setItem("ag_llm_model", aiConfig.model);
  localStorage.setItem("ag_llm_endpoint", aiConfig.endpoint);

  window.showToast("AI Assistant settings saved.");
}

export function renderChatMessages() {
  const container = document.getElementById("aiMessagesContainer");
  if (!container) return;

  container.innerHTML = chatState.messages.map((msg, idx) => {
    const isUser = msg.role === "user";
    const bubbleContent = isUser ? escapeHtml(msg.content) : formatAiResponse(msg.content, idx);

    return `
      <div class="ai-msg ${isUser ? "user" : "assistant"}">
        <div style="font-size: 10px; font-weight: 600; text-transform: uppercase; color: var(--text-muted); margin-bottom: 2px;">
          ${isUser ? "You" : "Policy Architect"}
        </div>
        <div class="ai-bubble">${bubbleContent}</div>
      </div>
    `;
  }).join("");

  container.scrollTop = container.scrollHeight;
}

function formatAiResponse(text, msgIdx) {
  // Extract yaml blocks ```yaml ... ```
  const codeBlockRegex = /```(?:yaml|yml)?\s*([\s\S]*?)```/g;
  let formatted = text;
  let match;
  let blockIndex = 0;

  const blocks = [];
  while ((match = codeBlockRegex.exec(text)) !== null) {
    const yamlCode = match[1].trim();
    const nameMatch = yamlCode.match(/^name\s*:\s*["']?([a-zA-Z0-9_-]+)["']?/m);
    const policyName = nameMatch ? nameMatch[1] : `ai-policy-${Date.now()}`;

    blocks.push({
      original: match[0],
      code: yamlCode,
      name: policyName,
      id: `block_${msgIdx}_${blockIndex++}`,
    });
  }

  // Replace code blocks with interactive card
  for (const b of blocks) {
    const replacement = `
      <div class="code-block-container">
        <div class="code-block-header">
          <div style="display: flex; align-items: center; gap: 6px;">
            <span class="badge badge-green">YAML POLICY</span>
            <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-white);">${escapeHtml(b.name)}.yaml</span>
          </div>
          <div style="display: flex; gap: 4px;">
            <button class="btn btn-sm" onclick="window.copyAiYaml('${b.id}')">Copy</button>
            <button class="btn btn-sm" onclick="window.loadAiYamlIntoEditor('${b.id}')">Open in Editor</button>
            <button class="btn btn-sm btn-primary" onclick="window.deployAiYamlToServer('${b.id}', '${escapeHtml(b.name)}')">🚀 Deploy to Server</button>
          </div>
        </div>
        <pre class="code-block-body" id="${b.id}">${escapeHtml(b.code)}</pre>
      </div>
    `;
    formatted = formatted.replace(b.original, replacement);
  }

  // Simple markdown formatting for bold and list items
  formatted = formatted
    .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
    .replace(/\n\n/g, "<br><br>")
    .replace(/\n- /g, "<br>• ");

  return formatted;
}

export async function sendChatMessage(userText) {
  if (!userText.trim() || chatState.isGenerating) return;

  if (!aiConfig.apiKey && aiConfig.provider !== "ollama") {
    window.openAiSettingsModal();
    window.showToast("Please configure your LLM Provider & API Key first.", true);
    return;
  }

  chatState.messages.push({ role: "user", content: userText });
  renderChatMessages();

  chatState.isGenerating = true;
  const inputEl = document.getElementById("aiChatInput");
  const sendBtn = document.getElementById("aiSendBtn");
  if (inputEl) inputEl.value = "";
  if (sendBtn) {
    sendBtn.disabled = true;
    sendBtn.innerText = "Generating...";
  }

  try {
    const assistantReply = await callLlmApi(chatState.messages);
    chatState.messages.push({ role: "assistant", content: assistantReply });
    renderChatMessages();
  } catch (err) {
    chatState.messages.push({
      role: "assistant",
      content: `❌ Error communicating with LLM (${aiConfig.provider}): ${err.message}. Please check your API key and network connection.`,
    });
    renderChatMessages();
  } finally {
    chatState.isGenerating = false;
    if (sendBtn) {
      sendBtn.disabled = false;
      sendBtn.innerText = "Send";
    }
  }
}

async function callLlmApi(messagesHistory) {
  const provider = aiConfig.provider;

  if (provider === "openai" || provider === "groq" || provider === "ollama") {
    const endpoint = provider === "groq"
      ? "https://api.groq.com/openai/v1/chat/completions"
      : provider === "ollama"
        ? `${aiConfig.endpoint.replace(/\/$/, "")}/chat/completions`
        : "https://api.openai.com/v1/chat/completions";

    const headers = { "Content-Type": "application/json" };
    if (aiConfig.apiKey) {
      headers["Authorization"] = `Bearer ${aiConfig.apiKey}`;
    }

    const payloadMessages = [
      { role: "system", content: SYSTEM_PROMPT },
      ...messagesHistory.map(m => ({ role: m.role, content: m.content })),
    ];

    const res = await fetch(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify({
        model: aiConfig.model || (provider === "groq" ? "llama-3.3-70b-versatile" : "gpt-4o-mini"),
        messages: payloadMessages,
        temperature: 0.2,
      }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error?.message || `HTTP ${res.status}`);
    return data.choices[0]?.message?.content || "(No response received)";
  }

  if (provider === "gemini") {
    const model = aiConfig.model || "gemini-2.0-flash";
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${aiConfig.apiKey}`;

    const contents = messagesHistory.map(m => ({
      role: m.role === "assistant" ? "model" : "user",
      parts: [{ text: m.content }],
    }));

    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        system_instruction: { parts: [{ text: SYSTEM_PROMPT }] },
        contents,
        generationConfig: { temperature: 0.2 },
      }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error?.message || `HTTP ${res.status}`);
    return data.candidates[0]?.content?.parts[0]?.text || "(No response received)";
  }

  if (provider === "anthropic") {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": aiConfig.apiKey,
        "anthropic-version": "2023-06-01",
        "dangerously-allow-browser": "true",
      },
      body: JSON.stringify({
        model: aiConfig.model || "claude-3-5-sonnet-20241022",
        system: SYSTEM_PROMPT,
        messages: messagesHistory.map(m => ({ role: m.role, content: m.content })),
        max_tokens: 2048,
        temperature: 0.2,
      }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error?.message || `HTTP ${res.status}`);
    return data.content[0]?.text || "(No response received)";
  }

  throw new Error(`Unsupported provider: ${provider}`);
}

export async function deployAiYamlToServer(blockId, policyName) {
  const el = document.getElementById(blockId);
  if (!el) return;
  const yamlContent = el.innerText;
  const filename = `policies/${policyName}.yaml`;

  try {
    await api.writeFile(filename, yamlContent);
    window.showToast(`Deployed '${policyName}' to connected daemon successfully!`);
    await loadPoliciesAndFiles();
  } catch (err) {
    window.showToast(`Deploy failed: ${err.message}`, true);
  }
}

export function loadAiYamlIntoEditor(blockId) {
  const el = document.getElementById(blockId);
  if (!el) return;
  const yamlContent = el.innerText;

  const editor = document.getElementById("policyEditorTextarea");
  const title = document.getElementById("editorFilePath");
  if (editor && title) {
    editor.value = yamlContent;
    title.innerText = "policies/generated-ai-policy.yaml (Unsaved)";
    window.switchTab("policies");
    window.showToast("Loaded AI-generated policy into editor.");
  }
}

export function copyAiYaml(blockId) {
  const el = document.getElementById(blockId);
  if (!el) return;
  navigator.clipboard.writeText(el.innerText).then(() => {
    window.showToast("YAML copied to clipboard!");
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
