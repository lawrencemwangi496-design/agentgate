import { api } from "./api.js";

const commandHistory = [];
let historyIndex = -1;

export async function executeConsoleCommand() {
  const cmdInput = document.getElementById("consoleCmdInput");
  const cwdInput = document.getElementById("consoleCwdInput");
  const outBox = document.getElementById("consoleOutput");

  const cmd = cmdInput.value.trim();
  const cwd = cwdInput.value.trim() || null;

  if (!cmd) return;

  commandHistory.unshift(cmd);
  historyIndex = -1;

  outBox.innerText = `> ${cmd}\n[Executing via connected daemon...]`;

  const startTime = performance.now();

  try {
    const data = await api.execCommand(cmd, cwd);
    const duration = Math.round(performance.now() - startTime);

    outBox.innerText = `[Exit Code: ${data.exit_code}] [${data.duration_ms || duration}ms]\n\nSTDOUT:\n${data.stdout || "(empty)"}\n\nSTDERR:\n${data.stderr || "(empty)"}`;
  } catch (err) {
    outBox.innerText = `Execution Error: ${err.message}`;
  }
}

export function initConsoleKeybindings() {
  const cmdInput = document.getElementById("consoleCmdInput");
  if (!cmdInput) return;

  cmdInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      executeConsoleCommand();
    } else if (e.key === "ArrowUp") {
      if (historyIndex < commandHistory.length - 1) {
        historyIndex++;
        cmdInput.value = commandHistory[historyIndex];
      }
    } else if (e.key === "ArrowDown") {
      if (historyIndex > 0) {
        historyIndex--;
        cmdInput.value = commandHistory[historyIndex];
      } else if (historyIndex === 0) {
        historyIndex = -1;
        cmdInput.value = "";
      }
    }
  });
}
