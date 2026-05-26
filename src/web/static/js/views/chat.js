// Intel chat view — grounded search over the TI store (design preserved).

import { apiFetch } from "../api.js";
import { appLayout, bindLogout } from "../ui.js";

function content() {
  return `
    <section class="section reveal delay-2">
      <div class="chat-shell">
        <div class="card">
          <h4>Active contexts</h4>
          <div class="list" style="margin-top: 12px;">
            <div class="list-item"><span>Article embeddings</span><span class="badge">vector</span></div>
            <div class="list-item"><span>IOCs / CVEs</span><span class="badge">keyword</span></div>
            <div class="list-item"><span>Search mode</span><span class="badge">contextual</span></div>
          </div>
          <div style="margin-top: 18px;">
            <h4>Suggested prompts</h4>
            <div class="chip-list" style="margin-top: 10px;">
              <span class="chip" data-prompt>ransomware infrastructure takedown</span>
              <span class="chip" data-prompt>critical VPN vulnerability exploited</span>
              <span class="chip" data-prompt>emerging botnet C2 activity</span>
            </div>
          </div>
        </div>

        <div class="card">
          <h4>Conversation</h4>
          <div class="chat-thread" id="chat-thread" style="margin-top: 14px; max-height: 360px; overflow-y: auto;">
            <div class="message assistant">Ask about indicators, CVEs, campaigns, or recent activity — answers are grounded in the collected intelligence.</div>
          </div>
          <form id="chat-form" style="margin-top: 16px; display: grid; gap: 10px;">
            <textarea id="chat-input" placeholder="Ask a threat intel question..."></textarea>
            <button class="button" type="submit">Send request</button>
          </form>
        </div>
      </div>
    </section>`;
}

export function render() {
  return appLayout({
    nav: "chat",
    title: "Intel chat",
    subtitle: "Contextual search over collected intelligence",
    content: content(),
  });
}

export function mount() {
  bindLogout();
  const form = document.getElementById("chat-form");
  const input = document.getElementById("chat-input");
  const thread = document.getElementById("chat-thread");

  const addMessage = (role, text) => {
    const msg = document.createElement("div");
    msg.className = `message ${role}`;
    msg.textContent = text;
    thread.appendChild(msg);
    thread.scrollTop = thread.scrollHeight;
  };

  const ask = async (value) => {
    addMessage("user", value);
    try {
      const res = await apiFetch("/chat/ask", {
        method: "POST",
        body: JSON.stringify({ message: value }),
      });
      addMessage("assistant", res.answer + (res.sources?.length ? `\n\nSources: ${res.sources.join(", ")}` : ""));
    } catch {
      addMessage("assistant", "Unable to reach the intel API right now.");
    }
  };

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const value = input.value.trim();
    if (!value) return;
    input.value = "";
    ask(value);
  });

  document.querySelectorAll("[data-prompt]").forEach((chip) =>
    chip.addEventListener("click", () => ask(chip.textContent.trim()))
  );
}
