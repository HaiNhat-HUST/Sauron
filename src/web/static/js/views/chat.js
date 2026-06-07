// Intel chat view — tool-calling agent + structured report generator.
//
// The conversation pane shows a transcript with markdown-rendered assistant
// replies and a collapsible "trace" listing the tools the agent invoked. The
// report pane runs the dedicated /chat/report endpoint and renders the
// returned markdown brief.

import { apiFetch } from "../api.js";
import { appLayout, bindLogout, esc } from "../ui.js";

// ---------------------------------------------------------------------------
// Minimal markdown renderer — covers headings / lists / bold / italic / code /
// fenced code blocks / links. Enough for the agent's output and report briefs.
// ---------------------------------------------------------------------------
function renderMarkdown(text) {
  if (!text) return "";
  const lines = String(text).split("\n");
  const html = [];
  let inCode = false;
  let inList = false;
  let codeBuf = [];

  const inline = (s) => {
    let t = esc(s);
    t = t.replace(/`([^`]+)`/g, "<code>$1</code>");
    t = t.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    t = t.replace(/\*([^*]+)\*/g, "<em>$1</em>");
    t = t.replace(
      /\[([^\]]+)\]\((https?:[^)\s]+)\)/g,
      '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>'
    );
    return t;
  };

  const closeList = () => { if (inList) { html.push("</ul>"); inList = false; } };

  for (const raw of lines) {
    if (raw.startsWith("```")) {
      if (inCode) {
        html.push(`<pre><code>${esc(codeBuf.join("\n"))}</code></pre>`);
        codeBuf = []; inCode = false;
      } else { closeList(); inCode = true; }
      continue;
    }
    if (inCode) { codeBuf.push(raw); continue; }
    if (raw.startsWith("# "))  { closeList(); html.push(`<h2>${inline(raw.slice(2))}</h2>`); continue; }
    if (raw.startsWith("## ")) { closeList(); html.push(`<h3>${inline(raw.slice(3))}</h3>`); continue; }
    if (raw.startsWith("### ")){ closeList(); html.push(`<h4>${inline(raw.slice(4))}</h4>`); continue; }
    if (raw.startsWith("- "))  {
      if (!inList) { html.push("<ul>"); inList = true; }
      html.push(`<li>${inline(raw.slice(2))}</li>`); continue;
    }
    if (raw.trim() === "") { closeList(); continue; }
    closeList();
    html.push(`<p>${inline(raw)}</p>`);
  }
  if (inList) html.push("</ul>");
  if (inCode) html.push(`<pre><code>${esc(codeBuf.join("\n"))}</code></pre>`);
  return html.join("\n");
}

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------
const SESSION_KEY = "ti-chat-session";

function getOrCreateSession() {
  let sid = localStorage.getItem(SESSION_KEY);
  if (!sid) {
    sid = `s-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    localStorage.setItem(SESSION_KEY, sid);
  }
  return sid;
}

function content() {
  return `
    <section class="section reveal delay-2">
      <div class="chat-shell">
        <div class="card">
          <h4>Agent capabilities</h4>
          <div class="list" style="margin-top: 12px;">
            <div class="list-item"><span>Semantic article search</span><span class="badge">vector</span></div>
            <div class="list-item"><span>IOC / CVE lookup</span><span class="badge">exact</span></div>
            <div class="list-item"><span>Tag / actor pivot</span><span class="badge">graph</span></div>
            <div class="list-item"><span>Report synthesis</span><span class="badge">structured</span></div>
          </div>
          <div style="margin-top: 18px;">
            <div style="display:flex; align-items:baseline; justify-content:space-between;">
              <h4 style="margin:0;">Suggested prompts</h4>
              <button class="link-button" id="suggestions-refresh" type="button" title="Refresh from live data">refresh</button>
            </div>
            <p class="small-note" style="margin: 6px 0 10px;">Generated from the entities the TI store currently knows about.</p>
            <div class="chip-list" id="suggestion-chips" style="margin-top: 10px;">
              <span class="small-note">Loading…</span>
            </div>
          </div>
          <div style="margin-top: 18px;">
            <button class="button button-ghost" id="chat-reset" type="button">Reset conversation</button>
          </div>
        </div>

        <div class="card">
          <div class="chat-tabs" role="tablist" style="display:flex; gap: 8px; margin-bottom: 14px;">
            <button class="button button-ghost" id="tab-chat" type="button" data-active="true">Chat</button>
            <button class="button button-ghost" id="tab-report" type="button">Generate report</button>
          </div>

          <div id="pane-chat">
            <div class="chat-thread" id="chat-thread" style="max-height: 460px; overflow-y: auto;">
              <div class="message assistant">
                <div class="md">Ask about indicators, CVEs, campaigns, tags, or recent activity. I'll ground every answer in the collected intelligence.</div>
              </div>
            </div>
            <form id="chat-form" class="chat-composer">
              <textarea id="chat-input" class="chat-input" rows="1"
                placeholder="Ask a threat intel question…  (e.g. What do we know about LockBit?)"></textarea>
              <button class="chat-send" type="submit" title="Send (Enter)" aria-label="Send">
                <span class="chat-send-icon">↑</span>
              </button>
            </form>
            <div class="chat-hint small-note">
              <span><kbd>Enter</kbd> to send · <kbd>Shift</kbd>+<kbd>Enter</kbd> for a new line</span>
            </div>
          </div>

          <div id="pane-report" hidden>
            <p class="small-note">
              Synthesizes a structured TI brief on a topic. The agent retrieves evidence
              from articles, tags and recent intel, then fills a fixed report schema.
            </p>
            <form id="report-form" style="display: grid; gap: 10px;">
              <input class="input" id="report-topic" type="text" placeholder='e.g. "LockBit ransomware activity"' />
              <button class="button" type="submit">Generate report</button>
            </form>
            <div id="report-output" style="margin-top: 18px;"></div>
          </div>
        </div>
      </div>
    </section>`;
}

export function render() {
  return appLayout({
    nav: "chat",
    title: "Intel agent",
    subtitle: "AI analyst grounded in the collected TI store",
    content: content(),
  });
}

export function mount() {
  bindLogout();
  const sessionId = getOrCreateSession();

  const thread = document.getElementById("chat-thread");
  const form = document.getElementById("chat-form");
  const input = document.getElementById("chat-input");
  const resetBtn = document.getElementById("chat-reset");

  const tabChat = document.getElementById("tab-chat");
  const tabReport = document.getElementById("tab-report");
  const paneChat = document.getElementById("pane-chat");
  const paneReport = document.getElementById("pane-report");
  const reportForm = document.getElementById("report-form");
  const reportTopic = document.getElementById("report-topic");
  const reportOutput = document.getElementById("report-output");

  // ---- chat ---------------------------------------------------------------
  const addUserMessage = (text) => {
    const el = document.createElement("div");
    el.className = "message user";
    el.innerHTML = `<div class="md">${esc(text).replace(/\n/g, "<br>")}</div>`;
    thread.appendChild(el);
    thread.scrollTop = thread.scrollHeight;
  };

  const addAssistantMessage = ({ answer, tool_calls, sources, pending }) => {
    const el = document.createElement("div");
    el.className = "message assistant";
    let traceHtml = "";
    if (tool_calls && tool_calls.length) {
      const items = tool_calls.map((tc) => {
        const argSummary = tc.args ? esc(JSON.stringify(tc.args)) : "";
        const status = tc.ok ? "" : ' <span class="badge badge-err">error</span>';
        return `<li><code>${esc(tc.name)}</code>${status}
                  <div class="small-note">${argSummary}</div>
                  <div class="small-note">→ ${esc(tc.preview || "")}</div></li>`;
      }).join("");
      traceHtml = `<details class="chat-trace" style="margin-top: 8px;">
                     <summary>${tool_calls.length} tool call${tool_calls.length > 1 ? "s" : ""}</summary>
                     <ul style="margin: 6px 0 0; padding-left: 18px;">${items}</ul>
                   </details>`;
    }
    const sourcesHtml = sources && sources.length
      ? `<div class="small-note" style="margin-top: 8px;">Sources: ${sources.map(esc).join(", ")}</div>`
      : "";
    const body = pending
      ? `<div class="md small-note">Thinking…</div>`
      : `<div class="md">${renderMarkdown(answer)}</div>${traceHtml}${sourcesHtml}`;
    el.innerHTML = body;
    thread.appendChild(el);
    thread.scrollTop = thread.scrollHeight;
    return el;
  };

  const ask = async (value) => {
    addUserMessage(value);
    const pending = addAssistantMessage({ pending: true });
    try {
      const res = await apiFetch("/chat/ask", {
        method: "POST",
        body: JSON.stringify({ message: value, session_id: sessionId }),
      });
      pending.remove();
      addAssistantMessage(res);
    } catch (exc) {
      pending.remove();
      addAssistantMessage({
        answer: "Unable to reach the agent. Check the LLM provider configuration.",
      });
    }
  };

  const sendBtn = form.querySelector(".chat-send");

  // Grow the textarea with its content, up to a cap, then scroll.
  const autoGrow = () => {
    input.style.height = "auto";
    input.style.height = `${Math.min(input.scrollHeight, 180)}px`;
  };
  // Reflect "has text" so the send button can light up / dim.
  const syncSendState = () => {
    const empty = input.value.trim() === "";
    if (sendBtn) sendBtn.disabled = empty;
    form.classList.toggle("is-empty", empty);
  };

  const submitPrompt = () => {
    const value = input.value.trim();
    if (!value) return;
    input.value = "";
    autoGrow();
    syncSendState();
    ask(value);
  };

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    submitPrompt();
  });

  // Enter sends; Shift+Enter inserts a newline.
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      submitPrompt();
    }
  });
  input.addEventListener("input", () => { autoGrow(); syncSendState(); });
  syncSendState();

  // ---- dynamic suggested prompts -----------------------------------------
  const chipsBox = document.getElementById("suggestion-chips");
  const refreshBtn = document.getElementById("suggestions-refresh");

  const _CATEGORY_BADGE = {
    threat_actor:     "actor",
    malware:          "malware",
    attack_technique: "ATT&CK",
    campaign:         "campaign",
    cve:              "CVE",
    ioc:              "IOC",
    stats:            "stats",
    recent:           "recent",
  };

  const renderChips = (items) => {
    if (!items || items.length === 0) {
      chipsBox.innerHTML = `<span class="small-note">No suggestions yet — the store is still warming up.</span>`;
      return;
    }
    chipsBox.innerHTML = items.map((s) => {
      const label = _CATEGORY_BADGE[s.category] || s.category || "";
      return `<span class="chip" data-prompt title="Category: ${esc(s.category)}">
                <span class="chip-tag">${esc(label)}</span>
                ${esc(s.prompt)}
              </span>`;
    }).join("");
    chipsBox.querySelectorAll("[data-prompt]").forEach((chip) => {
      // Take only the visible prompt text, drop the leading chip-tag span.
      chip.addEventListener("click", () => {
        const tagSpan = chip.querySelector(".chip-tag");
        const prompt = chip.textContent.replace(tagSpan ? tagSpan.textContent : "", "").trim();
        ask(prompt);
      });
    });
  };

  const loadSuggestions = async () => {
    try {
      const res = await apiFetch("/chat/suggestions");
      renderChips(res.items || []);
    } catch {
      chipsBox.innerHTML = `<span class="small-note is-error">Unable to load suggestions.</span>`;
    }
  };

  refreshBtn.addEventListener("click", loadSuggestions);
  loadSuggestions();

  resetBtn.addEventListener("click", async () => {
    try {
      await apiFetch("/chat/reset", {
        method: "POST",
        body: JSON.stringify({ session_id: sessionId }),
      });
    } catch { /* ignore */ }
    thread.innerHTML = `<div class="message assistant"><div class="md">Conversation cleared. Ask me anything.</div></div>`;
  });

  // ---- tabs ---------------------------------------------------------------
  const setTab = (which) => {
    const chat = which === "chat";
    tabChat.dataset.active = chat ? "true" : "false";
    tabReport.dataset.active = chat ? "false" : "true";
    paneChat.hidden = !chat;
    paneReport.hidden = chat;
  };
  tabChat.addEventListener("click", () => setTab("chat"));
  tabReport.addEventListener("click", () => setTab("report"));

  // ---- report -------------------------------------------------------------
  reportForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const topic = reportTopic.value.trim();
    if (!topic) return;
    reportOutput.innerHTML = `<div class="small-note">Synthesizing brief on "${esc(topic)}"… this can take 10-30s.</div>`;
    try {
      const res = await apiFetch("/chat/report", {
        method: "POST",
        body: JSON.stringify({ topic }),
      });
      const md = res.markdown || "";
      const generated = res.generated_at ? new Date(res.generated_at).toLocaleString() : "";
      reportOutput.innerHTML = `
        <article class="md report-card">
          ${renderMarkdown(md)}
        </article>
        <div class="small-note" style="margin-top: 10px;">
          Generated ${esc(generated)} ·
          <a href="#" id="report-download">Download Markdown</a>
        </div>`;
      const dl = document.getElementById("report-download");
      dl.addEventListener("click", (e) => {
        e.preventDefault();
        const blob = new Blob([md], { type: "text/markdown" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `ti-report-${topic.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}.md`;
        a.click();
        URL.revokeObjectURL(a.href);
      });
    } catch (exc) {
      reportOutput.innerHTML = `<div class="small-note is-error">Report generation failed: ${esc(exc?.message || exc)}</div>`;
    }
  });
}
