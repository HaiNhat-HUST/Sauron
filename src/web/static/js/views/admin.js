// Admin console view — connector control (config + run-now), retention, users.

import { apiFetch } from "../api.js";
import { appLayout, bindLogout, dateShort, esc, setStatus } from "../ui.js";

function content() {
  return `
    <section class="section reveal delay-2">
      <div class="section-head">
        <div class="section-title">Connector control</div>
        <label class="toggle-inline"><input type="checkbox" id="connectors-autorefresh" checked /> Auto-refresh</label>
      </div>
      <p class="small-note" id="connectors-summary"></p>
      <p class="small-note" id="admin-status"></p>
      <table class="table">
        <thead>
          <tr><th>Connector</th><th>Source</th><th>Interval (min)</th><th>Last run</th><th>State</th><th>Last result</th><th>Enabled</th><th>Actions</th></tr>
        </thead>
        <tbody id="connectors-body"></tbody>
      </table>
    </section>

    <section class="section reveal">
      <div class="section-head">
        <div class="section-title">Retention policy</div>
        <button class="button secondary" type="button" id="retention-save">Save policy</button>
      </div>
      <p class="small-note" id="retention-status"></p>
      <div class="grid-3" id="retention-form">
        <div class="card"><h4>Raw ingestion retention</h4><div class="field"><input id="retention-raw" type="number" value="30" /></div><div class="small-note">Days to keep raw bundles</div></div>
        <div class="card"><h4>Normalized entities</h4><div class="field"><input id="retention-normalized" type="number" value="180" /></div><div class="small-note">Days to keep enriched data</div></div>
        <div class="card"><h4>Archive window</h4><div class="field"><select id="retention-archive">
          <option value="cold-storage">Move to cold storage</option>
          <option value="delete">Delete after retention</option>
          <option value="keep">Keep indefinitely</option>
        </select></div><div class="small-note">Policy for expired data</div></div>
      </div>
    </section>

    <section class="section reveal">
      <div class="section-head">
        <div class="section-title">LLM models</div>
        <span class="small-note">Configure providers and route each AI function</span>
      </div>
      <p class="small-note" id="llm-status"></p>

      <div class="grid-3" id="llm-providers"></div>

      <h4 style="margin-top: 22px;">Function routing</h4>
      <p class="small-note">Pick a different model per function to tune cost vs. quality.</p>
      <div id="llm-functions" style="display:grid; gap:10px; margin-top:8px;"></div>

      <h4 style="margin-top: 22px;">Recommended presets</h4>
      <div class="chip-list" id="llm-presets" style="margin-top: 8px;"></div>
    </section>

    <section class="section reveal">
      <div class="section-head"><div class="section-title">User management</div></div>
      <form class="form-row" id="user-create-form">
        <div class="field"><label for="new-username">Username</label><input id="new-username" type="text" placeholder="new.user" /></div>
        <div class="field"><label for="new-password">Password</label><input id="new-password" type="password" placeholder="min 6 chars" /></div>
        <div class="field"><label for="new-role">Role</label><select id="new-role"><option value="analyst">Analyst</option><option value="admin">Administrator</option></select></div>
        <div class="field"><label>&nbsp;</label><button class="button" type="submit">Create user</button></div>
      </form>
      <p class="small-note" id="user-create-status"></p>
      <table class="table">
        <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Created at</th><th>Actions</th></tr></thead>
        <tbody id="users-body"></tbody>
      </table>
    </section>`;
}

export function render() {
  return appLayout({
    nav: "admin",
    title: "Admin console",
    subtitle: "Manage connectors, schedules, and access",
    content: content(),
  });
}

const stateChip = (c) => {
  if (c.status === "running") return `<span class="badge badge-run">Running…</span>`;
  if (c.status === "queued") return `<span class="badge badge-run">Queued</span>`;
  return c.is_enabled ? `<span class="badge">Scheduled</span>` : `<span class="badge badge-off">Paused</span>`;
};

const resultChip = (c) => {
  const ls = c.last_status;
  if (!ls) return `<span class="small-note">—</span>`;
  if (ls === "ok") return `<span class="badge badge-ok">OK · ${c.last_objects ?? 0} obj</span>`;
  if (ls === "needs-key") return `<span class="badge badge-warn" title="${c.last_error || ""}">Needs key</span>`;
  return `<span class="badge badge-err" title="${(c.last_error || "").replace(/"/g, "'")}">Error</span>`;
};

function renderConnectors(connectors) {
  const body = document.getElementById("connectors-body");
  if (!body) return;
  // Don't clobber an interval field being edited.
  const active = document.activeElement;
  if (active && active.matches && active.matches("#connectors-body [data-interval]")) return;
  body.innerHTML = "";
  const adminStatus = document.getElementById("admin-status");

  connectors.forEach((c) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${c.name}</td>
      <td>${c.source}</td>
      <td><input class="input-inline" type="number" min="1" value="${c.interval_minutes}" data-interval /></td>
      <td>${dateShort(c.last_run)}</td>
      <td>${stateChip(c)}</td>
      <td>${resultChip(c)}</td>
      <td><label class="toggle"><input type="checkbox" ${c.is_enabled ? "checked" : ""} data-toggle /><span class="slider"></span></label></td>
      <td><button class="button secondary button-sm" type="button" data-run>Run now</button></td>`;

    const intervalInput = row.querySelector("[data-interval]");
    const toggleInput = row.querySelector("[data-toggle]");
    const runBtn = row.querySelector("[data-run]");
    const update = (payload) =>
      apiFetch(`/admin/connectors/${c.id}`, { method: "PUT", body: JSON.stringify(payload) });

    intervalInput.addEventListener("change", async () => {
      const value = Number.parseInt(intervalInput.value, 10);
      if (!Number.isFinite(value) || value <= 0) return;
      try {
        await update({ interval_minutes: value });
        setStatus(adminStatus, `${c.name}: interval set to ${value} min`, false);
      } catch (error) {
        intervalInput.value = c.interval_minutes;
        setStatus(adminStatus, error.message || "Failed to update interval", true);
      }
    });

    toggleInput.addEventListener("change", async () => {
      try {
        await update({ is_enabled: toggleInput.checked });
        refreshConnectors();
      } catch (error) {
        toggleInput.checked = !toggleInput.checked;
        setStatus(adminStatus, error.message || "Failed to toggle connector", true);
      }
    });

    runBtn.addEventListener("click", async () => {
      runBtn.disabled = true;
      runBtn.textContent = "Queued…";
      try {
        await apiFetch(`/admin/connectors/${c.id}/run`, { method: "POST" });
        setStatus(adminStatus, `${c.name}: run triggered`, false);
        setTimeout(refreshConnectors, 800);
      } catch (error) {
        setStatus(adminStatus, error.message || "Failed to trigger run", true);
      } finally {
        setTimeout(() => { runBtn.disabled = false; runBtn.textContent = "Run now"; }, 1200);
      }
    });

    body.appendChild(row);
  });
}

function renderSummary(connectors) {
  const el = document.getElementById("connectors-summary");
  if (!el) return;
  const total = connectors.length;
  const enabled = connectors.filter((c) => c.is_enabled).length;
  const running = connectors.filter((c) => c.status === "running" || c.status === "queued").length;
  const errors = connectors.filter((c) => c.last_status === "error").length;
  const needKey = connectors.filter((c) => c.last_status === "needs-key").length;
  el.textContent = `${enabled}/${total} enabled · ${running} active now · ${errors} error(s)` +
    (needKey ? ` · ${needKey} need API key` : "");
}

async function refreshConnectors() {
  try {
    const connectors = await apiFetch("/admin/connectors");
    renderConnectors(connectors);
    renderSummary(connectors);
  } catch { /* transient; next poll retries */ }
}

async function loadUsers(statusEl) {
  const users = await apiFetch("/admin/users");
  const body = document.getElementById("users-body");
  if (!body) return;
  body.innerHTML = "";
  users.forEach((acc) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${acc.username}</td>
      <td><select class="input-inline" data-role>
        <option value="admin" ${acc.role === "admin" ? "selected" : ""}>Administrator</option>
        <option value="analyst" ${acc.role === "analyst" ? "selected" : ""}>Analyst</option>
      </select></td>
      <td><span class="status">${acc.is_active ? "Active" : "Disabled"}</span></td>
      <td>${acc.created_at || "-"}</td>
      <td><div class="user-actions">
        <input class="input-inline" type="password" placeholder="New password" data-password />
        <label class="toggle"><input type="checkbox" ${acc.is_active ? "checked" : ""} data-active /><span class="slider"></span></label>
        <button class="button secondary" type="button" data-save>Save</button>
      </div></td>`;
    const saveBtn = row.querySelector("[data-save]");
    saveBtn.addEventListener("click", async () => {
      try {
        await apiFetch(`/admin/users/${acc.id}`, {
          method: "PUT",
          body: JSON.stringify({
            role: row.querySelector("[data-role]").value,
            is_active: row.querySelector("[data-active]").checked,
            password: row.querySelector("[data-password]").value.trim() || null,
          }),
        });
        row.querySelector(".status").textContent = row.querySelector("[data-active]").checked ? "Active" : "Disabled";
        row.querySelector("[data-password]").value = "";
        setStatus(statusEl, "User updated", false);
      } catch (error) {
        setStatus(statusEl, error.message || "Failed to update user", true);
      }
    });
    body.appendChild(row);
  });
}

// --- LLM section ---------------------------------------------------------
const PROVIDER_LABELS = {
  openai: "OpenAI",
  gemini: "Google Gemini",
  ollama: "Ollama (local)",
};

const PROVIDER_NEEDS_KEY = { openai: true, gemini: true, ollama: false };

function modelDatalistId(provider) {
  return `models-${provider}`;
}

function renderProviderCard(provider, availableModels) {
  const id = provider.name;
  const needsKey = PROVIDER_NEEDS_KEY[id];
  const keyPlaceholder = provider.has_key ? `unchanged · ${esc(provider.key_hint || "")}` : "paste API key";
  const models = availableModels[id] || [];
  const datalist = `
    <datalist id="${modelDatalistId(id)}">
      ${models.map((m) => `<option value="${esc(m.id)}">${esc(m.label)}</option>`).join("")}
    </datalist>`;
  return `
    <div class="card llm-provider" data-provider="${id}">
      <div style="display:flex; align-items:center; justify-content:space-between;">
        <h4 style="margin:0;">${esc(PROVIDER_LABELS[id] || id)}</h4>
        <label class="toggle"><input type="checkbox" ${provider.enabled ? "checked" : ""} data-enabled /><span class="slider"></span></label>
      </div>

      ${needsKey ? `
        <div class="field" style="margin-top:12px;">
          <label>API key</label>
          <input class="input-inline" type="password" placeholder="${keyPlaceholder}" data-key />
          <div class="small-note">Saved server-side; never returned by GET.</div>
        </div>` : `
        <div class="field" style="margin-top:12px;">
          <label>Base URL</label>
          <input class="input-inline" type="text" value="${esc(provider.base_url || "")}" placeholder="http://localhost:11434" data-baseurl />
        </div>`}

      <div class="field" style="margin-top:10px;">
        <label>Default model</label>
        <input class="input-inline" type="text" list="${modelDatalistId(id)}" value="${esc(provider.default_model || "")}" data-default-model />
      </div>
      ${datalist}

      <div style="display:flex; gap:8px; margin-top:14px;">
        <button class="button button-sm" type="button" data-save>Save</button>
        <button class="button secondary button-sm" type="button" data-test>Test</button>
      </div>
      <p class="small-note" data-result style="margin-top:8px;"></p>
    </div>`;
}

function renderFunctionRow(fn, meta, providers, availableModels) {
  const enabledProviders = providers.filter((p) => p.enabled);
  const options = enabledProviders.length
    ? enabledProviders.map((p) =>
        `<option value="${p.name}" ${p.name === fn.provider ? "selected" : ""}>${esc(PROVIDER_LABELS[p.name] || p.name)}</option>`
      ).join("")
    : `<option value="">(no provider enabled)</option>`;
  const dlId = modelDatalistId(fn.provider);
  return `
    <div class="card llm-function" data-function="${fn.function}" style="padding:14px 16px;">
      <div style="display:flex; justify-content:space-between; align-items:baseline; gap:10px;">
        <div><strong>${esc(meta?.label || fn.function)}</strong><div class="small-note">${esc(meta?.hint || "")}</div></div>
      </div>
      <div class="form-row" style="margin-top:10px; margin-bottom:0;">
        <div class="field">
          <label>Provider</label>
          <select class="input-inline" data-provider ${enabledProviders.length ? "" : "disabled"}>${options}</select>
        </div>
        <div class="field">
          <label>Model (blank = provider default)</label>
          <input class="input-inline" type="text" list="${dlId}" value="${esc(fn.model || "")}" placeholder="default" data-model />
        </div>
        <div class="field" style="align-self:end;">
          <button class="button button-sm" type="button" data-save>Save</button>
        </div>
      </div>
    </div>`;
}

function renderPresets(presets) {
  return presets.map((p) => `
    <button class="chip llm-preset" type="button" data-preset="${p.id}" title="${esc(p.hint)}">${esc(p.label)}</button>
  `).join("");
}

async function loadLLMConfig() {
  const data = await apiFetch("/admin/llm");
  const status = document.getElementById("llm-status");
  const providersEl = document.getElementById("llm-providers");
  const functionsEl = document.getElementById("llm-functions");
  const presetsEl = document.getElementById("llm-presets");

  providersEl.innerHTML = data.providers.map((p) => renderProviderCard(p, data.available_models)).join("");
  const metaByName = Object.fromEntries(data.function_meta.map((m) => [m.name, m]));
  functionsEl.innerHTML = data.functions
    .map((f) => renderFunctionRow(f, metaByName[f.function], data.providers, data.available_models))
    .join("");
  presetsEl.innerHTML = renderPresets(data.presets);

  // Wire provider cards
  providersEl.querySelectorAll(".llm-provider").forEach((card) => {
    const name = card.dataset.provider;
    const result = card.querySelector("[data-result]");
    card.querySelector("[data-save]").addEventListener("click", async () => {
      const payload = {
        enabled: card.querySelector("[data-enabled]").checked,
        default_model: card.querySelector("[data-default-model]").value.trim() || null,
      };
      const keyInput = card.querySelector("[data-key]");
      const baseInput = card.querySelector("[data-baseurl]");
      if (keyInput && keyInput.value.trim() !== "") payload.api_key = keyInput.value.trim();
      if (baseInput) payload.base_url = baseInput.value.trim() || "";
      try {
        await apiFetch(`/admin/llm/providers/${name}`, { method: "PUT", body: JSON.stringify(payload) });
        setStatus(result, "Saved", false);
        if (keyInput) keyInput.value = "";
        await loadLLMConfig();  // refresh so function rows pick up provider changes
      } catch (error) {
        setStatus(result, error.message || "Failed to save", true);
      }
    });
    card.querySelector("[data-test]").addEventListener("click", async () => {
      setStatus(result, "Testing…", false);
      try {
        const res = await apiFetch(`/admin/llm/providers/${name}/test`, { method: "POST" });
        if (res.ok) {
          setStatus(result, `OK · ${res.latency_ms} ms · ${(res.message || "").slice(0, 80)}`, false);
        } else {
          setStatus(result, `Failed: ${res.message}`, true);
        }
      } catch (error) {
        setStatus(result, error.message || "Test failed", true);
      }
    });
  });

  // Wire function rows
  functionsEl.querySelectorAll(".llm-function").forEach((row) => {
    const fn = row.dataset.function;
    const providerSelect = row.querySelector("[data-provider]");
    const modelInput = row.querySelector("[data-model]");
    providerSelect.addEventListener("change", () => {
      modelInput.setAttribute("list", modelDatalistId(providerSelect.value));
    });
    row.querySelector("[data-save]").addEventListener("click", async () => {
      try {
        await apiFetch(`/admin/llm/functions/${fn}`, {
          method: "PUT",
          body: JSON.stringify({
            provider: providerSelect.value,
            model: modelInput.value.trim() || null,
          }),
        });
        setStatus(document.getElementById("llm-status"), `${fn}: routing updated`, false);
      } catch (error) {
        setStatus(document.getElementById("llm-status"), error.message || "Failed", true);
      }
    });
  });

  // Wire presets — apply all three function routes at once.
  presetsEl.querySelectorAll(".llm-preset").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const preset = data.presets.find((p) => p.id === btn.dataset.preset);
      if (!preset) return;
      const status = document.getElementById("llm-status");
      try {
        for (const [fn, assignment] of Object.entries(preset.assignments)) {
          await apiFetch(`/admin/llm/functions/${fn}`, {
            method: "PUT",
            body: JSON.stringify({ provider: assignment.provider, model: assignment.model || null }),
          });
        }
        setStatus(status, `Applied preset "${preset.label}"`, false);
        await loadLLMConfig();
      } catch (error) {
        setStatus(status, error.message || "Preset failed", true);
      }
    });
  });
}


export async function mount() {
  bindLogout();
  const statusEl = document.getElementById("admin-status");
  let pollTimer = null;

  try {
    await refreshConnectors();

    const autoToggle = document.getElementById("connectors-autorefresh");
    const startPolling = () => { if (!pollTimer) pollTimer = setInterval(refreshConnectors, 5000); };
    const stopPolling = () => { clearInterval(pollTimer); pollTimer = null; };
    autoToggle.addEventListener("change", () => (autoToggle.checked ? startPolling() : stopPolling()));
    if (autoToggle.checked) startPolling();

    const policy = await apiFetch("/admin/retention");
    document.getElementById("retention-raw").value = policy.raw_days;
    document.getElementById("retention-normalized").value = policy.normalized_days;
    document.getElementById("retention-archive").value = policy.archive_policy;

    await loadLLMConfig();
    await loadUsers(statusEl);
  } catch (error) {
    setStatus(statusEl, error.message || "Failed to load admin data", true);
  }

  document.getElementById("retention-save").addEventListener("click", async () => {
    const rstatus = document.getElementById("retention-status");
    try {
      await apiFetch("/admin/retention", {
        method: "PUT",
        body: JSON.stringify({
          raw_days: Number.parseInt(document.getElementById("retention-raw").value, 10),
          normalized_days: Number.parseInt(document.getElementById("retention-normalized").value, 10),
          archive_policy: document.getElementById("retention-archive").value,
        }),
      });
      setStatus(rstatus, "Retention policy saved", false);
    } catch (error) {
      setStatus(rstatus, error.message || "Failed to save retention", true);
    }
  });

  document.getElementById("user-create-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const cstatus = document.getElementById("user-create-status");
    try {
      await apiFetch("/admin/users", {
        method: "POST",
        body: JSON.stringify({
          username: document.getElementById("new-username").value.trim(),
          password: document.getElementById("new-password").value.trim(),
          role: document.getElementById("new-role").value,
        }),
      });
      document.getElementById("new-username").value = "";
      document.getElementById("new-password").value = "";
      setStatus(cstatus, "User created", false);
      await loadUsers(statusEl);
    } catch (error) {
      setStatus(cstatus, error.message || "Failed to create user", true);
    }
  });

  // Cleanup when navigating away: stop the auto-refresh poll.
  return () => { if (pollTimer) clearInterval(pollTimer); };
}
