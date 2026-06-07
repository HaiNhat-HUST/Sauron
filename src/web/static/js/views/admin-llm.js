// Admin · LLM & retention — provider config, per-function routing, and data retention.

import { apiFetch } from "../api.js";
import { appLayout, bindLogout, esc, setStatus } from "../ui.js";

function content() {
  return `
    <section class="section reveal delay-2">
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
    </section>`;
}

export function render() {
  return appLayout({
    nav: "admin-llm",
    title: "LLM & retention",
    subtitle: "AI providers, function routing, and data lifecycle",
    content: content(),
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
      // Switch the routed model to the newly selected provider's default,
      // so the function uses a model that provider actually serves.
      const provider = data.providers.find((p) => p.name === providerSelect.value);
      modelInput.value = provider?.default_model || "";
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
  const statusEl = document.getElementById("llm-status");

  try {
    const policy = await apiFetch("/admin/retention");
    document.getElementById("retention-raw").value = policy.raw_days;
    document.getElementById("retention-normalized").value = policy.normalized_days;
    document.getElementById("retention-archive").value = policy.archive_policy;

    await loadLLMConfig();
  } catch (error) {
    setStatus(statusEl, error.message || "Failed to load LLM/retention config", true);
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
}
