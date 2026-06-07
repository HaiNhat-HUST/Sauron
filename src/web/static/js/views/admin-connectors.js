// Admin · Connectors — connector control (config + run-now), with live polling.

import { apiFetch } from "../api.js";
import { appLayout, bindLogout, dateShort, setStatus } from "../ui.js";

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
    </section>`;
}

export function render() {
  return appLayout({
    nav: "admin-connectors",
    title: "Connectors",
    subtitle: "Schedule, enable, and trigger collection runs",
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
  } catch (error) {
    setStatus(statusEl, error.message || "Failed to load connectors", true);
  }

  // Cleanup when navigating away: stop the auto-refresh poll.
  return () => { if (pollTimer) clearInterval(pollTimer); };
}
