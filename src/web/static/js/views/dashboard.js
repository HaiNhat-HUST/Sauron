// Dashboard view — overview + collected TI (design preserved).

import { apiFetch } from "../api.js";
import {
  appLayout, bindLogout, dateShort, esc, metricList, num, setStatus, severityBadge, simpleList,
} from "../ui.js";

function content() {
  return `
    <section class="section reveal delay-2">
      <div class="section-head">
        <div class="section-title">Database health</div>
        <span class="badge" id="db-state">Loading…</span>
      </div>
      <p class="small-note" id="dashboard-status"></p>
      <div class="grid-4">
        <div class="card"><h4>Articles</h4><div class="value" data-stat-articles>0</div><div class="meta">OSINT posts / pulses</div></div>
        <div class="card"><h4>IOCs</h4><div class="value" data-stat-iocs>0</div><div class="meta">IP / domain / URL / email / hash</div></div>
        <div class="card"><h4>CVEs</h4><div class="value" data-stat-cves>0</div><div class="meta" data-stat-kev>0 known-exploited</div></div>
        <div class="card"><h4>Tags</h4><div class="value" data-stat-tags>0</div><div class="meta">malware / TTP / actors</div></div>
      </div>
      <div class="grid-4" style="margin-top: 16px">
        <div class="card"><h4>Connectors online</h4><div class="value" data-stat-connectors>0/0</div><div class="meta" data-stat-connectors-meta></div></div>
        <div class="card"><h4>Last ingest</h4><div class="value" id="last-ingest" style="font-size: 16px">—</div><div class="meta">most recent record stored</div></div>
      </div>
    </section>

    <section class="section reveal delay-3">
      <div class="section-head">
        <div class="section-title">Ingest activity</div>
        <div class="small-note">Articles + IOCs · last 14 days</div>
      </div>
      <div class="bar-chart" id="ingest-bars"></div>
    </section>

    <div class="grid-2">
      <section class="section reveal">
        <div class="section-head"><div class="section-title">IOCs by type</div></div>
        <div class="list" id="ioctype-list"></div>
      </section>
      <section class="section reveal">
        <div class="section-head"><div class="section-title">Top intel sources</div></div>
        <div class="list" id="source-list"></div>
      </section>
    </div>

    <div class="grid-2">
      <section class="section reveal">
        <div class="section-head"><div class="section-title">Top tags (malware / TTP / actors)</div></div>
        <div class="list" id="tags-list"></div>
      </section>
      <section class="section reveal">
        <div class="section-head"><div class="section-title">CVEs by severity</div></div>
        <div class="list" id="severity-list"></div>
      </section>
    </div>

    <div class="grid-2">
      <section class="section reveal">
        <div class="section-head"><div class="section-title">Recent IOCs</div></div>
        <div class="list" id="iocs-list"></div>
      </section>
      <section class="section reveal">
        <div class="section-head"><div class="section-title">Recent CVEs</div></div>
        <div class="list" id="cve-list"></div>
      </section>
    </div>`;
}

export function render() {
  return appLayout({
    nav: "dashboard",
    title: "Database overview",
    subtitle: "Unified visibility across connectors",
    content: content(),
  });
}

const setText = (sel, text) => {
  const el = document.querySelector(sel);
  if (el) el.textContent = text;
};
const setHTML = (id, html) => {
  const el = document.getElementById(id);
  if (el) el.innerHTML = html;
};

export async function mount() {
  bindLogout();
  const statusEl = document.getElementById("dashboard-status");
  try {
    const data = await apiFetch("/dashboard/overview");
    const s = data.summary || {};

    setText("[data-stat-articles]", num(s.articles));
    setText("[data-stat-iocs]", num(s.iocs));
    setText("[data-stat-cves]", num(s.cves));
    setText("[data-stat-kev]", `${num(s.known_exploited)} known-exploited`);
    setText("[data-stat-tags]", num(s.tags));
    setText("[data-stat-connectors]", `${s.connectors_online || 0}/${s.connectors_total || 0}`);
    setText("[data-stat-connectors-meta]", `${s.connectors_running || 0} running now`);
    setText("#last-ingest", dateShort(s.last_ingest));

    const dbBadge = document.getElementById("db-state");
    if (dbBadge) {
      dbBadge.textContent = data.db_available
        ? `TI store connected · ${num(s.embeddings)} embeddings`
        : "TI store offline";
      dbBadge.className = `badge ${data.db_available ? "badge-ok" : "badge-err"}`;
    }
    setStatus(statusEl, data.db_available ? "" :
      "TI store not reachable — showing connector config only. Start PostgreSQL and collect data.",
      !data.db_available);

    const tl = data.timeline || [];
    const maxObj = Math.max(...tl.map((d) => (d.articles || 0) + (d.iocs || 0)), 1);
    setHTML("ingest-bars", tl.length
      ? tl.map((d) => {
          const total = (d.articles || 0) + (d.iocs || 0);
          const h = Math.max(4, Math.round((total / maxObj) * 100));
          return `<div class="bar" style="height:${h}%" title="${esc(d.day)}: ${d.articles} articles, ${d.iocs} IOCs">${(d.day || "").slice(5)}</div>`;
        }).join("")
      : `<div class="small-note">No ingest activity in the last 14 days</div>`);

    setHTML("ioctype-list", metricList(data.by_ioc_type, "ioc_type", "count"));
    setHTML("source-list", simpleList(data.by_source,
      (i) => `<div class="list-item"><span>${esc(i.source)}</span><span class="badge">${num(i.count)}</span></div>`));
    setHTML("tags-list", simpleList(data.top_tags,
      (t) => `<div class="list-item"><span>${esc(t.name)} <span class="small-note">${esc(t.type)}</span></span><span class="badge">${num(t.count)}</span></div>`));
    setHTML("severity-list", simpleList(data.cve_severity,
      (i) => `<div class="list-item">${severityBadge(i.severity)}<strong>${num(i.count)}</strong></div>`));

    setHTML("iocs-list", simpleList(data.recent_iocs, (i) => {
      const tags = (i.tags || []).slice(0, 2).map((t) => `<span class="badge">${esc(t)}</span>`).join(" ");
      return `<div class="list-item"><span><span class="badge badge-run">${esc(i.ioc_type)}</span> ${esc((i.value || "").slice(0, 50))}</span><span>${tags}</span></div>`;
    }));

    setHTML("cve-list", simpleList(data.recent_cves,
      (v) => `<div class="list-item"><span>${esc(v.cve_id)}${v.cvss_score ? ` · ${v.cvss_score}` : ""}${v.known_exploited ? ' <span class="badge badge-err">KEV</span>' : ""}</span>${severityBadge(v.severity)}</div>`));
  } catch (error) {
    setStatus(statusEl, error.message || "Failed to load dashboard", true);
  }
}
