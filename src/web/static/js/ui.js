// Shared UI helpers + the app layout (sidebar + topbar) used by app views.

import { clearSession, getUser, isAdmin } from "./api.js";

export const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (ch) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch])
  );

export const num = (n) => Number(n || 0).toLocaleString();

export const dateShort = (iso) => {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
};

export const setStatus = (el, message, isError = false) => {
  if (!el) return;
  el.textContent = message;
  el.classList.toggle("is-error", isError);
};

export const severityBadge = (sev) => {
  const s = (sev || "unknown").toLowerCase();
  const cls = s === "critical" || s === "high" ? "badge-err" : s === "medium" ? "badge-warn" : "badge";
  return `<span class="badge ${cls}">${esc(sev || "unknown")}</span>`;
};

export const metricList = (items, labelKey, valueKey) => {
  if (!items || !items.length) return `<div class="small-note">No data yet</div>`;
  const max = Math.max(...items.map((i) => i[valueKey] || 0), 1);
  return items
    .map((i) => {
      const pct = Math.round(((i[valueKey] || 0) / max) * 100);
      return `
        <div class="list-item metric-row">
          <div class="metric-head"><span>${esc(i[labelKey])}</span><strong>${num(i[valueKey])}</strong></div>
          <div class="metric-track"><div class="metric-bar" style="width:${pct}%"></div></div>
        </div>`;
    })
    .join("");
};

export const simpleList = (items, render) =>
  items && items.length ? items.map(render).join("") : `<div class="small-note">No data yet</div>`;

// Wrap a view's inner content in the shared app shell (sidebar + topbar).
// `nav` is the active page key; `title`/`subtitle` fill the topbar.
export function appLayout({ nav, title, subtitle, content }) {
  const user = getUser() || {};
  const role = user.role === "admin" ? "Administrator" : "Analyst";
  const onAdmin = nav.startsWith("admin");
  const adminLinks = isAdmin()
    ? `
        <details class="nav-toggle" ${onAdmin ? "open" : ""}>
          <summary class="nav-link ${onAdmin ? "is-active" : ""}">
            <span>Admin console <span class="nav-pill">Admin</span></span>
            <span class="nav-caret">▾</span>
          </summary>
          <div class="nav-submenu">
            <a class="nav-link nav-sub ${nav === "admin-connectors" ? "is-active" : ""}" href="#/admin-connectors">Connectors</a>
            <a class="nav-link nav-sub ${nav === "admin-llm" ? "is-active" : ""}" href="#/admin-llm">LLM &amp; retention</a>
            <a class="nav-link nav-sub ${nav === "admin-users" ? "is-active" : ""}" href="#/admin-users">Users</a>
          </div>
        </details>`
    : "";
  return `
    <div class="app-shell">
      <aside class="sidebar reveal">
        <div class="brand"><span class="brand-mark">TL</span><span>Threat Lens</span></div>
        <nav class="nav-links">
          <a class="nav-link ${nav === "dashboard" ? "is-active" : ""}" href="#/dashboard">Overview</a>
          <a class="nav-link ${nav === "articles" ? "is-active" : ""}" href="#/articles">Articles</a>
          <a class="nav-link ${nav === "chat" ? "is-active" : ""}" href="#/chat">Intel chat</a>
          ${adminLinks}
        </nav>
        <div class="sidebar-footer">ai-threat-intel</div>
      </aside>
      <div class="app-body">
        <header class="topbar reveal delay-1">
          <div>
            <div class="section-title">${esc(title)}</div>
            <div class="small-note">${esc(subtitle)}</div>
          </div>
          <div class="user-meta">
            <span class="role-pill">${esc(role)}</span>
            <span class="user-name">${esc(user.username || "User")}</span>
            <button class="button secondary" type="button" id="logout-btn">Logout</button>
          </div>
        </header>
        <main class="content">${content}</main>
      </div>
    </div>`;
}

// Wire the logout button present in the app layout.
export function bindLogout() {
  const btn = document.getElementById("logout-btn");
  if (btn) {
    btn.addEventListener("click", () => {
      clearSession();
      location.hash = "#/login";
    });
  }
}
