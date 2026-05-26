// Login view (auth-shell layout — design preserved from the old index.html).

import { apiFetch, saveSession } from "../api.js";
import { setStatus } from "../ui.js";

export function render() {
  return `
    <div class="auth-shell">
      <section class="auth-hero reveal">
        <div class="brand"><span class="brand-mark">TL</span><span>Threat Lens</span></div>
        <h1>Automated threat intelligence command center.</h1>
        <p>
          Orchestrate collection, enrichment, and reporting from one place. Track
          connector health, analyze database trends, and query the intelligence
          knowledge base in real time.
        </p>
        <div class="hero-metrics">
          <div class="metric"><div class="metric-value">11</div><span class="metric-label">Connectors ready</span></div>
          <div class="metric"><div class="metric-value">RAG</div><span class="metric-label">Contextual search</span></div>
          <div class="metric"><div class="metric-value">PG</div><span class="metric-label">+ vector store</span></div>
        </div>
      </section>

      <section class="auth-panel reveal delay-1">
        <form class="panel" id="login-form">
          <h2>Sign in</h2>
          <p>Authenticate with the API. Role is assigned by the backend.</p>
          <div class="field">
            <label for="username">Username</label>
            <input id="username" name="username" type="text" placeholder="analyst" />
          </div>
          <div class="field">
            <label for="password">Password</label>
            <input id="password" name="password" type="password" placeholder="password" />
          </div>
          <button class="button" type="submit">Enter workspace</button>
          <p class="small-note" id="login-status" style="margin-top: 12px;">Use admin/admin123 or analyst/analyst123.</p>
        </form>
      </section>
    </div>`;
}

export function mount() {
  const form = document.getElementById("login-form");
  const statusEl = document.getElementById("login-status");
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    setStatus(statusEl, "Signing in...", false);
    const username = form.querySelector("#username").value.trim();
    const password = form.querySelector("#password").value.trim();
    try {
      const payload = await apiFetch("/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      saveSession(payload.token, payload.user);
      location.hash = payload.user.role === "admin" ? "#/admin" : "#/dashboard";
    } catch (error) {
      setStatus(statusEl, error.message || "Login failed", true);
    }
  });
}
