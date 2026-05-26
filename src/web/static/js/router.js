// Hash-based client-side router for the SPA.

import { isAdmin, isAuthed } from "./api.js";
import * as adminView from "./views/admin.js";
import * as chatView from "./views/chat.js";
import * as dashboardView from "./views/dashboard.js";
import * as loginView from "./views/login.js";

const routes = {
  login: { view: loginView, auth: false, body: "page-auth" },
  dashboard: { view: dashboardView, auth: true, body: "page-app" },
  chat: { view: chatView, auth: true, body: "page-app" },
  admin: { view: adminView, auth: true, adminOnly: true, body: "page-app" },
};

let _cleanup = null;

function currentKey() {
  return location.hash.replace(/^#\/?/, "").split("/")[0] || "";
}

export async function renderRoute() {
  if (_cleanup) {
    try { _cleanup(); } catch { /* ignore */ }
    _cleanup = null;
  }

  let key = currentKey();
  if (!key) key = isAuthed() ? "dashboard" : "login";
  const route = routes[key] || routes.dashboard;

  // Route guards.
  if (route.auth && !isAuthed()) return void (location.hash = "#/login");
  if (key === "login" && isAuthed()) return void (location.hash = "#/dashboard");
  if (route.adminOnly && !isAdmin()) return void (location.hash = "#/dashboard");

  document.body.className = route.body;
  document.getElementById("app").innerHTML = route.view.render();
  _cleanup = (await route.view.mount()) || null;
}

export function startRouter() {
  window.addEventListener("hashchange", renderRoute);
  renderRoute();
}
