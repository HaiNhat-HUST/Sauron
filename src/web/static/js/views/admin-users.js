// Admin · Users — create accounts, set roles, reset passwords, enable/disable.

import { apiFetch } from "../api.js";
import { appLayout, bindLogout, setStatus } from "../ui.js";

function content() {
  return `
    <section class="section reveal delay-2">
      <div class="section-head"><div class="section-title">User management</div></div>
      <form class="form-row" id="user-create-form">
        <div class="field"><label for="new-username">Username</label><input id="new-username" type="text" placeholder="new.user" /></div>
        <div class="field"><label for="new-password">Password</label><input id="new-password" type="password" placeholder="min 6 chars" /></div>
        <div class="field"><label for="new-role">Role</label><select id="new-role"><option value="analyst">Analyst</option><option value="admin">Administrator</option></select></div>
        <div class="field"><label>&nbsp;</label><button class="button" type="submit">Create user</button></div>
      </form>
      <p class="small-note" id="user-create-status"></p>
      <p class="small-note" id="admin-status"></p>
      <table class="table">
        <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Created at</th><th>Actions</th></tr></thead>
        <tbody id="users-body"></tbody>
      </table>
    </section>`;
}

export function render() {
  return appLayout({
    nav: "admin-users",
    title: "Users",
    subtitle: "Accounts, roles, and access control",
    content: content(),
  });
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

export async function mount() {
  bindLogout();
  const statusEl = document.getElementById("admin-status");

  try {
    await loadUsers(statusEl);
  } catch (error) {
    setStatus(statusEl, error.message || "Failed to load users", true);
  }

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
}
