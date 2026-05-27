// Session management + authenticated fetch wrapper.

const TOKEN_KEY = "ti.token";
const USER_KEY = "ti.user";

export function saveSession(token, user) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function clearSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function getUser() {
  const raw = localStorage.getItem(USER_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export function isAuthed() {
  return Boolean(getToken());
}

export function isAdmin() {
  return getUser()?.role === "admin";
}

// Thrown so callers can detect auth failures and redirect to login.
export class UnauthorizedError extends Error {}

export async function apiFetch(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;

  const response = await fetch(path, { ...options, headers });

  if (response.status === 401) {
    clearSession();
    location.hash = "#/login";
    throw new UnauthorizedError("unauthorized");
  }
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.detail || "Request failed");
  }
  if (response.status === 204) return null;
  return response.json();
}
