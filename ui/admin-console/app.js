"use strict";

let adminToken = null;
let toastTimer = null;

const KNOWN_BADGES = new Set([
  "allow", "deny", "challenge", "alert",
  "active", "disabled", "enabled",
  "approved", "denied", "pending", "expired", "failed", "revoked",
  "pending_activation", "privileged", "compliant"
]);

const LOADERS = {
  dashboard: loadDashboard,
  identities: loadIdentities,
  policies: loadPolicies,
  challenges: loadChallenges,
  audit: loadAudit,
  adapters: loadAdapters,
  settings: loadSettings
};

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

function $(id) {
  return document.getElementById(id);
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (text !== undefined && text !== null) {
    node.textContent = String(text);
  }
  return node;
}

function clear(node) {
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

function fmtTime(iso) {
  if (!iso) {
    return "—";
  }
  const d = new Date(iso);
  if (isNaN(d.getTime())) {
    return String(iso);
  }
  return d.toISOString().replace("T", " ").slice(0, 19) + "Z";
}

function shortId(id) {
  return id ? String(id).slice(0, 8) : "—";
}

function statusBadge(value) {
  const v = value === undefined || value === null || value === "" ? "unknown" : String(value);
  const cls = KNOWN_BADGES.has(v) ? "badge-" + v : "badge-neutral";
  return el("span", "badge " + cls, v);
}

function boolBadge(value, yesLabel) {
  if (value) {
    return el("span", "badge badge-privileged", yesLabel);
  }
  return el("span", "dim", "—");
}

function enabledBadge(value) {
  return value
    ? el("span", "badge badge-enabled", "enabled")
    : el("span", "badge badge-disabled", "disabled");
}

function toast(message, isError) {
  const t = $("toast");
  clear(t);
  t.textContent = message;
  t.classList.toggle("toast-error", Boolean(isError));
  t.hidden = false;
  if (toastTimer) {
    clearTimeout(toastTimer);
  }
  toastTimer = setTimeout(() => {
    t.hidden = true;
  }, 4200);
}

function friendlyMessage(err) {
  if (err instanceof ApiError) {
    if (err.status === 401 || err.status === 403) {
      return "Authentication failed — the token is invalid or has been revoked.";
    }
    if (err.status === 404) {
      return "Endpoint not found — is the OIAF server up to date?";
    }
    if (err.status >= 500) {
      return "The OIAF server reported an internal error. Please try again.";
    }
    return err.message;
  }
  if (err instanceof TypeError) {
    return "Cannot reach the OIAF server. Check that it is running and reachable.";
  }
  return err && err.message ? err.message : "Something went wrong.";
}

async function apiFetch(path, options) {
  if (!adminToken) {
    throw new ApiError("Not connected.", 0);
  }
  const opts = options ? Object.assign({}, options) : {};
  const headers = Object.assign(
    { "Authorization": "Bearer " + adminToken },
    opts.headers || {}
  );
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  opts.headers = headers;

  let res;
  try {
    res = await fetch(path, opts);
  } catch (err) {
    throw err;
  }

  if (!res.ok) {
    let message = "Request failed (HTTP " + res.status + ")";
    try {
      const body = await res.json();
      if (body && body.error) {
        message = body.error;
      }
    } catch (_) {
      // response body was not JSON; keep generic message
    }
    throw new ApiError(message, res.status);
  }
  if (res.status === 204) {
    return null;
  }
  return res.json();
}

async function connect(event) {
  if (event) {
    event.preventDefault();
  }
  const input = $("token-input");
  const errEl = $("login-error");
  const btn = $("connect-btn");
  const token = input.value.trim();

  errEl.hidden = true;
  errEl.textContent = "";

  if (!token) {
    errEl.textContent = "Enter an admin token to connect.";
    errEl.hidden = false;
    return;
  }

  btn.disabled = true;
  btn.textContent = "Verifying…";
  adminToken = token;

  try {
    await apiFetch("/v1/identities");
    input.value = "";
    $("login").style.display = "none";
    $("app").style.display = "";
    switchTab("dashboard");
    toast("Connected to OIAF control plane.");
  } catch (err) {
    adminToken = null;
    errEl.textContent = friendlyMessage(err);
    errEl.hidden = false;
  } finally {
    btn.disabled = false;
    btn.textContent = "Connect";
  }
}

function disconnect() {
  adminToken = null;
  $("token-input").value = "";
  $("app").style.display = "none";
  $("login").style.display = "";
  toast("Token cleared from memory. Disconnected.");
}

function activeTab() {
  const current = document.querySelector(".tab.is-active");
  return current ? current.dataset.panel : "dashboard";
}

function switchTab(name) {
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.classList.toggle("is-active", tab.dataset.panel === name);
  });
  document.querySelectorAll(".panel").forEach((panel) => {
    panel.classList.toggle("is-active", panel.id === "panel-" + name);
  });
  const loader = LOADERS[name];
  if (loader) {
    loader();
  }
}

function refreshCurrent() {
  const loader = LOADERS[activeTab()];
  if (loader) {
    loader();
    toast("Reloaded " + activeTab() + ".");
  }
}

function setLoading(container) {
  clear(container);
  container.appendChild(el("div", "loading-state", "loading…"));
}

function renderError(container, err) {
  clear(container);
  const box = el("div", "empty-state");
  box.appendChild(el("strong", null, "Failed to load: "));
  box.appendChild(el("span", null, " " + friendlyMessage(err)));
  container.appendChild(box);
  toast(friendlyMessage(err), true);
}

function buildTable(columns, rows, emptyMsg) {
  const frag = document.createDocumentFragment();
  if (!rows || rows.length === 0) {
    frag.appendChild(el("div", "empty-state", emptyMsg || "No records found."));
    return frag;
  }
  const table = el("table");
  const thead = el("thead");
  const headRow = el("tr");
  columns.forEach((col) => {
    headRow.appendChild(el("th", null, col.label));
  });
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = el("tbody");
  rows.forEach((row) => {
    const tr = el("tr");
    columns.forEach((col) => {
      const td = el("td", col.className || "");
      const content = col.render ? col.render(row) : row[col.key];
      if (content instanceof Node) {
        td.appendChild(content);
      } else if (content === undefined || content === null || content === "") {
        td.textContent = "—";
      } else {
        td.textContent = String(content);
      }
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  frag.appendChild(table);
  return frag;
}

function renderInto(container, fragment) {
  clear(container);
  container.appendChild(fragment);
}

function actorLabel(actor) {
  if (!actor) {
    return "—";
  }
  return (actor.type || "?") + ":" + (actor.id || "?");
}

function targetLabel(target) {
  if (!target) {
    return "—";
  }
  return (target.type || "?") + ":" + shortId(target.id);
}

const auditColumns = [
  { label: "Timestamp", className: "mono dim", render: (e) => fmtTime(e.timestamp) },
  { label: "Type", className: "mono", render: (e) => e.type },
  { label: "Actor", className: "mono", render: (e) => actorLabel(e.actor) },
  { label: "Target", className: "mono dim", render: (e) => targetLabel(e.target) },
  { label: "Decision", render: (e) => (e.decision ? statusBadge(e.decision) : "—") },
  { label: "Risk", className: "mono", render: (e) => (e.risk_score ? String(e.risk_score) : "0") },
  { label: "Reasons", className: "mono dim", render: (e) => (e.reasons || []).join(", ") }
];

async function loadDashboard() {
  const statsEl = $("dashboard-stats");
  const recentEl = $("dashboard-recent");
  setLoading(statsEl);
  setLoading(recentEl);

  try {
    const results = await Promise.all([
      apiFetch("/v1/identities"),
      apiFetch("/v1/policies"),
      apiFetch("/v1/adapters"),
      apiFetch("/v1/audit/events?limit=200"),
      apiFetch("/v1/challenges").catch(() => null)
    ]);
    const identities = results[0] || [];
    const policies = results[1] || [];
    const adapters = results[2] || [];
    const events = results[3] || [];
    const challenges = results[4] || [];

    const privileged = identities.filter((i) => i.privileged).length;
    const enabledPolicies = policies.filter((p) => p.enabled).length;
    const enabledAdapters = adapters.filter((a) => a.enabled).length;
    const pendingChallenges = challenges.filter((c) => c.status === "pending").length;
    const denials = events.filter((e) => e.decision === "deny").length;

    const grid = document.createDocumentFragment();
    grid.appendChild(statCard("Identities", identities.length, "teal"));
    grid.appendChild(statCard("Privileged", privileged, "red"));
    grid.appendChild(statCard("Policies enabled", enabledPolicies + " / " + policies.length, "amber"));
    grid.appendChild(statCard("Adapters enabled", enabledAdapters + " / " + adapters.length, "blue"));
    grid.appendChild(statCard("Challenges pending", pendingChallenges, "amber"));
    grid.appendChild(statCard("Audit events", events.length, "teal"));
    grid.appendChild(statCard("Denials (recent)", denials, "red"));
    renderInto(statsEl, grid);

    renderInto(recentEl, buildTable(auditColumns, events.slice(0, 8), "No audit events yet."));
  } catch (err) {
    renderError(statsEl, err);
    clear(recentEl);
  }
}

function statCard(label, value, tone) {
  const card = el("div", "stat-card" + (tone && tone !== "teal" ? " stat-" + tone : ""));
  card.appendChild(el("span", "stat-label", label));
  card.appendChild(el("span", "stat-value", value));
  return card;
}

async function loadIdentities() {
  const container = $("identities-table");
  setLoading(container);
  try {
    const identities = await apiFetch("/v1/identities");
    const columns = [
      { label: "Username", className: "mono", render: (i) => i.username },
      { label: "Display name", render: (i) => i.display_name },
      { label: "Type", render: (i) => statusBadge(i.type) },
      { label: "Groups", className: "mono dim", render: (i) => (i.groups || []).join(", ") },
      { label: "Email", className: "mono dim", render: (i) => i.email },
      { label: "Privileged", render: (i) => boolBadge(i.privileged, "privileged") },
      { label: "Created", className: "mono dim", render: (i) => fmtTime(i.created_at) }
    ];
    renderInto(container, buildTable(columns, identities, "No identities registered."));
  } catch (err) {
    renderError(container, err);
  }
}

async function loadPolicies() {
  const container = $("policies-table");
  setLoading(container);
  try {
    const policies = await apiFetch("/v1/policies");
    policies.sort((a, b) => (a.priority || 0) - (b.priority || 0));
    const columns = [
      { label: "Priority", className: "mono", render: (p) => String(p.priority) },
      { label: "Effect", render: (p) => statusBadge(p.effect) },
      { label: "Enabled", render: (p) => enabledBadge(p.enabled) },
      { label: "Description", render: (p) => p.description },
      {
        label: "Conditions",
        className: "mono dim",
        render: (p) => {
          let raw = "";
          try {
            raw = p.conditions ? JSON.stringify(p.conditions) : "";
          } catch (_) {
            raw = String(p.conditions);
          }
          const node = el("span", null, raw.length > 64 ? raw.slice(0, 64) + "…" : raw || "—");
          if (raw) {
            node.title = raw;
          }
          return node;
        }
      },
      {
        label: "Challenge methods",
        className: "mono",
        render: (p) => (p.challenge && p.challenge.methods ? p.challenge.methods.join(", ") : "—")
      },
      { label: "Updated", className: "mono dim", render: (p) => fmtTime(p.updated_at) }
    ];
    renderInto(container, buildTable(columns, policies, "No policies defined."));
  } catch (err) {
    renderError(container, err);
  }
}

async function loadChallenges() {
  const container = $("challenges-table");
  setLoading(container);
  try {
    const challenges = await apiFetch("/v1/challenges");
    challenges.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    const columns = [
      { label: "ID", className: "mono dim", render: (c) => shortId(c.id) },
      { label: "Identity", className: "mono", render: (c) => c.identity_id },
      { label: "Methods", className: "mono", render: (c) => (c.methods || []).join(", ") },
      { label: "Status", render: (c) => statusBadge(c.status) },
      { label: "Attempts", className: "mono", render: (c) => c.attempts + " / " + c.max_attempts },
      { label: "Expires", className: "mono dim", render: (c) => fmtTime(c.expires_at) },
      { label: "Created", className: "mono dim", render: (c) => fmtTime(c.created_at) }
    ];
    renderInto(container, buildTable(columns, challenges, "No challenges issued."));
  } catch (err) {
    renderError(container, err);
  }
}

async function loadAudit() {
  const container = $("audit-table");
  setLoading(container);
  try {
    const events = await apiFetch("/v1/audit/events?limit=200");
    renderInto(container, buildTable(auditColumns, events, "No audit events recorded."));
  } catch (err) {
    renderError(container, err);
  }
}

async function verifyAuditChain() {
  const resultEl = $("audit-verify-result");
  resultEl.className = "verify-result";
  resultEl.textContent = "verifying…";
  try {
    const res = await apiFetch("/v1/audit/verify");
    if (res.valid) {
      resultEl.textContent = "hash chain valid — " + res.count + " events";
      resultEl.classList.add("ok");
    } else {
      resultEl.textContent = "HASH CHAIN INVALID — " + res.count + " events";
      resultEl.classList.add("bad");
      toast("Audit hash chain verification failed.", true);
    }
  } catch (err) {
    resultEl.textContent = "verification failed: " + friendlyMessage(err);
    resultEl.classList.add("bad");
  }
}

async function loadAdapters() {
  const container = $("adapters-table");
  setLoading(container);
  try {
    const adapters = await apiFetch("/v1/adapters");
    const columns = [
      { label: "Name", render: (a) => a.name },
      { label: "Type", className: "mono", render: (a) => a.type },
      { label: "Status", render: (a) => enabledBadge(a.enabled) },
      { label: "ID", className: "mono dim", render: (a) => shortId(a.id) },
      { label: "Created", className: "mono dim", render: (a) => fmtTime(a.created_at) }
    ];
    renderInto(container, buildTable(columns, adapters, "No adapters registered."));
  } catch (err) {
    renderError(container, err);
  }
}

async function loadSettings() {
  const container = $("server-info");
  setLoading(container);
  try {
    const version = await fetch("/version").then((r) => r.json()).catch(() => null);
    const health = await fetch("/healthz").then((r) => r.json()).catch(() => null);

    const list = el("dl", "kv-list");
    const rows = [
      ["Product", version && version.name ? version.name : "oiaf"],
      ["Version", version && version.version ? version.version : "unknown"],
      ["Health", health && health.status ? health.status : "unreachable"],
      ["API base", "/v1"],
      ["Token storage", "in-memory only (cleared on reload)"]
    ];
    rows.forEach((pair) => {
      list.appendChild(el("dt", null, pair[0]));
      list.appendChild(el("dd", null, pair[1]));
    });
    renderInto(container, list);
  } catch (err) {
    renderError(container, err);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  $("login-form").addEventListener("submit", connect);
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => switchTab(tab.dataset.panel));
  });
  $("refresh-btn").addEventListener("click", refreshCurrent);
  $("disconnect-btn").addEventListener("click", disconnect);
  $("settings-disconnect-btn").addEventListener("click", disconnect);
  $("audit-verify-btn").addEventListener("click", verifyAuditChain);
});
