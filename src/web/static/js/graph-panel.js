// Relationship-graph panel for the Articles page — Neo4j-style, via vis-network.
//
// Renders an article and its linked entities (IOC / CVE / malware / ATT&CK /
// actor / campaign) as an interactive force-directed graph: round nodes with
// the label inside, coloured by type, and labelled relationship edges. The
// graph starts two levels deep around the chosen article; tapping any leaf node
// expands it one further hop. Already-present nodes/edges are merged (vis
// DataSet.update is idempotent), so re-tapping is a no-op and the layout stays
// stable.

import { apiFetch } from "./api.js";
import { loadVisNetwork } from "./graph-lib-loader.js";
import { esc } from "./ui.js";

// Palette keyed by node `type` (article + ioc + cve + the four tag types).
const TYPE_COLOR = {
  article: "#2a9d8f",
  ioc: "#6c7c59",
  cve: "#ff6b35",
  malware: "#b94a2f",
  attack_technique: "#234e8c",
  threat_actor: "#7a5a12",
  campaign: "#8a3f9a",
  tag: "#5d5a53",
};

const TYPE_LABEL = {
  article: "Article",
  ioc: "IOC",
  cve: "CVE",
  malware: "Malware",
  attack_technique: "ATT&CK",
  threat_actor: "Threat actor",
  campaign: "Campaign",
  tag: "Tag",
};

// IOC sub-types get their own shade + shape so an indicator graph (domain →
// ip → ...) is readable: you can tell a domain from the IP it resolves to.
const IOC_SUBTYPE_COLOR = {
  ip: "#6c7c59",       // olive (the base IOC colour)
  domain: "#4f7d6f",   // teal-green
  url: "#a07b3f",      // amber
  email: "#7a6cae",    // muted violet
  hash: "#9a5b5b",     // dusty red
};

const IOC_SUBTYPE_SHAPE = {
  ip: "dot",
  domain: "diamond",
  url: "triangle",
  email: "square",
  hash: "hexagon",
};

const IOC_SUBTYPE_LABEL = {
  ip: "IP",
  domain: "Domain",
  url: "URL",
  email: "Email",
  hash: "Hash",
};

function colorFor(type) {
  return TYPE_COLOR[type] || TYPE_COLOR.tag;
}

// Resolve a node's colour: IOC nodes vary by ioc_type, everything else by type.
function nodeColor(n) {
  if (n.type === "ioc") {
    const sub = (n.meta || {}).ioc_type;
    return IOC_SUBTYPE_COLOR[sub] || TYPE_COLOR.ioc;
  }
  return colorFor(n.type);
}

// A node's "group key" — the unit the legend filter toggles. IOC nodes group by
// sub-type (ip/domain/...) so "show only domains + IPs" is possible; tag nodes
// group by their tag type (malware/attack_technique/...) so ATT&CK can be hidden
// on its own; everything else groups by its type.
function groupKeyOf(node) {
  if (node.type === "ioc") return (node.meta || {}).ioc_type || "ioc";
  return node.type;
}

// The ordered set of filterable groups, used to render the legend/filter.
// Each entry: { key, label, color }.
const FILTER_GROUPS = [
  { key: "article", label: "Article", color: TYPE_COLOR.article },
  { key: "cve", label: "CVE", color: TYPE_COLOR.cve },
  { key: "malware", label: "Malware", color: TYPE_COLOR.malware },
  { key: "attack_technique", label: "ATT&CK", color: TYPE_COLOR.attack_technique },
  { key: "threat_actor", label: "Threat actor", color: TYPE_COLOR.threat_actor },
  { key: "campaign", label: "Campaign", color: TYPE_COLOR.campaign },
  { key: "ip", label: "IP", color: IOC_SUBTYPE_COLOR.ip },
  { key: "domain", label: "Domain", color: IOC_SUBTYPE_COLOR.domain },
  { key: "url", label: "URL", color: IOC_SUBTYPE_COLOR.url },
  { key: "email", label: "Email", color: IOC_SUBTYPE_COLOR.email },
  { key: "hash", label: "Hash", color: IOC_SUBTYPE_COLOR.hash },
];

// Wrap long labels so they sit inside the node bubble like Neo4j.
function wrapLabel(text, width = 18) {
  const words = String(text || "").split(/\s+/);
  const lines = [];
  let line = "";
  for (const w of words) {
    if ((line + " " + w).trim().length > width) {
      if (line) lines.push(line);
      line = w.length > width ? w.slice(0, width - 1) + "…" : w;
    } else {
      line = (line + " " + w).trim();
    }
  }
  if (line) lines.push(line);
  return lines.slice(0, 3).join("\n");
}

// Build a rich HTML tooltip element for a node. vis-network renders an
// HTMLElement passed as `title` as-is, so each node type can show the detail
// that matters: articles → summary, CVEs → severity/CVSS/KEV, IOCs → type, etc.
function nodeTitle(n) {
  const m = n.meta || {};
  const el = document.createElement("div");
  el.className = "graph-tip";

  const rows = [];
  // IOC nodes show their sub-type ("Domain", "IP", …) in the matching colour.
  const kindLabel = n.type === "ioc"
    ? (IOC_SUBTYPE_LABEL[m.ioc_type] || "IOC")
    : (TYPE_LABEL[n.type] || n.type);
  rows.push(`<div class="graph-tip-kind" style="color:${nodeColor(n)}">${esc(kindLabel)}</div>`);
  rows.push(`<div class="graph-tip-title">${esc(n.label || "")}</div>`);

  const meta = [];
  if (m.source) meta.push(`<span><b>Source</b> ${esc(m.source)}</span>`);
  if (m.published) meta.push(`<span><b>Published</b> ${esc(m.published.slice(0, 10))}</span>`);
  if (m.ioc_type) meta.push(`<span><b>Type</b> ${esc(m.ioc_type)}</span>`);
  // IOC enrichment (ioc_basic): pivots + internal cross-reference.
  if (m.rdns) meta.push(`<span><b>rDNS</b> ${esc(m.rdns)}</span>`);
  if (m.host) meta.push(`<span><b>Host</b> ${esc(m.host)}</span>`);
  if (Array.isArray(m.resolved_ips) && m.resolved_ips.length)
    meta.push(`<span><b>Resolves to</b> ${esc(m.resolved_ips.slice(0, 4).join(", "))}</span>`);
  if (Array.isArray(m.malware) && m.malware.length)
    meta.push(`<span><b>Malware</b> ${esc(m.malware.slice(0, 4).join(", "))}</span>`);
  // Hash intel (MalwareBazaar / VirusTotal).
  if (m.family) meta.push(`<span><b>Family</b> ${esc(m.family)}</span>`);
  if (m.file_type) meta.push(`<span><b>File type</b> ${esc(m.file_type)}</span>`);
  if (m.vt_detection) meta.push(`<span><b>VT</b> ${esc(m.vt_detection)} detections</span>`);
  if (m.article_refs) meta.push(`<span><b>Seen in</b> ${esc(String(m.article_refs))} article(s)</span>`);
  if (m.known_c2) meta.push(`<span class="graph-tip-kev">⚠ Known C2 infrastructure</span>`);
  if (m.severity) meta.push(`<span><b>Severity</b> ${esc(m.severity)}</span>`);
  if (m.cvss != null) meta.push(`<span><b>CVSS</b> ${esc(String(m.cvss))}</span>`);
  // EPSS: exploitation probability (next 30 days) + percentile rank.
  if (m.epss != null) {
    const pct = (m.epss * 100).toFixed(1);
    const rank = m.epss_percentile != null ? ` (top ${(100 - m.epss_percentile * 100).toFixed(1)}%)` : "";
    meta.push(`<span><b>EPSS</b> ${esc(pct)}%${esc(rank)}</span>`);
  }
  if (m.kev) meta.push(`<span class="graph-tip-kev">⚠ Known-exploited (KEV)</span>`);
  // ATT&CK techniques: show the code and, when known, the taxonomy name.
  if (n.type === "attack_technique") {
    if (m.code) meta.push(`<span><b>ATT&CK</b> ${esc(m.code)}</span>`);
    if (m.name) meta.push(`<span><b>Name</b> ${esc(m.name)}</span>`);
  } else if (m.tag_type) {
    meta.push(`<span><b>Category</b> ${esc(m.tag_type)}</span>`);
  }
  if (meta.length) rows.push(`<div class="graph-tip-meta">${meta.join("")}</div>`);

  if (n.type === "article") {
    rows.push(m.summary
      ? `<div class="graph-tip-summary">${esc(m.summary)}</div>`
      : `<div class="graph-tip-summary graph-tip-muted">No summary yet — pending enrichment.</div>`);
  }

  el.innerHTML = rows.join("");
  return el;
}

// Map an API node to a vis node. `centerId`/`expanded` drive emphasis + the
// dashed "expandable" ring on leaves not yet opened. `hiddenGroups` hides a
// node whose group the user has filtered out (the centre is never hidden).
function toVisNode(n, centerId, expanded, hiddenGroups) {
  const isCenter = n.id === centerId;
  const canExpand = !expanded.has(n.id);
  const bg = nodeColor(n);
  const gkey = groupKeyOf(n);
  // Shape: articles are pills; IOC nodes vary by sub-type; the rest are dots.
  let shape = "dot";
  if (n.type === "article") shape = "ellipse";
  else if (n.type === "ioc") shape = IOC_SUBTYPE_SHAPE[(n.meta || {}).ioc_type] || "dot";
  return {
    id: n.id,
    label: wrapLabel(n.label),
    title: nodeTitle(n),
    group: n.type,
    gkey,                                   // group key for the legend filter
    hidden: !isCenter && hiddenGroups.has(gkey),
    shape,
    value: isCenter ? 40 : 20,
    color: {
      background: bg,
      border: isCenter ? "#1d1c19" : (canExpand ? "rgba(29,28,25,0.45)" : bg),
      highlight: { background: bg, border: "#ff6b35" },
    },
    borderWidth: isCenter ? 4 : (canExpand ? 2 : 1),
    borderWidthSelected: 4,
    shapeProperties: { borderDashes: canExpand && !isCenter ? [4, 3] : false },
    font: { color: "#1d1c19", size: isCenter ? 15 : 13, face: "Space Grotesk, sans-serif" },
  };
}

function toVisEdge(e) {
  return {
    id: e.id,
    from: e.source,
    to: e.target,
    label: e.label,
    arrows: { to: { enabled: true, scaleFactor: 0.6 } },
    color: { color: "#c9c2b4", highlight: "#ff6b35" },
    font: { size: 10, color: "#5d5a53", strokeWidth: 3, strokeColor: "#f6f2e8", align: "middle" },
    smooth: { type: "dynamic" },
  };
}

// Render the legend as an interactive filter: each group is a toggle button.
// A "hidden" group is dimmed; clicking flips it. The leading "All" button
// resets every group back to visible.
function filterHTML() {
  const groups = FILTER_GROUPS.map((g) =>
    `<button type="button" class="graph-filter-item" data-group="${g.key}">
       <span class="graph-dot" style="background:${g.color}"></span>${esc(g.label)}
     </button>`
  ).join("");
  return `
    <button type="button" class="graph-filter-item graph-filter-all" data-group="__all__">All</button>
    ${groups}`;
}

const VIS_OPTIONS = {
  physics: {
    solver: "forceAtlas2Based",
    forceAtlas2Based: { gravitationalConstant: -55, centralGravity: 0.012, springLength: 110, springConstant: 0.08 },
    stabilization: { iterations: 180, fit: true },
  },
  interaction: { hover: true, tooltipDelay: 120, navigationButtons: true, keyboard: false, multiselect: false },
  nodes: { scaling: { min: 14, max: 46 } },
  edges: { selectionWidth: 1.5 },
};

// Public: build/replace the graph for an article inside `container`.
// Returns a cleanup function that destroys the vis Network instance.
export async function openGraph(container, article) {
  container.innerHTML = `
    <div class="graph-head">
      <div>
        <div class="section-title">${esc((article.title || "Article").slice(0, 80))}</div>
        <div class="small-note">${esc(article.source_name || article.source_type || "")}</div>
      </div>
      <div class="graph-head-actions">
        <button class="link-button is-hidden" type="button" data-graph-restore>↩ Restore</button>
        <button class="link-button" type="button" data-graph-close>Close ✕</button>
      </div>
    </div>
    <div class="graph-legend" data-graph-filter>${filterHTML()}</div>
    <div class="graph-canvas" data-graph-canvas></div>
    <p class="small-note graph-status" data-graph-status>Loading graph…</p>`;

  const canvas = container.querySelector("[data-graph-canvas]");
  const statusEl = container.querySelector("[data-graph-status]");
  const closeBtn = container.querySelector("[data-graph-close]");
  const restoreBtn = container.querySelector("[data-graph-restore]");
  const filterBar = container.querySelector("[data-graph-filter]");

  // Groups the user has filtered out of view (node ids stay in the graph, just
  // hidden — so unhiding is instant and expansion bookkeeping is unaffected).
  const hiddenGroups = new Set();

  let network = null;
  let destroyed = false;
  let nodes = null;
  let edges = null;
  const knownIds = new Set();
  const expanded = new Set();
  // Provenance for collapse: parent node id -> Set of child node ids it added.
  const childrenOf = new Map();
  // Undo stack for deletions: each entry restores one removed sub-graph.
  const deletedStack = [];
  let centerId = null;

  let onDocClick = null;
  const cleanup = () => {
    destroyed = true;
    if (onDocClick) { document.removeEventListener("click", onDocClick); onDocClick = null; }
    if (network) { network.destroy(); network = null; }
  };
  closeBtn.addEventListener("click", () => {
    cleanup();
    container.classList.add("is-hidden");
    container.innerHTML = "";
  });

  // Merge an API payload into the DataSets, skipping ids already present.
  // Returns the ids that were actually new, so callers can record provenance.
  function absorb(payload) {
    const newNodes = [];
    const newEdges = [];
    const newNodeIds = [];
    for (const n of payload.nodes || []) {
      if (knownIds.has(n.id)) continue;
      knownIds.add(n.id);
      newNodes.push(toVisNode(n, centerId, expanded, hiddenGroups));
      newNodeIds.push(n.id);
    }
    for (const e of payload.edges || []) {
      if (knownIds.has(e.id)) continue;
      knownIds.add(e.id);
      newEdges.push(toVisEdge(e));
    }
    if (newNodes.length) nodes.add(newNodes);
    if (newEdges.length) edges.add(newEdges);
    return newNodeIds;
  }

  // After expanding a node, refresh its ring (it is no longer "expandable").
  // Reuse the node's own background so IOC sub-type colours are preserved.
  function refreshNodeStyle(id) {
    const bg = nodes.get(id)?.color?.background || "#6c7c59";
    nodes.update({
      id,
      borderWidth: 1,
      shapeProperties: { borderDashes: false },
      color: { background: bg, border: bg,
               highlight: { background: bg, border: "#ff6b35" } },
    });
  }

  let vis;
  try {
    vis = await loadVisNetwork();
  } catch (error) {
    statusEl.textContent = error.message || "Failed to load graph library";
    statusEl.classList.add("is-error");
    return cleanup;
  }
  if (destroyed) return cleanup;

  let seed;
  try {
    seed = await apiFetch(`/articles/${article.id}/graph`);
  } catch (error) {
    statusEl.textContent = error.message || "Failed to load graph";
    statusEl.classList.add("is-error");
    return cleanup;
  }
  if (destroyed) return cleanup;

  if (!seed.nodes || !seed.nodes.length) {
    statusEl.textContent = "No linked entities to graph for this article yet.";
    return cleanup;
  }

  centerId = seed.center;
  expanded.add(centerId);          // the seed graph already expanded the centre
  nodes = new vis.DataSet();
  edges = new vis.DataSet();
  // The article's direct entities (depth 1) were expanded by the seed too.
  for (const n of seed.nodes) {
    if (n.depth === 1) expanded.add(n.id);
  }
  absorb(seed);

  network = new vis.Network(canvas, { nodes, edges }, VIS_OPTIONS);
  statusEl.textContent = "Right-click a node and choose Extend to expand it one more level.";

  // Keep a node's type around so we can restyle it after expansion.
  const typeById = new Map((seed.nodes || []).map((n) => [n.id, n.type]));

  // --- group visibility filter (the legend doubles as a toggle bar) -------
  // Apply current hiddenGroups to every node by flipping its `hidden` flag in
  // one batch update (the centre is always kept visible).
  function applyFilter() {
    const updates = nodes.map((node) => ({
      id: node.id,
      hidden: node.id !== centerId && hiddenGroups.has(node.gkey),
    }));
    if (updates.length) nodes.update(updates);
    syncFilterButtons();
  }

  // Reflect hidden/visible + presence state on the filter buttons.
  function syncFilterButtons() {
    const present = new Set(nodes.map((n) => n.gkey));
    filterBar.querySelectorAll(".graph-filter-item").forEach((btn) => {
      const key = btn.dataset.group;
      if (key === "__all__") {
        btn.classList.toggle("is-active", hiddenGroups.size === 0);
        return;
      }
      btn.classList.toggle("is-off", hiddenGroups.has(key));
      // Dim groups that aren't present in the current graph at all.
      btn.classList.toggle("is-absent", !present.has(key));
    });
  }

  filterBar.addEventListener("click", (event) => {
    const btn = event.target.closest(".graph-filter-item");
    if (!btn) return;
    const key = btn.dataset.group;
    if (key === "__all__") {
      hiddenGroups.clear();
    } else if (hiddenGroups.has(key)) {
      hiddenGroups.delete(key);
    } else {
      hiddenGroups.add(key);
    }
    applyFilter();
  });

  syncFilterButtons();

  // Grow the graph by one hop around `id`. Re-extending an already-expanded
  // node re-fetches its neighbourhood and re-adds any missing neighbours, which
  // is how re-extending (e.g. the centre) restores deleted child nodes.
  async function expandNode(id) {
    const wasExpanded = expanded.has(id);
    expanded.add(id);
    refreshNodeStyle(id);
    statusEl.classList.remove("is-error");
    statusEl.textContent = wasExpanded ? "Re-extending…" : "Expanding…";
    try {
      const payload = await apiFetch(`/articles/graph/expand?node=${encodeURIComponent(id)}`);
      if (destroyed) return;
      for (const n of payload.nodes || []) if (!typeById.has(n.id)) typeById.set(n.id, n.type);
      const addedIds = absorb(payload);
      // Record which nodes this expansion introduced so Collapse can undo it.
      if (addedIds.length) {
        const bucket = childrenOf.get(id) || new Set();
        addedIds.forEach((cid) => bucket.add(cid));
        childrenOf.set(id, bucket);
      }
      // Restored nodes drop off the undo stack — keep it from growing stale.
      pruneDeletedStack();
      updateRestoreButton();
      // New groups may have appeared (or filtered groups gained members).
      syncFilterButtons();
      statusEl.textContent = addedIds.length
        ? `${wasExpanded ? "Restored" : "Added"} ${addedIds.length} related node(s).`
        : (wasExpanded ? "Nothing to restore here." : "No new related nodes.");
    } catch (error) {
      if (!wasExpanded) expanded.delete(id);
      statusEl.textContent = error.message || "Failed to expand node";
      statusEl.classList.add("is-error");
    }
  }

  // Drop deletion snapshots whose nodes are all back in the graph (e.g. they
  // were brought back by re-extending a parent rather than via Restore).
  function pruneDeletedStack() {
    for (let i = deletedStack.length - 1; i >= 0; i--) {
      const snap = deletedStack[i];
      if (snap.nodes.every((n) => knownIds.has(n.id))) deletedStack.splice(i, 1);
    }
  }

  // Forget a node entirely: drop it (and any edges touching it) from the graph
  // and all bookkeeping, so it can be re-introduced later by re-extending its
  // parent. Edges are captured in delete snapshots before this runs.
  function forget(id) {
    const touching = edges.get({ filter: (e) => e.from === id || e.to === id });
    touching.forEach((e) => { edges.remove(e.id); knownIds.delete(e.id); });
    nodes.remove(id);
    knownIds.delete(id);
    expanded.delete(id);
    childrenOf.delete(id);
    for (const set of childrenOf.values()) set.delete(id);
  }

  // Collect a node plus everything reachable only through its expansions, so a
  // delete/collapse removes the whole sub-branch, not just one bubble.
  function descendants(id, acc = new Set()) {
    for (const child of childrenOf.get(id) || []) {
      if (acc.has(child) || child === centerId) continue;
      acc.add(child);
      descendants(child, acc);
    }
    return acc;
  }

  // Collapse: undo a node's own expansion (remove the children it added) but
  // keep the node itself, so it becomes extendable again.
  function collapseNode(id) {
    const kids = descendants(id);
    if (!kids.size) {
      statusEl.textContent = "Nothing to collapse on this node.";
      return;
    }
    kids.forEach(forget);
    expanded.delete(id);
    refreshExpandableStyle(id);
    statusEl.classList.remove("is-error");
    statusEl.textContent = `Collapsed ${kids.size} node(s).`;
    syncFilterButtons();
  }

  // Delete: remove the node and its sub-branch, capturing enough to restore it.
  function deleteNode(id) {
    if (id === centerId) return;  // never delete the article being explored
    const branch = descendants(id);
    const removeIds = [id, ...branch];
    const snapshot = {
      nodes: removeIds.map((rid) => nodes.get(rid)).filter(Boolean),
      edges: edges.get({ filter: (e) => removeIds.includes(e.from) || removeIds.includes(e.to) }),
      expanded: removeIds.filter((rid) => expanded.has(rid)),
      children: removeIds.map((rid) => [rid, [...(childrenOf.get(rid) || [])]]),
    };
    deletedStack.push(snapshot);
    removeIds.forEach(forget);
    statusEl.classList.remove("is-error");
    statusEl.textContent = `Deleted ${removeIds.length} node(s). Use Restore to undo.`;
    updateRestoreButton();
    syncFilterButtons();
  }

  // Restore the most recent deletion.
  function restoreLast() {
    const snap = deletedStack.pop();
    if (!snap) return;
    for (const node of snap.nodes) {
      if (!knownIds.has(node.id)) { knownIds.add(node.id); nodes.add(node); }
    }
    for (const edge of snap.edges) {
      if (!knownIds.has(edge.id)) { knownIds.add(edge.id); edges.add(edge); }
    }
    for (const id of snap.expanded) expanded.add(id);
    for (const [id, kids] of snap.children) {
      if (kids.length) childrenOf.set(id, new Set(kids));
    }
    statusEl.classList.remove("is-error");
    statusEl.textContent = `Restored ${snap.nodes.length} node(s).`;
    updateRestoreButton();
    // Restored nodes must obey the current filter, and groups may reappear.
    applyFilter();
  }

  function updateRestoreButton() {
    restoreBtn.classList.toggle("is-hidden", deletedStack.length === 0);
  }

  // Re-apply the dashed "expandable" ring when a node becomes collapsible again.
  // Keep the node's own background so IOC sub-type colours survive a collapse.
  function refreshExpandableStyle(id) {
    const bg = nodes.get(id)?.color?.background || colorFor(typeById.get(id) || "tag");
    nodes.update({
      id,
      borderWidth: id === centerId ? 4 : 2,
      shapeProperties: { borderDashes: id === centerId ? false : [4, 3] },
      color: {
        background: bg,
        border: id === centerId ? "#1d1c19" : "rgba(29,28,25,0.45)",
        highlight: { background: bg, border: "#ff6b35" },
      },
    });
  }

  restoreBtn.addEventListener("click", restoreLast);

  // --- right-click context menu ("Extend") -------------------------------
  const menu = document.createElement("div");
  menu.className = "graph-menu is-hidden";
  container.appendChild(menu);

  const hideMenu = () => menu.classList.add("is-hidden");

  // Dismiss the menu on any plain click / scroll / drag elsewhere.
  network.on("click", hideMenu);
  network.on("dragStart", hideMenu);
  network.on("zoom", hideMenu);
  onDocClick = hideMenu;
  document.addEventListener("click", onDocClick);

  // Render the context menu for `id`. `confirmingDelete` swaps the Delete row
  // for an inline "Confirm / Cancel" pair (no native confirm dialog).
  function renderMenu(id, confirmingDelete) {
    const isExpanded = expanded.has(id);
    const hasChildren = (childrenOf.get(id) || new Set()).size > 0;
    const isCenter = id === centerId;

    if (confirmingDelete) {
      menu.innerHTML = `
        <div class="graph-menu-confirm">Delete this node and its branch?</div>
        <button type="button" data-action="delete-confirm" class="graph-menu-danger">Yes, delete</button>
        <button type="button" data-action="delete-cancel">Cancel</button>`;
    } else {
      menu.innerHTML = `
        <button type="button" data-action="extend">
          ${isExpanded ? "↻ Re-extend" : "⤢ Extend"}
        </button>
        <button type="button" data-action="collapse" ${hasChildren ? "" : "disabled"}>
          ⤡ Collapse
        </button>
        <button type="button" data-action="delete" class="graph-menu-danger" ${isCenter ? "disabled" : ""}>
          🗑 Delete${isCenter ? " (root)" : ""}
        </button>`;
    }

    menu.querySelector('[data-action="extend"]')?.addEventListener("click", (e) => {
      e.stopPropagation(); hideMenu(); expandNode(id);
    });
    menu.querySelector('[data-action="collapse"]')?.addEventListener("click", (e) => {
      e.stopPropagation(); hideMenu(); collapseNode(id);
    });
    // Delete asks for confirmation by re-rendering the menu in-place.
    menu.querySelector('[data-action="delete"]')?.addEventListener("click", (e) => {
      e.stopPropagation();
      if (id === centerId) return;
      renderMenu(id, true);
    });
    menu.querySelector('[data-action="delete-confirm"]')?.addEventListener("click", (e) => {
      e.stopPropagation(); hideMenu(); deleteNode(id);
    });
    menu.querySelector('[data-action="delete-cancel"]')?.addEventListener("click", (e) => {
      e.stopPropagation(); renderMenu(id, false);
    });
  }

  network.on("oncontext", (params) => {
    params.event.preventDefault();        // suppress the browser context menu
    const id = network.getNodeAt(params.pointer.DOM);
    if (!id) { hideMenu(); return; }

    network.selectNodes([id]);
    renderMenu(id, false);
    // Position within the panel (DOM pointer is relative to the canvas).
    const rect = canvas.getBoundingClientRect();
    const host = container.getBoundingClientRect();
    menu.style.left = `${rect.left - host.left + params.pointer.DOM.x}px`;
    menu.style.top = `${rect.top - host.top + params.pointer.DOM.y}px`;
    menu.classList.remove("is-hidden");
  });

  return cleanup;
}
