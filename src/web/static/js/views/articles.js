// Articles view — a news feed of collected OSINT with LLM summaries and
// metadata. Selecting an article opens a relationship graph in a right-hand
// panel (see graph-panel.js).

import { apiFetch } from "../api.js";
import { appLayout, bindLogout, dateShort, esc, setStatus } from "../ui.js";
import { openGraph } from "../graph-panel.js";

const PAGE_SIZE = 15;

const TAG_LABEL = {
  malware: "Malware",
  attack_technique: "ATT&CK",
  threat_actor: "Actor",
  campaign: "Campaign",
};

function content() {
  return `
    <div class="articles-shell" data-articles-shell>
      <section class="section reveal delay-2 articles-feed">
        <div class="section-head">
          <div class="section-title">Articles</div>
          <input class="input-inline articles-search" type="search" placeholder="Search title or summary…" data-search />
        </div>
        <p class="small-note" id="articles-status"></p>
        <div class="feed-list" data-feed></div>
        <div class="feed-more">
          <button class="button secondary button-sm is-hidden" type="button" data-load-more>Load more</button>
        </div>
      </section>

      <aside class="graph-panel is-hidden" data-graph-panel></aside>
    </div>`;
}

export function render() {
  return appLayout({
    nav: "articles",
    title: "Articles",
    subtitle: "Collected OSINT news feed",
    content: content(),
  });
}

function metaChips(a) {
  const chips = [];
  if (a.ioc_count) chips.push(`<span class="badge badge-run">${a.ioc_count} IOC</span>`);
  if (a.cve_count) chips.push(`<span class="badge badge-err">${a.cve_count} CVE</span>`);
  for (const t of (a.tags || []).slice(0, 4)) {
    // Techniques carry a T-code in `name` and the readable name in `label`.
    const text = t.label && t.label !== t.name ? `${t.name} ${t.label}` : t.name;
    chips.push(`<span class="badge">${esc(TAG_LABEL[t.type] || t.type)}: ${esc(text)}</span>`);
  }
  return chips.join(" ");
}

function articleCard(a) {
  const summary = a.summary
    ? esc(a.summary.slice(0, 280)) + (a.summary.length > 280 ? "…" : "")
    : `<span class="small-note">No summary yet — pending enrichment.</span>`;
  const source = esc(a.source_name || a.source_type || "Unknown source");
  const link = a.url
    ? `<a href="${esc(a.url)}" target="_blank" rel="noopener" class="link-button">Open source ↗</a>`
    : "";
  return `
    <article class="feed-item" data-article-id="${a.id}" tabindex="0" role="button">
      <div class="feed-item-head">
        <h3>${esc(a.title || "Untitled")}</h3>
        <span class="small-note">${dateShort(a.published_date)}</span>
      </div>
      <div class="feed-item-meta">
        <span class="badge badge-off">${source}</span>
        ${metaChips(a)}
      </div>
      <p class="feed-summary">${summary}</p>
      <div class="feed-item-foot">
        <button class="button button-sm" type="button" data-graph>Explore graph</button>
        ${link}
      </div>
    </article>`;
}

export async function mount() {
  bindLogout();
  const statusEl = document.getElementById("articles-status");
  const shell = document.querySelector("[data-articles-shell]");
  const feedEl = shell.querySelector("[data-feed]");
  const searchEl = shell.querySelector("[data-search]");
  const moreBtn = shell.querySelector("[data-load-more]");
  const panel = shell.querySelector("[data-graph-panel]");

  let offset = 0;
  let total = 0;
  let search = "";
  let loading = false;
  let graphCleanup = null;
  const byId = new Map();

  async function loadPage(reset) {
    if (loading) return;
    loading = true;
    if (reset) {
      offset = 0;
      feedEl.innerHTML = `<p class="small-note">Loading…</p>`;
    }
    try {
      const q = new URLSearchParams({ limit: PAGE_SIZE, offset });
      if (search) q.set("search", search);
      const data = await apiFetch(`/articles?${q.toString()}`);
      total = data.total || 0;
      if (reset) {
        feedEl.innerHTML = "";
        byId.clear();
      }
      if (!data.items.length && reset) {
        feedEl.innerHTML = `<p class="small-note">No articles found${search ? " for this search" : " yet"}.</p>`;
      } else {
        feedEl.insertAdjacentHTML("beforeend", data.items.map(articleCard).join(""));
        data.items.forEach((a) => byId.set(String(a.id), a));
      }
      offset += data.items.length;
      moreBtn.classList.toggle("is-hidden", offset >= total);
      setStatus(statusEl, `${total} article(s) collected`, false);
    } catch (error) {
      setStatus(statusEl, error.message || "Failed to load articles", true);
      if (reset) feedEl.innerHTML = "";
    } finally {
      loading = false;
    }
  }

  async function showGraph(article) {
    if (graphCleanup) { try { graphCleanup(); } catch { /* ignore */ } graphCleanup = null; }
    shell.classList.add("has-graph");
    panel.classList.remove("is-hidden");
    feedEl.querySelectorAll(".feed-item.is-active").forEach((el) => el.classList.remove("is-active"));
    feedEl.querySelector(`[data-article-id="${article.id}"]`)?.classList.add("is-active");
    graphCleanup = await openGraph(panel, article);
  }

  // Event delegation: a card (or its Explore button) opens the graph.
  feedEl.addEventListener("click", (event) => {
    const item = event.target.closest(".feed-item");
    if (!item) return;
    if (event.target.closest("a")) return; // let source links work normally
    const article = byId.get(item.dataset.articleId);
    if (article) showGraph(article);
  });
  feedEl.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" && event.key !== " ") return;
    const item = event.target.closest(".feed-item");
    if (!item) return;
    event.preventDefault();
    const article = byId.get(item.dataset.articleId);
    if (article) showGraph(article);
  });

  moreBtn.addEventListener("click", () => loadPage(false));

  let searchTimer = null;
  searchEl.addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      search = searchEl.value.trim();
      loadPage(true);
    }, 300);
  });

  // When the graph panel hides itself (its close button clears innerHTML),
  // drop the active highlight too.
  panel.addEventListener("click", (event) => {
    if (event.target.closest("[data-graph-close]")) {
      shell.classList.remove("has-graph");
      feedEl.querySelectorAll(".feed-item.is-active").forEach((el) => el.classList.remove("is-active"));
    }
  });

  await loadPage(true);

  return () => {
    clearTimeout(searchTimer);
    if (graphCleanup) { try { graphCleanup(); } catch { /* ignore */ } }
  };
}
