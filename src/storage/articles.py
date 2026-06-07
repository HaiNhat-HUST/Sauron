"""Article news-feed + relationship-graph queries over the TI schema.

Powers the Articles page:
* :meth:`ArticleQueries.feed` — paginated news feed with summary + metadata
  (source, published date, and counts/labels of linked IOCs, CVEs and tags).
* :meth:`ArticleQueries.expand` — one-hop neighbourhood of any graph node, used
  both to seed the initial article graph and to grow it on demand. The graph
  alternates *article ↔ entity*: expanding an article reveals its IOCs / CVEs /
  tags; expanding an entity reveals the other articles that reference it.

Node id scheme (the prefix is the *kind*, used to route :meth:`expand`)::

    article:<id>   ioc:<id>   cve:<cve_id>   tag:<id>

The node ``type`` carries a finer *category* for client-side colouring:
``article``, ``ioc``, ``cve``, or the tag's own type (``malware`` /
``attack_technique`` / ``threat_actor`` / ``campaign``).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .database import get_sessionmaker
from .models import Article, ArticleCVE, ArticleIOC, ArticleTag, CVE, IOC, IOCRelation, Tag


# --- node builders -------------------------------------------------------
def _article_node(id_: int, title: str | None, source: str | None = None,
                  published: Any = None, summary: str | None = None) -> dict:
    return {
        "id": f"article:{id_}",
        "type": "article",
        "label": (title or "Untitled")[:90],
        "meta": {
            "source": source,
            "published": published.isoformat() if published else None,
            "summary": (summary or "")[:400] or None,
        },
    }


def _ioc_node(id_: int, ioc_type: str, value: str | None, enrichment: dict | None = None) -> dict:
    meta: dict = {"ioc_type": ioc_type}
    enr = enrichment or {}
    # Surface the most useful enrichment signals for the tooltip.
    if enr.get("rdns"):
        meta["rdns"] = enr["rdns"]
    pivot = enr.get("pivot") or {}
    if pivot.get("resolved_ips"):
        meta["resolved_ips"] = pivot["resolved_ips"]
    if pivot.get("host"):
        meta["host"] = pivot["host"]
    internal = enr.get("internal") or {}
    if internal.get("known_c2"):
        meta["known_c2"] = True
    if internal.get("malware"):
        meta["malware"] = internal["malware"]
    if internal.get("article_refs"):
        meta["article_refs"] = internal["article_refs"]
    # Hash intel from MalwareBazaar / VirusTotal.
    hash_intel = pivot.get("hash_intel") or {}
    mb = hash_intel.get("malwarebazaar") or {}
    vt = hash_intel.get("virustotal") or {}
    if mb.get("file_type"):
        meta["file_type"] = mb["file_type"]
    # Signature / family: prefer MalwareBazaar signature, fall back to VT label.
    family = mb.get("signature") or vt.get("threat_label")
    if family:
        meta["family"] = family
    if vt.get("ratio"):
        meta["vt_detection"] = vt["ratio"]
    return {
        "id": f"ioc:{id_}",
        "type": "ioc",
        "label": (value or "")[:60],
        "meta": meta,
    }


def _cve_node(cve_id: str, severity: str | None = None, cvss: float | None = None,
              kev: bool | None = None, enrichment: dict | None = None) -> dict:
    meta: dict = {"severity": severity, "cvss": cvss, "kev": bool(kev)}
    enr = enrichment or {}
    # EPSS: probability of exploitation in the next 30 days (0–1) + percentile.
    if enr.get("epss") is not None:
        meta["epss"] = enr["epss"]
    if enr.get("percentile") is not None:
        meta["epss_percentile"] = enr["percentile"]
    return {
        "id": f"cve:{cve_id}",
        "type": "cve",
        "label": cve_id,
        "meta": meta,
    }


def _tag_node(id_: int, name: str, tag_type: str, display: str | None = None) -> dict:
    # For techniques `name` is the bare T-code; `display` is the ATT&CK name.
    # The graph label shows "T1059 · Command and Scripting Interpreter" when the
    # name is known, falling back to the code alone.
    label = f"{name} · {display}" if display and display != name else name
    return {
        "id": f"tag:{id_}",
        "type": tag_type or "tag",   # malware | attack_technique | threat_actor | campaign
        "label": label,
        "meta": {"tag_type": tag_type, "code": name, "name": display},
    }


def _edge(source: str, target: str, label: str) -> dict:
    return {"id": f"{source}__{target}", "source": source, "target": target, "label": label}


class ArticleQueries:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession] | None = None):
        self._sessionmaker = sessionmaker or get_sessionmaker()

    # --- news feed -------------------------------------------------------
    async def feed(self, limit: int = 20, offset: int = 0, search: str | None = None) -> dict:
        search = (search or "").strip()
        async with self._sessionmaker() as s:
            where = []
            if search:
                like = f"%{search}%"
                where.append(or_(Article.title.ilike(like), Article.summary_llm.ilike(like)))

            total = await s.scalar(
                select(func.count()).select_from(Article).where(*where)
            )

            rows = (await s.execute(
                select(Article.id, Article.title, Article.url, Article.source_name,
                       Article.source_type, Article.published_date, Article.summary_llm,
                       Article.created_at)
                .where(*where)
                .order_by(desc(func.coalesce(Article.published_date, Article.created_at)))
                .limit(limit).offset(offset)
            )).all()

            ids = [r[0] for r in rows]
            tags_by_article: dict[int, list[dict]] = {i: [] for i in ids}
            ioc_counts: dict[int, int] = {}
            cve_counts: dict[int, int] = {}
            if ids:
                for aid, name, ttype, tlabel in (await s.execute(
                    select(ArticleTag.article_id, Tag.name, Tag.type, Tag.label)
                    .join(Tag, Tag.id == ArticleTag.tag_id)
                    .where(ArticleTag.article_id.in_(ids))
                    .order_by(desc(ArticleTag.confidence))
                )).all():
                    tags_by_article[aid].append({"name": name, "type": ttype, "label": tlabel})
                ioc_counts = dict((await s.execute(
                    select(ArticleIOC.article_id, func.count())
                    .where(ArticleIOC.article_id.in_(ids)).group_by(ArticleIOC.article_id)
                )).all())
                cve_counts = dict((await s.execute(
                    select(ArticleCVE.article_id, func.count())
                    .where(ArticleCVE.article_id.in_(ids)).group_by(ArticleCVE.article_id)
                )).all())

        items = [
            {
                "id": i, "title": t, "url": u, "source_name": sn, "source_type": st,
                "published_date": pd.isoformat() if pd else None,
                "summary": summary,
                "tags": tags_by_article.get(i, []),
                "ioc_count": ioc_counts.get(i, 0),
                "cve_count": cve_counts.get(i, 0),
            }
            for i, t, u, sn, st, pd, summary, _ca in rows
        ]
        return {"items": items, "total": total or 0, "limit": limit, "offset": offset}

    # --- initial 2-level graph ------------------------------------------
    async def seed_graph(self, article_id: int, limit: int = 30) -> dict:
        """Build the starting graph for an article: two levels deep.

        Level 0 is the article itself, level 1 its entities (IOC/CVE/tag), and
        level 2 the other articles those entities also appear in. Nodes carry a
        ``depth`` so the client knows the centre and which leaves are expandable.
        """
        merged_nodes: dict[str, dict] = {}
        merged_edges: dict[str, dict] = {}

        def absorb(payload: dict, depth_of: dict[str, int]) -> None:
            for n in payload["nodes"]:
                if n["id"] not in merged_nodes:
                    n = {**n, "depth": depth_of.get(n["id"], 99)}
                    merged_nodes[n["id"]] = n
            for e in payload["edges"]:
                merged_edges[e["id"]] = e

        center_id = f"article:{article_id}"
        level1 = await self._expand_article(article_id, limit)
        if not level1["nodes"]:
            return {"nodes": [], "edges": [], "center": center_id}
        depth1 = {n["id"]: (0 if n["id"] == center_id else 1) for n in level1["nodes"]}
        absorb(level1, depth1)

        # Level 2: expand each level-1 entity one hop back to articles.
        for node in [n for n in level1["nodes"] if n["id"] != center_id]:
            kind, raw_id = node["id"].split(":", 1)
            payload = await self.expand(kind, raw_id, limit)
            depth2 = {n["id"]: merged_nodes.get(n["id"], {}).get("depth", 2) for n in payload["nodes"]}
            for n in payload["nodes"]:
                if n["id"] not in merged_nodes:
                    depth2[n["id"]] = 2
            absorb(payload, depth2)

        return {
            "nodes": list(merged_nodes.values()),
            "edges": list(merged_edges.values()),
            "center": center_id,
        }

    # --- graph expansion -------------------------------------------------
    async def expand(self, kind: str, raw_id: str, limit: int = 30) -> dict:
        """Return the one-hop neighbourhood of a node as ``{nodes, edges}``.

        The centre node is always included so the client has its metadata even
        when it appears for the first time via an expansion.
        """
        if kind == "article":
            return await self._expand_article(int(raw_id), limit)
        if kind == "cve":
            return await self._expand_cve(raw_id, limit)
        if kind == "tag":
            return await self._expand_tag(int(raw_id), limit)
        if kind == "ioc":
            return await self._expand_ioc(int(raw_id), limit)
        return {"nodes": [], "edges": []}

    async def _expand_article(self, article_id: int, limit: int) -> dict:
        nodes: list[dict] = []
        edges: list[dict] = []
        async with self._sessionmaker() as s:
            art = (await s.execute(
                select(Article.id, Article.title, Article.source_name, Article.published_date,
                       Article.summary_llm)
                .where(Article.id == article_id)
            )).first()
            if not art:
                return {"nodes": [], "edges": []}
            center = _article_node(art[0], art[1], art[2], art[3], art[4])
            nodes.append(center)

            # IOCs linked to this article (via the article_iocs join table).
            for iid, itype, value, enr in (await s.execute(
                select(IOC.id, IOC.ioc_type, IOC.value, IOC.enrichment)
                .join(ArticleIOC, ArticleIOC.ioc_id == IOC.id)
                .where(ArticleIOC.article_id == article_id).limit(limit)
            )).all():
                node = _ioc_node(iid, itype, value, enr)
                nodes.append(node)
                edges.append(_edge(center["id"], node["id"], "indicator"))

            # CVEs referenced by this article.
            for cve_id, sev, cvss, kev, enr in (await s.execute(
                select(CVE.cve_id, CVE.severity, CVE.cvss_score, CVE.known_exploited, CVE.enrichment)
                .join(ArticleCVE, ArticleCVE.cve_id == CVE.cve_id)
                .where(ArticleCVE.article_id == article_id).limit(limit)
            )).all():
                node = _cve_node(cve_id, sev, cvss, kev, enr)
                nodes.append(node)
                edges.append(_edge(center["id"], node["id"], "references"))

            # Tags (malware / attack technique / actor / campaign).
            for tid, name, ttype, tlabel in (await s.execute(
                select(Tag.id, Tag.name, Tag.type, Tag.label)
                .join(ArticleTag, ArticleTag.tag_id == Tag.id)
                .where(ArticleTag.article_id == article_id)
                .order_by(desc(ArticleTag.confidence)).limit(limit)
            )).all():
                node = _tag_node(tid, name, ttype, tlabel)
                nodes.append(node)
                edges.append(_edge(center["id"], node["id"], "mentions"))
        return {"nodes": nodes, "edges": edges}

    async def _expand_cve(self, cve_id: str, limit: int) -> dict:
        nodes: list[dict] = []
        edges: list[dict] = []
        async with self._sessionmaker() as s:
            cve = (await s.execute(
                select(CVE.cve_id, CVE.severity, CVE.cvss_score, CVE.known_exploited, CVE.enrichment)
                .where(CVE.cve_id == cve_id)
            )).first()
            center = _cve_node(*cve) if cve else _cve_node(cve_id)
            nodes.append(center)
            for aid, title, src, pd, summary in (await s.execute(
                select(Article.id, Article.title, Article.source_name, Article.published_date,
                       Article.summary_llm)
                .join(ArticleCVE, ArticleCVE.article_id == Article.id)
                .where(ArticleCVE.cve_id == cve_id)
                .order_by(desc(func.coalesce(Article.published_date, Article.created_at)))
                .limit(limit)
            )).all():
                node = _article_node(aid, title, src, pd, summary)
                nodes.append(node)
                edges.append(_edge(node["id"], center["id"], "references"))
        return {"nodes": nodes, "edges": edges}

    async def _expand_tag(self, tag_id: int, limit: int) -> dict:
        nodes: list[dict] = []
        edges: list[dict] = []
        async with self._sessionmaker() as s:
            tag = (await s.execute(
                select(Tag.id, Tag.name, Tag.type, Tag.label).where(Tag.id == tag_id)
            )).first()
            if not tag:
                return {"nodes": [], "edges": []}
            center = _tag_node(*tag)
            nodes.append(center)
            for aid, title, src, pd, summary in (await s.execute(
                select(Article.id, Article.title, Article.source_name, Article.published_date,
                       Article.summary_llm)
                .join(ArticleTag, ArticleTag.article_id == Article.id)
                .where(ArticleTag.tag_id == tag_id)
                .order_by(desc(func.coalesce(Article.published_date, Article.created_at)))
                .limit(limit)
            )).all():
                node = _article_node(aid, title, src, pd, summary)
                nodes.append(node)
                edges.append(_edge(node["id"], center["id"], "mentions"))
        return {"nodes": nodes, "edges": edges}

    async def _expand_ioc(self, ioc_id: int, limit: int) -> dict:
        nodes: list[dict] = []
        edges: list[dict] = []
        async with self._sessionmaker() as s:
            ioc = (await s.execute(
                select(IOC.id, IOC.ioc_type, IOC.value, IOC.enrichment).where(IOC.id == ioc_id)
            )).first()
            if not ioc:
                return {"nodes": [], "edges": []}
            center = _ioc_node(ioc[0], ioc[1], ioc[2], ioc[3])
            nodes.append(center)
            # Every article that references this indicator — the pivot the
            # many-to-many model exists for.
            for aid, title, src, pd, summary in (await s.execute(
                select(Article.id, Article.title, Article.source_name, Article.published_date,
                       Article.summary_llm)
                .join(ArticleIOC, ArticleIOC.article_id == Article.id)
                .where(ArticleIOC.ioc_id == ioc_id)
                .order_by(desc(func.coalesce(Article.published_date, Article.created_at)))
                .limit(limit)
            )).all():
                node = _article_node(aid, title, src, pd, summary)
                nodes.append(node)
                edges.append(_edge(node["id"], center["id"], "indicator"))

            # Related IOCs that share infrastructure (enrichment edges). Look
            # both ways: outgoing (this domain → its IPs) and incoming (this IP
            # ← every domain that resolves to it — the shared-infra pivot).
            outgoing = (await s.execute(
                select(IOC.id, IOC.ioc_type, IOC.value, IOC.enrichment, IOCRelation.relation)
                .join(IOCRelation, IOCRelation.dst_ioc_id == IOC.id)
                .where(IOCRelation.src_ioc_id == ioc_id).limit(limit)
            )).all()
            for iid, itype, value, enr, relation in outgoing:
                node = _ioc_node(iid, itype, value, enr)
                nodes.append(node)
                edges.append(_edge(center["id"], node["id"], relation))

            incoming = (await s.execute(
                select(IOC.id, IOC.ioc_type, IOC.value, IOC.enrichment, IOCRelation.relation)
                .join(IOCRelation, IOCRelation.src_ioc_id == IOC.id)
                .where(IOCRelation.dst_ioc_id == ioc_id).limit(limit)
            )).all()
            for iid, itype, value, enr, relation in incoming:
                node = _ioc_node(iid, itype, value, enr)
                nodes.append(node)
                edges.append(_edge(node["id"], center["id"], relation))
        return {"nodes": nodes, "edges": edges}
