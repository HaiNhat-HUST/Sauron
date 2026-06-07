"""Article news-feed + relationship-graph routes (any authenticated user)."""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query

from ...storage.articles import ArticleQueries
from ..deps import get_current_user

router = APIRouter(prefix="/articles", tags=["articles"])

# Node ids are "<kind>:<raw_id>"; only these kinds are expandable.
_KINDS = {"article", "ioc", "cve", "tag"}


@router.get("")
async def feed(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    search: str | None = None,
    _: Dict[str, Any] = Depends(get_current_user),
) -> Any:
    return await ArticleQueries().feed(limit=limit, offset=offset, search=search)


@router.get("/{article_id}/graph")
async def graph(
    article_id: int,
    _: Dict[str, Any] = Depends(get_current_user),
) -> Any:
    return await ArticleQueries().seed_graph(article_id)


@router.get("/graph/expand")
async def expand(
    node: str = Query(..., description="Node id in the form '<kind>:<raw_id>'"),
    _: Dict[str, Any] = Depends(get_current_user),
) -> Any:
    kind, sep, raw_id = node.partition(":")
    if not sep or kind not in _KINDS or not raw_id:
        raise HTTPException(status_code=400, detail="Invalid node id")
    if kind in ("article", "ioc") and not raw_id.isdigit():
        raise HTTPException(status_code=400, detail="Invalid node id")
    return await ArticleQueries().expand(kind, raw_id)
