"""Chat route — grounded lookup over the TI store (vector + keyword search)."""

from __future__ import annotations

import asyncio
from typing import Any, Dict

from fastapi import APIRouter, Depends

from ...storage.retrieval import Retriever
from ...storage.vector import get_vector_store
from ..deps import get_current_user
from ..schemas import ChatRequest

router = APIRouter(tags=["chat"])


### will implement ai agent here
@router.post("/chat/ask")
async def ask(payload: ChatRequest, _: Dict[str, Any] = Depends(get_current_user)) -> Any:
    # message = payload.message.strip()
    # if not message:
    #     return {"answer": "Please enter a question.", "sources": []}

    # lines: list[str] = []
    # sources: list[str] = []

    # # Contextual (semantic) search over article content via the vector DB.
    # try:
    #     vec_hits = await asyncio.to_thread(get_vector_store().search, message, 5)
    # except Exception:  # noqa: BLE001
    #     vec_hits = []
    # for h in vec_hits:
    #     meta = h.get("metadata") or {}
    #     title = meta.get("title") or h.get("id")
    #     snippet = (h.get("document") or "").strip().replace("\n", " ")[:160]
    #     lines.append(f"• [article] {title}" + (f" — {snippet}" if snippet else ""))
    #     src = meta.get("source_name") or meta.get("source_type")
    #     if src and src not in sources:
    #         sources.append(src)

    # # Exact keyword hits for CVEs / IOCs from PostgreSQL.
    # try:
    #     kw_hits = await Retriever().search(message, limit=4)
    # except Exception:  # noqa: BLE001
    #     kw_hits = []
    # for h in kw_hits:
    #     if h.get("kind") == "article":
    #         continue
    #     lines.append(f"• [{h.get('kind')}] {h.get('label')}")
    #     if h.get("source") and h["source"] not in sources:
    #         sources.append(h["source"])

    # if not lines:
    #     return {
    #         "answer": f"No stored intelligence matched “{message}” yet. "
    #                   "Collect more data or rephrase the question.",
    #         "sources": [],
    #     }
    # header = f"Found {len(lines)} relevant item(s) for “{message}”:"
    # return {"answer": header + "\n" + "\n".join(lines), "sources": sources[:6]}
    return 0
