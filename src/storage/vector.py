"""ChromaDB vector store — embeddings of article content for contextual search.

Stores the cleaned full content of each article so the chatbot / agentic layer
can do semantic retrieval. ``chromadb`` is imported lazily so the rest of the
storage layer works without it; if it is unavailable or disabled
(``VECTOR_ENABLED=false``) the store degrades to a no-op.

Client mode:
* ``CHROMA_HOST`` set → HTTP client (Chroma running as a service).
* otherwise → embedded ``PersistentClient`` at ``CHROMA_PATH`` (``./data/chroma``).

Embedding backend (``EMBEDDING_PROVIDER``): ``default`` (local ONNX all-MiniLM,
no API key) or ``openai`` (needs ``OPENAI_API_KEY``).
"""

from __future__ import annotations

import logging
from typing import Any

from .config import StorageConfig, storage_config

logger = logging.getLogger(__name__)


def _scalar_metadata(meta: dict) -> dict:
    """Chroma metadata values must be str/int/float/bool (no None/list)."""
    out: dict[str, Any] = {}
    for k, v in meta.items():
        if v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            out[k] = v
        elif isinstance(v, (list, tuple)):
            out[k] = ", ".join(str(x) for x in v)
        else:
            out[k] = str(v)
    return out


class VectorStore:
    def __init__(self, config: StorageConfig | None = None):
        self.config = config or storage_config
        self._collection = None
        self._disabled = not self.config.vector_enabled

    # -- lazy init ---------------------------------------------------------
    def _collection_or_none(self):
        if self._disabled:
            return None
        if self._collection is not None:
            return self._collection
        try:
            import chromadb

            cfg = self.config
            if cfg.chroma_host:
                client = chromadb.HttpClient(host=cfg.chroma_host, port=cfg.chroma_port)
            else:
                client = chromadb.PersistentClient(path=cfg.chroma_path)
            self._collection = client.get_or_create_collection(
                name=cfg.chroma_collection,
                embedding_function=self._embedding_function(),
                metadata={"hnsw:space": "cosine"},
            )
            logger.info("ChromaDB ready (collection=%s)", cfg.chroma_collection)
        except Exception as exc:  # noqa: BLE001 — never break ingestion on vector errors
            logger.warning("ChromaDB unavailable (%s); vector store disabled", exc)
            self._disabled = True
            return None
        return self._collection

    def _embedding_function(self):
        from chromadb.utils import embedding_functions

        if self.config.embedding_provider == "openai" and self.config.openai_api_key:
            return embedding_functions.OpenAIEmbeddingFunction(
                api_key=self.config.openai_api_key, model_name=self.config.embedding_model
            )
        return embedding_functions.DefaultEmbeddingFunction()

    @property
    def available(self) -> bool:
        return self._collection_or_none() is not None

    # -- write -------------------------------------------------------------
    def upsert(self, items: list[dict]) -> int:
        """Upsert article embeddings. items: {id, document, metadata}.

        Skips items without document text. Returns the count upserted.
        """
        collection = self._collection_or_none()
        if collection is None:
            return 0
        ids, docs, metas = [], [], []
        for it in items:
            doc = (it.get("document") or "").strip()
            if not doc:
                continue
            ids.append(str(it["id"]))
            docs.append(doc)
            metas.append(_scalar_metadata(it.get("metadata") or {}))
        if not ids:
            return 0
        try:
            collection.upsert(ids=ids, documents=docs, metadatas=metas)
        except Exception:  # noqa: BLE001
            logger.exception("ChromaDB upsert failed")
            return 0
        return len(ids)

    # -- read --------------------------------------------------------------
    def search(self, query: str, k: int = 6, where: dict | None = None) -> list[dict]:
        collection = self._collection_or_none()
        if collection is None or not (query or "").strip():
            return []
        try:
            res = collection.query(query_texts=[query], n_results=k, where=where)
        except Exception:  # noqa: BLE001
            logger.exception("ChromaDB query failed")
            return []
        out: list[dict] = []
        ids = (res.get("ids") or [[]])[0]
        docs = (res.get("documents") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        dists = (res.get("distances") or [[]])[0]
        for i, _id in enumerate(ids):
            out.append({
                "id": _id,
                "document": docs[i] if i < len(docs) else "",
                "metadata": metas[i] if i < len(metas) else {},
                "distance": dists[i] if i < len(dists) else None,
            })
        return out

    def count(self) -> int:
        collection = self._collection_or_none()
        return collection.count() if collection is not None else 0


# Process-wide singleton.
_vector_store: VectorStore | None = None


def get_vector_store(config: StorageConfig | None = None) -> VectorStore:
    global _vector_store
    if _vector_store is None:
        _vector_store = VectorStore(config)
    return _vector_store
