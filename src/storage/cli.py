"""CLI for the storage layer.

    python -m src.storage.cli init-db
    python -m src.storage.cli ingest --dir data/output   # load CollectionResult json files
    python -m src.storage.cli stats
    python -m src.storage.cli search "qakbot"
    python -m src.storage.cli lookup 1.2.3.4
"""

from __future__ import annotations

import argparse
import json
import logging
import re
from pathlib import Path

from dotenv import load_dotenv

from ..collectors.records import CollectionResult
from ..utils.aiorun import run as aiorun
from .database import dispose, init_db
from .queries import DashboardQueries
from .retrieval import Retriever
from .store import Store

logger = logging.getLogger("storage.cli")
_SOURCE_RE = re.compile(r"^(?P<source>.+?)_\d{8}T\d")


def _source_from_filename(path: Path, override: str | None) -> str:
    if override:
        return override
    m = _SOURCE_RE.match(path.name)
    return m.group("source") if m else path.stem


async def _ingest(args) -> None:
    store = Store()
    files = sorted(Path(args.dir).glob("*.json"))
    if not files:
        logger.warning("no files found in %s", args.dir)
        return
    totals = {"articles": 0, "iocs": 0, "cves": 0, "tags": 0}
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            logger.error("skip invalid JSON: %s", f.name)
            continue
        result = CollectionResult.from_dict(data)
        stats = await store.ingest(result, source_type=_source_from_filename(f, args.source))
        for k in totals:
            totals[k] += stats.get(k, 0)
        if args.delete:
            f.unlink()
    print(f"ingested {len(files)} files: {totals}")


async def _stats(_args) -> None:
    q = DashboardQueries()
    print("== overview =="); print(json.dumps(await q.overview(), indent=2))
    print("== by source =="); print(json.dumps(await q.counts_by_source(), indent=2))
    print("== ioc types =="); print(json.dumps(await q.counts_by_ioc_type(), indent=2))
    print("== cve severity =="); print(json.dumps(await q.cve_by_severity(), indent=2))


async def _search(args) -> None:
    print(json.dumps(await Retriever().search(args.query, limit=args.limit), indent=2, ensure_ascii=False))


async def _lookup(args) -> None:
    r = await Retriever().lookup_ioc(args.value)
    print(json.dumps(r, indent=2, ensure_ascii=False) if r else "not found")


async def _dispatch(args) -> None:
    try:
        if args.command == "init-db":
            await init_db(); print("schema initialised")
        elif args.command == "ingest":
            await _ingest(args)
        elif args.command == "stats":
            await _stats(args)
        elif args.command == "search":
            await _search(args)
        elif args.command == "lookup":
            await _lookup(args)
    finally:
        await dispose()


def main() -> None:
    load_dotenv()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    p = argparse.ArgumentParser(description="ai-threat-intel storage CLI")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db", help="create tables")
    pi = sub.add_parser("ingest", help="load CollectionResult json files into the DB")
    pi.add_argument("--dir", default="data/output")
    pi.add_argument("--source", default=None)
    pi.add_argument("--delete", action="store_true")
    sub.add_parser("stats", help="print dashboard aggregations")
    ps = sub.add_parser("search", help="keyword search")
    ps.add_argument("query"); ps.add_argument("--limit", type=int, default=8)
    pl = sub.add_parser("lookup", help="IOC lookup by value")
    pl.add_argument("value")
    aiorun(_dispatch(p.parse_args()))


if __name__ == "__main__":
    main()
