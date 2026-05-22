# Sauron

# ai-threat-intel

Automated, AI-augmented Threat Intelligence platform. Connectors pull from
external threat sources, normalize everything to **STIX 2.1**, and feed a
pipeline for extraction / enrichment / storage.

This repository currently ships:
- the **connector framework** (`src/collectors`) — an OpenCTI-inspired, async,
  in-process collection layer, and
- the **storage layer** (`src/storage`) — PostgreSQL + pgvector for dashboard
  aggregation, IOC lookup and agentic RAG retrieval.

---

## Connector framework

### Design (inspired by OpenCTI)

Like OpenCTI's `EXTERNAL_IMPORT` connectors, each connector is a scheduled job
that pulls from one source, builds a STIX bundle, and ships it. Adapted here to
run **async and in-process** so it plugs straight into the Python pipeline (no
RabbitMQ required to get started — swap in a broker later by adding one
`OutputHandler`).

```
                ┌──────────────────────────────────────────┐
                │              runner.py (CLI)               │
                │   schedules N connectors on async loops    │
                └───────────────┬────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
  ┌───────────┐          ┌───────────┐           ┌───────────┐
  │ Connector │  …        │ Connector │   …        │ Connector │   (BaseConnector)
  └─────┬─────┘          └─────┬─────┘           └─────┬─────┘
        │ collect() -> [STIX objects]                  │
        ▼                                              ▼
  StixFactory (author + TLP + deterministic IDs)   StateStore (cursors)
        │
        ▼
  build_bundle() ──► OutputHandler ──► data/output/*.json  (or asyncio.Queue → pipeline)
```

Key pieces (all under [src/collectors/](src/collectors/)):

| File | Responsibility |
|------|----------------|
| [base.py](src/collectors/base.py) | `BaseConnector`: scheduling loop, retry/backoff HTTP, state, author/TLP stamping, bundling |
| [stix_utils.py](src/collectors/stix_utils.py) | `StixFactory` + pattern builders; deterministic UUIDv5 IDs for dedup |
| [ioc_extractor.py](src/collectors/ioc_extractor.py) | regex IOC extraction (handles defanged `hxxp`, `1.2.3[.]4`) |
| [config.py](src/collectors/config.py) | per-connector `pydantic-settings` models (env-driven) |
| [state.py](src/collectors/state.py) | file-backed per-connector cursors |
| [output.py](src/collectors/output.py) | `OutputHandler`s: File / Queue / Logging / Composite |
| [registry.py](src/collectors/registry.py) | name → connector mapping |
| [runner.py](src/collectors/runner.py) | CLI entry point |

### Connectors (10 + 1)

| Connector | Source | TI targets | Auth |
|-----------|--------|-----------|------|
| `urlhaus` | abuse.ch URLhaus | malicious URLs, domains, IPs | abuse.ch key |
| `malwarebazaar` | abuse.ch MalwareBazaar | malware file hashes, families | abuse.ch key |
| `threatfox` | abuse.ch ThreatFox | mixed IOCs + malware | abuse.ch key |
| `feodo` | abuse.ch Feodo Tracker | botnet C2 IPs | none |
| `nvd` | NIST NVD | CVE vulnerabilities + CVSS | optional key |
| `mitre_attack` | MITRE ATT&CK | attack techniques / TTPs | none |
| `cisa_kev` | CISA KEV catalog | known-exploited CVEs | none |
| `otx` | AlienVault OTX | pulses → all IOC types | OTX key |
| `reddit` | Reddit (r/netsec…) | OSINT reports + extracted IOCs | optional OAuth |
| `rss` | security blogs | OSINT reports + extracted IOCs | none |
| `twitter` | X/Twitter v2 | OSINT reports + extracted IOCs | **paid** bearer (disabled by default) |

STIX output mapping:
- IOC feeds → `indicator` (STIX pattern) + the matching SCO (`ipv4-addr`,
  `domain-name`, `url`, `file`) joined by a `based-on` relationship, plus
  `malware` SDOs and `indicates` relationships where a family is known.
- CVE feeds → `vulnerability` SDOs (CVSS score/severity as labels).
- MITRE ATT&CK → native `attack-pattern` / `intrusion-set` / `malware` / `tool`
  objects and their relationships (the dataset is already STIX 2.1).
- Text sources (Reddit/RSS/X) → a `report` per document with regex-extracted
  IOCs as `object_refs`. The downstream LLM stage refines these.

### Setup

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env   # then fill in API keys
```

API keys (all optional — a connector missing its key logs a warning and idles):
- **abuse.ch** (`ABUSECH_AUTH_KEY`) — one key for URLhaus/MalwareBazaar/ThreatFox. Free at <https://auth.abuse.ch/>.
- **NVD** (`NVD_API_KEY`) — optional, raises rate limit. <https://nvd.nist.gov/developers/request-an-api-key>.
- **OTX** (`OTX_API_KEY`) — free at <https://otx.alienvault.com/api>.
- **Reddit** (`REDDIT_CLIENT_ID`/`SECRET`) — optional; without it falls back to rate-limited public JSON.
- **X/Twitter** (`TWITTER_BEARER_TOKEN`) — paid API; disabled by default.

### Run

```powershell
# list connectors
python -m src.collectors.runner --list

# one-shot run of everything enabled (writes bundles to data/output/)
python -m src.collectors.runner --once

# run specific connectors once
python -m src.collectors.runner --once --connector nvd --connector rss

# dry run (collect + log summary, no files written)
python -m src.collectors.runner --once --dry-run --connector nvd

# long-running scheduler (each connector loops on its own interval)
python -m src.collectors.runner
```

Each cycle writes a STIX bundle to `data/output/<connector>_<timestamp>.json`
and persists incremental cursors to `data/state/<connector>.json`.

### Adding a connector

1. Create `src/collectors/sources/<name>.py` subclassing `BaseConnector`,
   implement `collect()` returning a list of STIX objects (use `self.stix`,
   `self.state`, `self.get_json/post_json/get_text`).
2. Add a config class in [config.py](src/collectors/config.py).
3. Register the pair in [registry.py](src/collectors/registry.py).

### Notes / known limitations

- Some feeds sit behind CDN bot protection (e.g. CISA via Akamai,
  BleepingComputer via Cloudflare) and may return **HTTP 403** from data-center
  or geo-restricted IPs. The connector code is correct; run from a permitted
  network or via a proxy. Text connectors skip a failing feed and continue.
- `mitre_attack` downloads the full Enterprise bundle (~tens of MB) and only
  re-emits when the content hash changes, so the daily interval is cheap.

---

## Storage layer (PostgreSQL + pgvector)

The store ([src/storage/](src/storage/)) ingests connector bundles into one
PostgreSQL database designed to serve three jobs at once:

1. **Dashboard aggregation** — promoted, indexed columns for fast `GROUP BY`.
2. **Exact IOC lookup** — "is this IP/hash known, and what's it linked to?"
3. **Agentic RAG** — semantic + keyword retrieval to ground LLM Q&A / report
   generation in stored intelligence.

### Schema

| Table | Holds | Notes |
|-------|-------|-------|
| `stix_objects` | every SDO/SCO (node in the threat graph) | full object in `raw` (JSONB) + promoted columns (`type`, `value`, `labels`, `severity`, `cvss_score`, `tlp`, dates) + `sources[]` provenance + generated `tsvector` for full-text search |
| `stix_relationships` | SROs (edges) | indexed on both `source_ref` / `target_ref` for cheap graph pivoting |
| `embeddings` | one pgvector per text-bearing object | dimension fixed from `EMBEDDING_DIM`; HNSW cosine index |
| `ingestion_log` | one row per ingested bundle | powers the ingestion timeline |

Dedup is by STIX id (deterministic UUIDv5 from the connectors), so the same IOC
seen by multiple connectors is one row with merged `sources[]` and a bumped
`last_seen`.

### Embeddings (pluggable)

Selected by `EMBEDDING_PROVIDER`: `none` (default, disables semantic search) ·
`local` (sentence-transformers, needs `pip install sentence-transformers`) ·
`openai` · `voyage`. The embedder is resolved lazily, so nothing heavy is
imported unless you opt in. `EMBEDDING_DIM` **must** match the model.

### Run

```powershell
# 1. start PostgreSQL+pgvector (compose) — or your own instance
docker compose up -d db

# 2. create extension, tables, vector index
python -m src.storage.cli init-db

# 3a. let connectors write straight to the DB...
python -m src.collectors.runner --once --output db
# 3b. ...or ingest previously written bundle files
python -m src.storage.cli ingest --dir data/output

# explore
python -m src.storage.cli stats
python -m src.storage.cli search "qakbot c2 infrastructure"   # --mode hybrid|semantic|keyword
python -m src.storage.cli lookup 1.2.3.4
python -m src.storage.cli backfill-embeddings                 # after enabling a provider
```

`DATABASE_URL` (async, psycopg driver) configures the connection; see
`.env.example`. On Windows the CLIs force a `SelectorEventLoop` (psycopg async
requirement) via [src/utils/aiorun.py](src/utils/aiorun.py).

### Using the store from code (e.g. the agentic layer)

```python
from src.storage import Retriever, DashboardQueriesa

retr = Retriever()
context = await retr.context_for_query("recent Emotet C2 servers")  # hits + 1-hop graph
ioc = await retr.lookup_observable("203.0.113.10")                  # exact + neighbors
stats = await DashboardQueries().overview()
```

`Retriever` exposes `semantic_search`, `keyword_search`, `hybrid_search` (RRF
fusion), `lookup_observable`, `neighbors`, and `context_for_query` — the
building blocks for the Q&A / report-generation agent.
