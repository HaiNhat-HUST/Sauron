"""Normalized records that every connector emits — the contract between the
collectors and the storage layer (replaces the old STIX bundle output).

Two source shapes are supported:

* **Unstructured** (RSS / Reddit / Twitter): free-text documents → one
  :class:`ArticleRecord` each, carrying the IOCs / CVEs / tags extracted from
  the text.
* **Structured** (NVD / CISA / abuse.ch / OTX / MITRE): already-parsed feeds →
  standalone :class:`IOCRecord` / :class:`CVERecord` / :class:`TagRecord`
  (and OTX pulses, which are article-like, also use :class:`ArticleRecord`).

A connector returns a single :class:`CollectionResult`; the store knows how to
persist each kind into the ``articles`` / ``iocs`` / ``cves`` / ``tags`` tables.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime

# Allowed IOC types (matches the DB CHECK constraint).
IOC_TYPES = ("ip", "domain", "url", "email", "hash")
# Allowed tag types.
TAG_TYPES = ("malware", "attack_technique", "threat_actor", "campaign")


@dataclass
class IOCRecord:
    ioc_type: str                       # ip | domain | url | email | hash
    value: str
    context: str | None = None          # surrounding text / note
    tags: list[str] = field(default_factory=list)   # free tags e.g. ['emotet','c2']
    score: float = 0.0
    enrichment: dict | None = None      # ASN/country/... (filled by enrichment stage)
    first_seen: datetime | None = None
    last_seen: datetime | None = None


@dataclass
class CVERecord:
    cve_id: str
    description: str | None = None
    cvss_score: float | None = None
    published_date: datetime | None = None
    last_modified: datetime | None = None
    products: list[str] = field(default_factory=list)


@dataclass
class TagRecord:
    name: str                           # dedup key — bare T-code for techniques
    type: str                           # one of TAG_TYPES
    confidence: float = 0.5             # used when linked to an article
    label: str | None = None            # human-readable display name (optional)


@dataclass
class ArticleRecord:
    title: str
    url: str | None = None
    content: str | None = None
    published_date: datetime | None = None
    source_name: str | None = None      # human source ('The Hacker News', 'r/netsec')
    iocs: list[IOCRecord] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)      # CVE ids referenced
    tags: list[TagRecord] = field(default_factory=list)


@dataclass
class CollectionResult:
    """Everything a single connector cycle produced."""

    articles: list[ArticleRecord] = field(default_factory=list)
    iocs: list[IOCRecord] = field(default_factory=list)   # standalone (no article)
    cves: list[CVERecord] = field(default_factory=list)   # standalone structured CVEs
    tags: list[TagRecord] = field(default_factory=list)   # standalone taxonomy

    def is_empty(self) -> bool:
        return not (self.articles or self.iocs or self.cves or self.tags)

    def count(self) -> int:
        return len(self.articles) + len(self.iocs) + len(self.cves) + len(self.tags)

    def to_dict(self) -> dict:
        """JSON-serializable form (datetimes → ISO) for file output."""
        def _enc(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            if dataclasses.is_dataclass(obj):
                return {k: _enc(v) for k, v in dataclasses.asdict(obj).items()}
            if isinstance(obj, list):
                return [_enc(x) for x in obj]
            return obj

        return {
            "articles": [_enc(a) for a in self.articles],
            "iocs": [_enc(i) for i in self.iocs],
            "cves": [_enc(c) for c in self.cves],
            "tags": [_enc(t) for t in self.tags],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CollectionResult":
        """Rebuild from :meth:`to_dict` output (parses ISO datetimes)."""
        def dt(v):
            return datetime.fromisoformat(v) if isinstance(v, str) and v else None

        def ioc(d):
            return IOCRecord(
                ioc_type=d["ioc_type"], value=d["value"], context=d.get("context"),
                tags=d.get("tags") or [], score=d.get("score", 0.0),
                enrichment=d.get("enrichment"),
                first_seen=dt(d.get("first_seen")), last_seen=dt(d.get("last_seen")),
            )

        return cls(
            articles=[
                ArticleRecord(
                    title=a["title"], url=a.get("url"), content=a.get("content"),
                    published_date=dt(a.get("published_date")), source_name=a.get("source_name"),
                    iocs=[ioc(x) for x in a.get("iocs", [])],
                    cves=a.get("cves", []),
                    tags=[TagRecord(**t) for t in a.get("tags", [])],
                )
                for a in data.get("articles", [])
            ],
            iocs=[ioc(x) for x in data.get("iocs", [])],
            cves=[
                CVERecord(
                    cve_id=c["cve_id"], description=c.get("description"),
                    cvss_score=c.get("cvss_score"), published_date=dt(c.get("published_date")),
                    last_modified=dt(c.get("last_modified")), products=c.get("products") or [],
                )
                for c in data.get("cves", [])
            ],
            tags=[TagRecord(**t) for t in data.get("tags", [])],
        )
