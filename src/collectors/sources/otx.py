"""AlienVault OTX connector (semi-structured) — pulses as articles.

Each subscribed pulse becomes an :class:`ArticleRecord` (title/description/url)
carrying its indicators as IOCs, CVE indicators as linked CVEs, and its
malware-families / attack-ids / adversary as tags.

Requires ``OTX_API_KEY``. API: https://otx.alienvault.com/api
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from ...extraction.cleaner import clean_text
from ..base import BaseConnector
from ..config import OTXConfig
from ..records import ArticleRecord, CollectionResult, IOCRecord, TagRecord

_API = "https://otx.alienvault.com/api/v1/pulses/subscribed"

# OTX attack ids arrive as "T1566", "T1566 Phishing", or "T1566.001 - Spearphishing".
_TECHNIQUE_CODE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


def _split_technique(display: str | None) -> tuple[str | None, str | None]:
    """Split an OTX attack id into (bare T-code, human label).

    The code is the dedup key; the remainder (if any) becomes the display
    label. Returns (None, None) when no T-code is present.
    """
    text = (display or "").strip()
    m = _TECHNIQUE_CODE_RE.search(text)
    if not m:
        return None, None
    code = m.group(0).upper()
    label = text.replace(m.group(0), "", 1).strip(" -:–—") or None
    return code, label

_IOC_MAP = {
    "IPv4": "ip", "IPv6": "ip", "domain": "domain", "hostname": "domain",
    "URL": "url", "URI": "url", "email": "email",
    "FileHash-MD5": "hash", "FileHash-SHA1": "hash", "FileHash-SHA256": "hash",
}


class OTXConnector(BaseConnector):
    name = "otx"
    description = "AlienVault OTX — subscribed pulses"
    required_settings = ("api_key",)
    config: OTXConfig

    async def collect(self) -> CollectionResult:
        since = self.state.get("modified_since") or _iso(datetime.now(timezone.utc) - timedelta(days=7))
        headers = {"X-OTX-API-KEY": self.config.api_key}

        result = CollectionResult()
        url: str | None = _API
        params: dict | None = {"modified_since": since, "limit": 50}

        while url:
            data = await self.get_json(url, params=params, headers=headers)
            params = None
            for pulse in data.get("results", []):
                result.articles.append(self._pulse_to_article(pulse))
            url = data.get("next")

        self.state.set("modified_since", _iso(datetime.now(timezone.utc)))
        self.log.info("OTX: %d pulses", len(result.articles))
        return result

    def _pulse_to_article(self, pulse: dict) -> ArticleRecord:
        iocs: list[IOCRecord] = []
        cves: list[str] = []
        for ind in pulse.get("indicators", []):
            value = ind.get("indicator")
            itype = ind.get("type")
            if not value:
                continue
            if itype == "CVE":
                cves.append(value)
            elif itype in _IOC_MAP:
                iocs.append(IOCRecord(ioc_type=_IOC_MAP[itype], value=value, score=0.6))

        tags: list[TagRecord] = []
        for fam in pulse.get("malware_families", []) or []:
            name = fam.get("display_name") if isinstance(fam, dict) else fam
            if name:
                tags.append(TagRecord(name=name, type="malware", confidence=0.7))
        for tech in pulse.get("attack_ids", []) or []:
            display = tech.get("display_name") if isinstance(tech, dict) else tech
            code, label = _split_technique(display)
            if code:
                tags.append(TagRecord(
                    name=code, type="attack_technique", confidence=0.7, label=label
                ))
        if pulse.get("adversary"):
            tags.append(TagRecord(name=pulse["adversary"], type="threat_actor", confidence=0.7))

        return ArticleRecord(
            title=pulse.get("name") or f"OTX pulse {pulse.get('id')}",
            url=f"https://otx.alienvault.com/pulse/{pulse.get('id')}",
            content=clean_text(pulse.get("description")),
            published_date=_parse(pulse.get("created")),
            source_name="AlienVault OTX",
            iocs=iocs,
            cves=cves,
            tags=tags,
        )


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def _parse(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
