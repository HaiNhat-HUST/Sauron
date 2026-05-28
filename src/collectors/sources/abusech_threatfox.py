"""ThreatFox connector (structured) — mixed IOCs as IOC records.

Requires an abuse.ch ``Auth-Key`` (``ABUSECH_AUTH_KEY``).
API: https://threatfox.abuse.ch/api/
"""

from __future__ import annotations

from ..base import BaseConnector
from ..config import ThreatFoxConfig
from ..records import CollectionResult, IOCRecord

# ThreatFox ioc_type -> our ioc_type
_TYPE_MAP = {
    "ip:port": "ip", "domain": "domain", "url": "url",
    "md5_hash": "hash", "sha1_hash": "hash", "sha256_hash": "hash",
}


class ThreatFoxConnector(BaseConnector):
    name = "threatfox"
    description = "abuse.ch ThreatFox — mixed IOC feed"
    required_settings = ("auth_key",)

    API = "https://threatfox-api.abuse.ch/api/v1/"
    config: ThreatFoxConfig

    async def collect(self) -> CollectionResult:
        data = await self.post_json(
            self.API, headers={"Auth-Key": self.config.auth_key},
            json={"query": "get_iocs", "days": self.config.days},
        )
        if not isinstance(data, dict) or data.get("query_status") != "ok":
            self.log.warning("unexpected ThreatFox response: %s", str(data)[:200])
            return CollectionResult()

        seen = set(self.state.get("seen_ids", []))
        result = CollectionResult()
        new: list[str] = []

        for ioc in data.get("data", []):
            ioc_id = ioc.get("id")
            value = ioc.get("ioc")
            mapped = _TYPE_MAP.get(ioc.get("ioc_type"))
            if not value or not mapped or ioc_id in seen:
                continue
            new.append(ioc_id)

            if mapped == "ip" and ":" in value:
                value = value.split(":", 1)[0]   # strip :port

            tags = [t for t in (ioc.get("tags") or []) if t]
            family = ioc.get("malware_printable")
            if family and family.lower() != "unknown":
                tags.append(family)
            context = f"threat_type={ioc.get('threat_type')} malware={family} ref=https://threatfox.abuse.ch/ioc/{ioc_id}/"
            score = (ioc.get("confidence_level") or 0) / 100.0

            result.iocs.append(
                IOCRecord(ioc_type=mapped, value=value, context=context, tags=tags, score=score)
            )

        self.state.set("seen_ids", (new + list(seen))[:10000])
        self.log.info("ThreatFox: %d new IOCs", len(new))
        return result
