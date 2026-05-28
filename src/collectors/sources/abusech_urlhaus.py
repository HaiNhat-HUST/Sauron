"""URLhaus connector (structured) — malicious URLs + payload hosts as IOCs.

Requires an abuse.ch ``Auth-Key`` (``ABUSECH_AUTH_KEY``).
API: https://urlhaus-api.abuse.ch/
"""

from __future__ import annotations

import ipaddress

from ..base import BaseConnector
from ..config import URLhausConfig
from ..records import CollectionResult, IOCRecord


class URLhausConnector(BaseConnector):
    name = "urlhaus"
    description = "abuse.ch URLhaus — malicious URL feed"
    required_settings = ("auth_key",)

    API = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    config: URLhausConfig

    async def collect(self) -> CollectionResult:
        data = await self.post_json(
            self.API, headers={"Auth-Key": self.config.auth_key}, data={"limit": "1000"}
        )
        if not isinstance(data, dict) or data.get("query_status") != "ok":
            self.log.warning("unexpected URLhaus response: %s", str(data)[:200])
            return CollectionResult()

        seen = set(self.state.get("seen_ids", []))
        result = CollectionResult()
        new_ids: list[str] = []

        for entry in data.get("urls", []):
            uid = entry.get("id")
            url = entry.get("url")
            if not url or uid in seen:
                continue
            new_ids.append(uid)

            tags = [t for t in (entry.get("tags") or []) if t]
            if entry.get("threat"):
                tags.append(entry["threat"])
            context = f"threat={entry.get('threat')} status={entry.get('url_status')} ref={entry.get('urlhaus_reference')}"

            result.iocs.append(IOCRecord(ioc_type="url", value=url, context=context, tags=tags, score=0.7))

            host = entry.get("host")
            if host:
                result.iocs.append(IOCRecord(ioc_type=_host_type(host), value=host, tags=tags))

        self.state.set("seen_ids", (new_ids + list(seen))[:5000])
        self.log.info("URLhaus: %d new URLs", len(new_ids))
        return result


def _host_type(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return "ip"
    except ValueError:
        return "domain"
