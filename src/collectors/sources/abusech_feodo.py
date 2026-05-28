"""Feodo Tracker connector (structured) — botnet C2 IPs as IOCs.

API: https://feodotracker.abuse.ch/downloads/
"""

from __future__ import annotations

from ..base import BaseConnector
from ..config import FeodoConfig
from ..records import CollectionResult, IOCRecord


class FeodoConnector(BaseConnector):
    name = "feodo"
    description = "abuse.ch Feodo Tracker — botnet C2 IP blocklist"

    FEED = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    config: FeodoConfig

    async def collect(self) -> CollectionResult:
        headers = {"Auth-Key": self.config.auth_key} if self.config.auth_key else {}
        data = await self.get_json(self.FEED, headers=headers)
        if not isinstance(data, list):
            self.log.warning("unexpected Feodo response: %s", str(data)[:200])
            return CollectionResult()

        seen = set(self.state.get("seen", []))
        result = CollectionResult()
        new: list[str] = []

        for entry in data:
            ip = entry.get("ip_address")
            if not ip:
                continue
            key = f"{ip}:{entry.get('last_online', '')}"
            if key in seen:
                continue
            new.append(key)

            family = entry.get("malware")
            tags = ["c2"] + ([family] if family else [])
            context = (
                f"port={entry.get('port')} status={entry.get('status')} "
                f"malware={family} as={entry.get('as_number')} country={entry.get('country')}"
            )
            result.iocs.append(IOCRecord(ioc_type="ip", value=ip, context=context, tags=tags, score=0.8))

        self.state.set("seen", (new + list(seen))[:10000])
        self.log.info("Feodo: %d new C2 IPs", len(new))
        return result
