"""CISA KEV connector (structured) — Known Exploited Vulnerabilities as CVEs.

Each entry is a CVE flagged ``known_exploited`` (set by the store from the
``cisa_kev`` source_type). No API key required.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..base import BaseConnector
from ..config import CisaKevConfig
from ..records import CollectionResult, CVERecord

_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CisaKevConnector(BaseConnector):
    name = "cisa_kev"
    description = "CISA Known Exploited Vulnerabilities catalog"
    config: CisaKevConfig

    async def collect(self) -> CollectionResult:
        data = await self.get_json(_FEED)
        if not isinstance(data, dict):
            self.log.warning("unexpected CISA KEV response")
            return CollectionResult()

        catalog_version = data.get("catalogVersion")
        if catalog_version and catalog_version == self.state.get("catalog_version"):
            self.log.info("CISA KEV: catalog %s unchanged", catalog_version)
            return CollectionResult()

        result = CollectionResult()
        for v in data.get("vulnerabilities", []):
            cve_id = v.get("cveID")
            if not cve_id:
                continue
            description = (
                f"{v.get('vulnerabilityName', '')}. {v.get('shortDescription', '')} "
                f"Required action: {v.get('requiredAction')} (due {v.get('dueDate')})."
            ).strip()
            products = [p for p in (f"{v.get('vendorProject')}:{v.get('product')}",) if p and p != "None:None"]
            result.cves.append(
                CVERecord(
                    cve_id=cve_id,
                    description=description,
                    published_date=_parse(v.get("dateAdded")),
                    products=products,
                )
            )

        self.state.set("catalog_version", catalog_version)
        self.log.info("CISA KEV: %d exploited vulnerabilities (catalog %s)", len(result.cves), catalog_version)
        return result


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    except ValueError:
        return None
