"""NVD connector (structured) — newly modified CVEs as CVE records.

Pulls CVEs modified since the last run (lastModStartDate/EndDate window).
``NVD_API_KEY`` optional (raises rate limit).
API: https://nvd.nist.gov/developers/vulnerabilities
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..base import BaseConnector
from ..config import NVDConfig
from ..records import CollectionResult, CVERecord

_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PAGE = 2000


class NVDConnector(BaseConnector):
    name = "nvd"
    description = "NIST NVD — CVE vulnerability feed"
    config: NVDConfig

    async def collect(self) -> CollectionResult:
        end = datetime.now(timezone.utc)
        last = self.state.get("last_modified")
        start = _parse(last) if last else end - timedelta(hours=self.config.initial_lookback_hours)

        headers = {"apiKey": self.config.api_key} if self.config.api_key else {}
        result = CollectionResult()
        start_index, total = 0, None

        while total is None or start_index < total:
            params = {
                "lastModStartDate": _fmt(start),
                "lastModEndDate": _fmt(end),
                "resultsPerPage": _PAGE,
                "startIndex": start_index,
            }
            data = await self.get_json(_API, params=params, headers=headers)
            total = data.get("totalResults", 0)
            vulns = data.get("vulnerabilities", [])
            for item in vulns:
                rec = _to_cve(item.get("cve", {}))
                if rec is not None:
                    result.cves.append(rec)
            start_index += _PAGE
            if not vulns:
                break

        self.state.set("last_modified", _fmt(end))
        self.log.info("NVD: %d CVEs in window", len(result.cves))
        return result


def _to_cve(cve: dict) -> CVERecord | None:
    cve_id = cve.get("id")
    if not cve_id:
        return None
    description = next(
        (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
    )
    score = _cvss(cve.get("metrics", {}))
    products = _products(cve)
    return CVERecord(
        cve_id=cve_id,
        description=description,
        cvss_score=score,
        published_date=_parse(cve.get("published")),
        last_modified=_parse(cve.get("lastModified")),
        products=products,
    )


def _cvss(metrics: dict) -> float | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            return entries[0].get("cvssData", {}).get("baseScore")
    return None


def _products(cve: dict) -> list[str]:
    """Collect distinct vendor:product names from CPE configurations."""
    products: set[str] = set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                # cpe:2.3:a:vendor:product:version:...
                parts = (match.get("criteria") or "").split(":")
                if len(parts) >= 5 and parts[4] != "*":
                    products.add(f"{parts[3]}:{parts[4]}")
    return sorted(products)[:50]


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
