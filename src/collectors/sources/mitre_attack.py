"""MITRE ATT&CK connector (structured taxonomy) — techniques/groups/software as tags.

Downloads the ATT&CK dataset (JSON) and maps objects to taxonomy tags:
attack-pattern → attack_technique, intrusion-set → threat_actor,
malware/tool → malware, campaign → campaign. Skipped when unchanged (hash).
No API key. Data: https://github.com/mitre-attack/attack-stix-data
"""

from __future__ import annotations

import hashlib
import json

from ..base import BaseConnector
from ..config import MitreAttackConfig
from ..records import CollectionResult, TagRecord

_BASE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"

_TYPE_MAP = {
    "attack-pattern": "attack_technique",
    "intrusion-set": "threat_actor",
    "malware": "malware",
    "tool": "malware",
    "campaign": "campaign",
}


class MitreAttackConnector(BaseConnector):
    name = "mitre_attack"
    description = "MITRE ATT&CK — techniques, groups and software taxonomy"
    config: MitreAttackConfig

    async def collect(self) -> CollectionResult:
        domain = self.config.domain
        raw = await self.get_text(f"{_BASE_URL}/{domain}/{domain}.json")

        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        if digest == self.state.get("bundle_sha256"):
            self.log.info("MITRE ATT&CK (%s): unchanged", domain)
            return CollectionResult()

        bundle = json.loads(raw)
        result = CollectionResult()
        seen: set[str] = set()
        for obj in bundle.get("objects", []):
            tag_type = _TYPE_MAP.get(obj.get("type"))
            if not tag_type or obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            name = obj.get("name")
            if not name:
                continue
            attack_id = _attack_id(obj)
            # Techniques are keyed on their bare ATT&CK code so every source
            # (this feed, OTX, the LLM enricher) maps to one tag row; the human
            # name is carried separately as the display label. Other object
            # types have no stable code, so the name stays the key.
            if tag_type == "attack_technique" and attack_id:
                key, label = attack_id, name
            else:
                key, label = name, None
            if key in seen:
                continue
            seen.add(key)
            result.tags.append(TagRecord(name=key, type=tag_type, label=label))

        self.state.set("bundle_sha256", digest)
        self.log.info("MITRE ATT&CK (%s): %d taxonomy tags", domain, len(result.tags))
        return result


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None
