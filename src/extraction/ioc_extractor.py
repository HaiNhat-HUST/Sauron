"""Lightweight regex IOC extraction for text sources (Reddit / RSS / X).

This is intentionally *cheap and recall-oriented*: it pulls candidate
observables out of free text so the connector can emit them immediately.
The downstream LLM/enrichment stages (`src/extraction`, `src/enrichment`)
are responsible for high-precision parsing, false-positive pruning and
context — this just gives them a head start.

Handles common defanging ("hxxp", "1.2.3[.]4", "evil(.)com").
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Refang: undo the obfuscation analysts use to make IOCs non-clickable.
_REFANG = [
    # Markdown auto-escaping (common on Reddit) backslash-escapes punctuation,
    # e.g. `evil\[.\]com`. Strip those backslashes FIRST so defang rules match.
    (re.compile(r"\\([\[\]().\-_*`~])"), r"\1"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}", re.I), "."),
    (re.compile(r"\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[:\]", re.I), ":"),
    (re.compile(r"\[@\]|\(at\)|\[at\]", re.I), "@"),
    (re.compile(r"hxxps", re.I), "https"),
    (re.compile(r"hxxp", re.I), "http"),
]

# Trailing characters to trim off captured URLs/domains (punctuation that is
# almost always sentence/markup noise rather than part of the IOC).
_TRIM = "\\'\".,;:!?)]}>"

_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_URL = re.compile(r"\bhttps?://[^\s<>\"'\]\)]+", re.I)
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
# Domain: at least one label + a TLD of 2+ alpha chars.
_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")


# Common file extensions we do NOT want mistaken for domains.
_FILE_EXT = {
    "exe", "dll", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "zip",
    "rar", "7z", "gz", "tar", "iso", "img", "msi", "apk", "deb", "rpm",
    "js", "vbs", "ps1", "bat", "cmd", "scr", "jar", "class", "py", "sh",
    "rb", "pl", "go", "ts", "c", "cpp", "h", "java", "css",
    "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2", "ttf",
    "html", "htm", "php", "asp", "aspx", "jsp",
    "txt", "json", "xml", "yaml", "yml", "csv", "log", "md", "conf", "ini",
    "sql", "env", "pem", "key", "crt", "cer", "p12", "pfx",
    "bin", "dat", "tmp", "bak", "dmp",
}


@dataclass
class ExtractedIOCs:
    ipv4: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    md5: set[str] = field(default_factory=set)
    sha1: set[str] = field(default_factory=set)
    sha256: set[str] = field(default_factory=set)
    cves: set[str] = field(default_factory=set)
    emails: set[str] = field(default_factory=set)

    def is_empty(self) -> bool:
        return not any(
            (self.ipv4, self.domains, self.urls, self.md5, self.sha1,
             self.sha256, self.cves, self.emails)
        )

    def total(self) -> int:
        return sum(
            len(s) for s in (self.ipv4, self.domains, self.urls, self.md5,
                             self.sha1, self.sha256, self.cves, self.emails)
        )


def refang(text: str) -> str:
    for pattern, repl in _REFANG:
        text = pattern.sub(repl, text)
    return text


def _looks_like_filename(token: str) -> bool:
    return token.rsplit(".", 1)[-1].lower() in _FILE_EXT


def extract(text: str) -> ExtractedIOCs:
    """Extract candidate IOCs from a block of free text."""
    if not text:
        return ExtractedIOCs()
    text = refang(text)
    result = ExtractedIOCs()

    result.urls = {u for u in (_clean(x) for x in _URL.findall(text)) if _valid_url(u)}
    result.ipv4 = {ip for ip in _IPV4.findall(text) if not _is_private_or_trivial(ip)}
    result.cves = {c.upper() for c in _CVE.findall(text)}
    result.emails = set(_EMAIL.findall(text))

    # Hashes: match longest first so a SHA-256 isn't also flagged as MD5.
    result.sha256 = set(_SHA256.findall(text))
    result.sha1 = set(_SHA1.findall(text))
    result.md5 = set(_MD5.findall(text))

    # Domains: drop ones that are really filenames, the host of an extracted
    # URL (kept via the url SCO instead), or the local part of an email.
    url_hosts = {_host_of(u) for u in result.urls}
    email_domains = {e.split("@", 1)[-1].lower() for e in result.emails}
    for d in _DOMAIN.findall(text):
        dl = _clean(d).lower().strip(".")
        if not dl or "\\" in dl:
            continue
        if _looks_like_filename(dl) or dl in url_hosts or dl in email_domains:
            continue
        result.domains.add(dl)

    return result


def _clean(value: str) -> str:
    """Strip stray backslashes and trailing markup/sentence punctuation."""
    return value.replace("\\", "").rstrip(_TRIM)


def _valid_url(url: str) -> bool:
    # Must still look like a URL with a host after cleaning.
    return bool(re.match(r"https?://[^\s/]+\.", url, re.I))


def _host_of(url: str) -> str:
    m = re.match(r"https?://([^/:\s]+)", url, re.I)
    return m.group(1).lower() if m else ""


def _is_private_or_trivial(ip: str) -> bool:
    """Skip RFC1918 / loopback / version-string-looking IPs."""
    octets = ip.split(".")
    if octets[0] in {"0", "10", "127"}:
        return True
    if octets[0] == "192" and octets[1] == "168":
        return True
    if octets[0] == "172" and 16 <= int(octets[1]) <= 31:
        return True
    return False
