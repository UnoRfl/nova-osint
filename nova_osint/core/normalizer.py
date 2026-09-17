"""One shape for results that arrive in a dozen different shapes.

Every module already writes into :class:`~nova_osint.core.models.Finding`, so
the *schema* is uniform by construction. What is not uniform is the content:
RDAP pads values with whitespace, crt.sh returns hostnames with a trailing dot,
two sources routinely report the same fact, and a source that found nothing
sometimes says so with an empty string instead of not reporting at all.

:class:`DataNormalizer` runs over each :class:`ScanResult` once the module is
done and fixes exactly that, under one hard rule:

    **It never invents information.** A value it cannot verify is dropped or
    left as-is; it is never upgraded, guessed at, or given a confidence the
    source did not earn.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from .models import Finding, ScanResult

#: Control characters make a mess of terminals, CSV and HTML alike.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE = re.compile(r"[ \t\r\n\f\v]+")

#: Long enough for a DMARC record or a long SPF chain, short enough that one
#: pathological value cannot make a report unreadable.
MAX_VALUE_CHARS = 4000

#: Schemes we will tidy up. Anything else is left exactly as the source gave it.
_WEB_SCHEMES = ("http", "https")
_DEFAULT_PORTS = {"http": "80", "https": "443"}


@dataclass
class NormalizationReport:
    """What the pass changed, so nothing disappears silently."""

    cleaned: int = 0
    dropped_empty: int = 0
    dropped_duplicate: int = 0
    urls_normalized: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.cleaned or self.dropped_empty or self.dropped_duplicate
                    or self.urls_normalized)

    def summary(self) -> str:
        bits = []
        if self.dropped_duplicate:
            bits.append(f"{self.dropped_duplicate} duplicate")
        if self.dropped_empty:
            bits.append(f"{self.dropped_empty} empty")
        return ", ".join(bits) + " finding(s) removed" if bits else "no changes"


def clean_text(value: str) -> str:
    """Strip control characters, collapse runs of whitespace, trim, truncate."""
    text = _CONTROL.sub("", value)
    text = _WHITESPACE.sub(" ", text).strip()
    if len(text) > MAX_VALUE_CHARS:
        text = text[:MAX_VALUE_CHARS] + f" ... (truncated, {len(value)} chars total)"
    return text


def normalize_url(url: str | None) -> str | None:
    """Canonicalise an http(s) URL; return anything else untouched.

    Lowercases the scheme and host, drops a redundant default port and a
    trailing dot on the host, and removes an empty query or fragment marker.
    The path, query and fragment are otherwise left alone - ``#Adobe`` on a
    Have I Been Pwned link is load-bearing, not decoration.
    """
    if not url:
        return None
    text = url.strip()
    if not text:
        return None
    parts = urllib.parse.urlsplit(text)
    if parts.scheme.lower() not in _WEB_SCHEMES:
        return text  # mailto:, tel:, or something we should not be rewriting

    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return text
    netloc = host
    if parts.port and str(parts.port) != _DEFAULT_PORTS.get(parts.scheme.lower()):
        netloc = f"{host}:{parts.port}"
    if parts.username:
        credentials = parts.username
        if parts.password:
            credentials += f":{parts.password}"
        netloc = f"{credentials}@{netloc}"

    return urllib.parse.urlunsplit(
        (parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment)
    )


def _normalize_value(value: Any) -> Any:
    """Clean a finding value without changing its type or its meaning."""
    if isinstance(value, str):
        return clean_text(value)
    if isinstance(value, (list, tuple, set)):
        seen: list[Any] = []
        for item in value:
            cleaned = _normalize_value(item)
            if _is_empty(cleaned):
                continue
            if cleaned not in seen:  # de-duplicate inside a list value
                seen.append(cleaned)
        return seen
    return value


def _is_empty(value: Any) -> bool:
    """True for values that carry no information.

    ``0`` and ``False`` are *not* empty: "0 open ports" and "DNSSEC: False"
    are both real answers.
    """
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) == 0
    return False


def _fingerprint(finding: Finding) -> tuple:
    """Identity of a finding for de-duplication purposes.

    Source is part of the key on purpose: the same subdomain reported by crt.sh
    and by CertSpotter is two pieces of corroborating evidence, not one fact
    said twice, and an investigator wants to see both.
    """
    value = finding.value
    if isinstance(value, list):
        value = tuple(str(v) for v in value)
    return (
        finding.label.casefold(),
        str(value).casefold(),
        finding.source.casefold(),
        (finding.url or "").casefold(),
    )


class DataNormalizer:
    """Tidies a :class:`ScanResult` in place and reports what it did."""

    def __init__(self, *, drop_empty: bool = True, drop_duplicates: bool = True) -> None:
        self.drop_empty = drop_empty
        self.drop_duplicates = drop_duplicates

    def normalize(self, result: ScanResult) -> NormalizationReport:
        report = NormalizationReport()
        kept: list[Finding] = []
        seen: set[tuple] = set()

        for finding in result.findings:
            original_label, original_url = finding.label, finding.url
            finding.label = clean_text(str(finding.label))
            finding.source = clean_text(str(finding.source))
            finding.value = _normalize_value(finding.value)
            finding.url = normalize_url(finding.url)

            if finding.url != original_url and original_url:
                report.urls_normalized += 1
            if finding.label != original_label:
                report.cleaned += 1

            if self.drop_empty and _is_empty(finding.value) and not finding.url:
                report.dropped_empty += 1
                continue

            key = _fingerprint(finding)
            if self.drop_duplicates and key in seen:
                report.dropped_duplicate += 1
                continue
            seen.add(key)
            kept.append(finding)

        result.findings = kept
        self._normalize_pivots(result)
        return report

    @staticmethod
    def _normalize_pivots(result: ScanResult) -> None:
        """Trim pivot targets and drop the ones that became empty or duplicate."""
        cleaned = []
        seen: set[tuple[str, str]] = set()
        for pivot in result.pivots:
            target = clean_text(str(pivot.target)).strip("., ").lower()
            if not target:
                continue
            key = (target, pivot.target_type.value)
            if key in seen:
                continue
            seen.add(key)
            pivot.target = target
            pivot.reason = clean_text(pivot.reason)
            cleaned.append(pivot)
        result.pivots = cleaned


#: The default instance, used by the engine. Modules never call this directly -
#: normalisation is something that happens *to* their output, so a new module
#: gets it for free.
DEFAULT = DataNormalizer()
