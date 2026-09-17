"""Email address intelligence.

Deliberately *passive*: this module never opens an SMTP conversation with the
target's mail server and never attempts the RCPT-TO probe that "email verifier"
services use. Everything below is either a DNS lookup, a public profile API, or
arithmetic on the address itself.
"""

from __future__ import annotations

import hashlib
import re
import urllib.parse
from pathlib import Path

from ..core import dns as dnsmod
from ..core.models import Confidence, ScanResult, Severity, TargetType
from ..core.registry import Module, register

DISPOSABLE_LIST = Path(__file__).resolve().parent.parent / "data" / "disposable.txt"
DISPOSABLE_REMOTE = (
    "https://raw.githubusercontent.com/disposable-email-domains/"
    "disposable-email-domains/master/disposable_email_blocklist.conf"
)

ROLE_ACCOUNTS = {
    "admin", "administrator", "abuse", "billing", "contact", "hello", "help",
    "info", "mail", "marketing", "noreply", "no-reply", "office", "postmaster",
    "privacy", "root", "sales", "security", "support", "team", "webmaster",
    "careers", "jobs", "hr", "legal", "press", "donotreply",
}

FREEMAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "msn.com", "aol.com", "icloud.com", "me.com", "mac.com",
    "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net", "mail.com",
    "yandex.ru", "zoho.com", "tutanota.com", "fastmail.com", "hey.com",
}


@register
class EmailModule(Module):
    name = "email"
    title = "Email address analysis"
    description = "Structure, deliverability, disposability, and public profile links."
    accepts = frozenset({TargetType.EMAIL})

    def run(self, target: str, result: ScanResult) -> None:
        address = target.strip().lower()
        local, _, domain = address.partition("@")
        if not domain:
            result.error("not an email address")
            return

        result.add("local part", local, source="parse")
        result.add("domain", domain, source="parse")
        result.pivot(domain, TargetType.DOMAIN, "email domain")

        # Plus-addressing and gmail dot-folding both hide the real inbox.
        canonical = local.split("+")[0]
        if "+" in local:
            result.add("tagged address", f"base inbox is {canonical}@{domain}",
                       source="parse", severity=Severity.NOTABLE)
        if domain in ("gmail.com", "googlemail.com") and "." in canonical:
            result.add("gmail dot-folding", f"equivalent to {canonical.replace('.', '')}@gmail.com",
                       source="parse", severity=Severity.NOTABLE)

        if canonical in ROLE_ACCOUNTS:
            result.add("account type", "role account (shared mailbox, not a person)",
                       source="analysis", confidence=Confidence.LIKELY)
        else:
            result.add("account type",
                       "freemail / personal" if domain in FREEMAIL else "custom domain",
                       source="analysis", confidence=Confidence.LIKELY)
            if guess := _guess_name(canonical):
                result.add("possible real name", guess, source="heuristic",
                           confidence=Confidence.POSSIBLE)

        for handle in _handle_candidates(canonical):
            result.pivot(handle, TargetType.USERNAME, "derived from email local part")

        # deliverability -----------------------------------------------------
        mx = dnsmod.resolve(self.http, domain, "MX")
        if mx:
            result.add("mail exchangers", sorted({m.split()[-1].rstrip('.') for m in mx if m.split()}),
                       source="doh")
            result.add("deliverable", "domain accepts mail", source="doh")
        else:
            a = dnsmod.resolve(self.http, domain, "A")
            result.add(
                "deliverable",
                "no MX record - mail would fall back to the A record" if a
                else "no MX and no A record: address cannot receive mail",
                source="doh",
                severity=Severity.NOTABLE if a else Severity.HIGH,
            )

        if self._is_disposable(domain):
            result.add("disposable", "yes - throwaway mail provider", source="blocklist",
                       severity=Severity.HIGH)

        # public profiles ----------------------------------------------------
        self._gravatar(address, result)
        self._github(address, result)


    # ------------------------------------------------------------------ helpers

    def _is_disposable(self, domain: str) -> bool:
        domains = _load_disposable(self.http)
        return domain in domains

    def _gravatar(self, address: str, result: ScanResult) -> None:
        digest = hashlib.md5(address.strip().lower().encode()).hexdigest()
        # d=404 means "no avatar" instead of the default silhouette, which is
        # the only way to tell a real Gravatar from a generated one.
        avatar = f"https://www.gravatar.com/avatar/{digest}?d=404"
        head = self.http.get(avatar, method="HEAD")
        if head.ok:
            result.add("Gravatar avatar", f"https://www.gravatar.com/avatar/{digest}",
                       source="gravatar", url=f"https://www.gravatar.com/avatar/{digest}?s=400",
                       severity=Severity.NOTABLE)

        profile = self.http.get(f"https://www.gravatar.com/{digest}.json",
                                headers={"Accept": "application/json"})
        data = profile.json()
        entries = (data or {}).get("entry") if isinstance(data, dict) else None
        if not entries:
            return
        entry = entries[0]
        result.add("Gravatar profile", entry.get("profileUrl", ""), source="gravatar",
                   url=entry.get("profileUrl"), severity=Severity.HIGH)
        for field, label in (("preferredUsername", "username"), ("displayName", "display name"),
                             ("aboutMe", "bio"), ("currentLocation", "location")):
            if value := entry.get(field):
                result.add(f"Gravatar {label}", value, source="gravatar",
                           severity=Severity.NOTABLE)
                if field == "preferredUsername":
                    result.pivot(str(value), TargetType.USERNAME, "Gravatar username")
        for acc in entry.get("accounts", []) or []:
            result.add(f"linked: {acc.get('shortname', acc.get('domain', '?'))}",
                       acc.get("url", ""), source="gravatar", url=acc.get("url"),
                       severity=Severity.HIGH)
            if user := acc.get("username"):
                result.pivot(str(user), TargetType.USERNAME, "linked in Gravatar profile")

    def _github(self, address: str, result: ScanResult) -> None:
        headers = {"Accept": "application/vnd.github+json"}
        if token := self.config.key("github"):
            headers["Authorization"] = f"Bearer {token}"
        q = urllib.parse.quote(f"{address} in:email")
        data = self.http.get_json(
            f"https://api.github.com/search/users?q={q}", headers=headers
        )
        if not isinstance(data, dict):
            return
        if data.get("message") and not data.get("items"):
            result.error("GitHub user search rate-limited (set GITHUB_TOKEN to raise it)")
            return
        for item in (data.get("items") or [])[:5]:
            result.add("GitHub account", item.get("login", ""), source="github",
                       url=item.get("html_url"), severity=Severity.HIGH)
            result.pivot(str(item.get("login")), TargetType.USERNAME, "GitHub account for this email")


_DISPOSABLE_CACHE: set[str] | None = None


def _load_disposable(http) -> set[str]:  # type: ignore[no-untyped-def]
    global _DISPOSABLE_CACHE
    if _DISPOSABLE_CACHE is not None:
        return _DISPOSABLE_CACHE
    domains: set[str] = set()
    if DISPOSABLE_LIST.exists():
        domains |= {
            line.strip().lower()
            for line in DISPOSABLE_LIST.read_text("utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        }
    resp = http.get(DISPOSABLE_REMOTE)
    if resp.ok:
        domains |= {line.strip().lower() for line in resp.text.splitlines() if line.strip()}
    _DISPOSABLE_CACHE = domains
    return domains


def _guess_name(local: str) -> str | None:
    """Turn ``jane.doe`` / ``jdoe2`` / ``jane_doe`` into a readable guess."""
    cleaned = re.sub(r"\d+$", "", local)
    parts = [p for p in re.split(r"[._\-]+", cleaned) if p.isalpha() and len(p) > 1]
    if len(parts) >= 2:
        return " ".join(p.capitalize() for p in parts)
    return None


def _handle_candidates(local: str) -> list[str]:
    out = {local}
    out.add(re.sub(r"[._-]", "", local))
    out.add(re.sub(r"\d+$", "", local))
    return [h for h in sorted(out) if len(h) >= 3]
