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
from ..core.addresses import ROLE_LOCALPARTS, judge_address
from ..core.entities import EntityType
from ..core.models import Confidence, ScanResult, Severity, TargetType
from ..core.registry import Module, register

DISPOSABLE_LIST = Path(__file__).resolve().parent.parent / "data" / "disposable.txt"
DISPOSABLE_REMOTE = (
    "https://raw.githubusercontent.com/disposable-email-domains/"
    "disposable-email-domains/master/disposable_email_blocklist.conf"
)

#: Kept as a name for anything importing it, but the list itself now lives in
#: :mod:`nova_osint.core.addresses` - the expansion gate has to make the same
#: call this module reports, and two lists drift.
ROLE_ACCOUNTS = ROLE_LOCALPARTS

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
        result.entity(EntityType.DOMAIN, domain, relation="mail-domain",
                      evidence="email-domain",
                      detail="domain half of the address")

        # Plus-addressing and gmail dot-folding both hide the real inbox.
        canonical = local.split("+")[0]
        if "+" in local:
            result.add("tagged address", f"base inbox is {canonical}@{domain}",
                       source="parse", severity=Severity.NOTABLE)
        if domain in ("gmail.com", "googlemail.com") and "." in canonical:
            result.add("gmail dot-folding", f"equivalent to {canonical.replace('.', '')}@gmail.com",
                       source="parse", severity=Severity.NOTABLE)

        # One source of truth with the expansion gate. This module used to keep
        # its own ROLE_ACCOUNTS list and report the fact *after* a pivot had
        # already spent seven modules on the address; the judge is consulted
        # before the pivot now, and reporting from the same verdict means the
        # two can never disagree about what a mailbox is.
        verdict = judge_address(f"{canonical}@{domain}")
        if verdict.kind == "automated":
            result.add("account type",
                       f"automated mailbox - {verdict.reason}",
                       source="analysis", confidence=Confidence.LIKELY,
                       extra={"note": "nobody reads this address; it is not a "
                                      "lead and was not followed"})
        elif verdict.kind == "role":
            result.add("account type", "role account (shared mailbox, not a person)",
                       source="analysis", confidence=Confidence.LIKELY,
                       extra={"note": verdict.reason})
        else:
            result.add("account type",
                       "freemail / personal" if domain in FREEMAIL else "custom domain",
                       source="analysis", confidence=Confidence.LIKELY)
            if guess := _guess_name(canonical):
                result.add("possible real name", guess, source="heuristic",
                           confidence=Confidence.POSSIBLE)

        # Only a person's local part is a guess at their handle. "sales" from
        # a shared mailbox is a word, not an identifier: pointing a 480-site
        # sweep at it returned 180-odd "accounts" belonging to strangers.
        handles = (_handle_candidates(canonical)
                   if verdict.kind == "personal" else [])
        for handle in handles:
            result.entity(EntityType.USERNAME, handle, relation="possible-handle",
                          evidence="handle-derived",
                          detail="generated from the local part, not observed")

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
        if verdict.kind != "automated":
            self._openpgp(address, result)
            self._commits(address, result)

    def _openpgp(self, address: str, result: ScanResult) -> None:
        """keys.openpgp.org only serves a key by address once its owner has
        clicked a confirmation link sent *to that address* - so a hit here is
        proof of control, unlike keyserver.ubuntu.com where anyone can upload
        a key naming anyone. The fingerprint joins the same key wherever else
        it is published (GitHub, a website), which is the point."""
        from ..core.pgp import parse_keys

        url = ("https://keys.openpgp.org/vks/v1/by-email/"
               + urllib.parse.quote(address))
        resp = self.http.get(url, timeout=15)
        if resp.status == 404:
            result.add("verified PGP key", "none on keys.openpgp.org",
                       source="keys.openpgp.org")
            return
        if not resp.ok:
            result.error(f"keys.openpgp.org answered {resp.status or resp.error}")
            return
        for key in parse_keys(resp.text)[:3]:
            result.add("verified PGP key", key.fingerprint, source="keys.openpgp.org",
                       url=f"https://keys.openpgp.org/search?q={key.fingerprint}",
                       severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                       extra={"basis": "the address owner confirmed this key by email"})
            result.entity(EntityType.KEY, f"gpg/{key.fingerprint}", relation="holds-key",
                          evidence="key-fingerprint-shared",
                          url=f"https://keys.openpgp.org/search?q={key.fingerprint}",
                          detail="key the address owner verified on keys.openpgp.org")

    def _commits(self, address: str, result: ScanResult) -> None:
        """Public commits *authored* with this address, and the account each
        one is attributed to. Stronger than the user search below it: an
        address need not be public on a profile to sign every commit."""
        headers = {"Accept": "application/vnd.github+json"}
        if token := self.config.key("github"):
            headers["Authorization"] = f"Bearer {token}"
        q = urllib.parse.quote(f"author-email:{address}")
        data = self.http.get_json(
            f"https://api.github.com/search/commits?q={q}&per_page=30",
            headers=headers)
        if not isinstance(data, dict) or "items" not in data:
            return
        logins: dict[str, int] = {}
        repos: set[str] = set()
        for item in data.get("items") or []:
            login = ((item.get("author") or {}).get("login") or "").strip()
            if login:
                logins[login] = logins.get(login, 0) + 1
            if repo := (item.get("repository") or {}).get("full_name"):
                repos.add(repo)
        total = int(data.get("total_count") or 0)
        if not total:
            return
        result.add("commits authored with this address", f"{total} public commit(s)",
                   source="github", severity=Severity.NOTABLE,
                   extra={"repositories": sorted(repos)[:15]})
        # One login across the sample is an attribution; several mean the
        # address is shared, or was set in someone else's git config.
        for login, n in sorted(logins.items(), key=lambda kv: -kv[1])[:3]:
            result.add("GitHub account (by commits)", login, source="github",
                       url=f"https://github.com/{login}", severity=Severity.HIGH,
                       confidence=(Confidence.CONFIRMED if len(logins) == 1
                                   else Confidence.LIKELY),
                       extra={"commits_in_sample": n,
                              "other_accounts": len(logins) - 1})
            result.entity(EntityType.USERNAME, login, relation="same-as",
                          evidence="commit-email", url=f"https://github.com/{login}",
                          detail=f"{n} public commit(s) authored with this address")


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

        # The current API (v3) keys profiles by SHA-256 and returns verified
        # accounts. The legacy MD5 .json endpoint is the fallback - it still
        # answers for some profiles and is what older ones were indexed by.
        sha = hashlib.sha256(address.strip().lower().encode()).hexdigest()
        v3 = self.http.get(f"https://api.gravatar.com/v3/profiles/{sha}",
                           headers={"Accept": "application/json"})
        prof = v3.json() if v3.ok else None
        if isinstance(prof, dict) and prof.get("hash"):
            self._gravatar_v3(prof, result)
            return

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
                    result.entity(EntityType.USERNAME, str(value), relation="same-as",
                                  evidence="gravatar-hash",
                                  detail="preferred username on the Gravatar profile")
        for acc in entry.get("accounts", []) or []:
            result.add(f"linked: {acc.get('shortname', acc.get('domain', '?'))}",
                       acc.get("url", ""), source="gravatar", url=acc.get("url"),
                       severity=Severity.HIGH)
            if user := acc.get("username"):
                result.entity(EntityType.USERNAME, str(user), relation="linked-account",
                              evidence="gravatar-hash",
                              detail="account linked from the Gravatar profile")

    def _gravatar_v3(self, prof: dict, result: ScanResult) -> None:
        url = prof.get("profile_url") or ""
        result.add("Gravatar profile", url, source="gravatar", url=url or None,
                   severity=Severity.HIGH, confidence=Confidence.CONFIRMED)
        for field, label in (("display_name", "display name"),
                             ("location", "location"), ("description", "bio"),
                             ("job_title", "job title"), ("company", "company"),
                             ("pronouns", "pronouns")):
            if value := prof.get(field):
                # Self-described, on a profile the address owner controls.
                result.add(f"Gravatar {label}", str(value)[:300], source="gravatar",
                           severity=Severity.NOTABLE,
                           extra={"basis": "self-described on the owner's profile"})
        for acc in prof.get("verified_accounts") or []:
            if not isinstance(acc, dict) or acc.get("is_hidden"):
                continue
            label = acc.get("service_label") or acc.get("service_type") or "?"
            link = acc.get("url") or ""
            # Gravatar checked these: the owner proved control of the account.
            result.add(f"verified: {label}", link, source="gravatar",
                       url=link or None, severity=Severity.HIGH,
                       confidence=Confidence.CONFIRMED)
            handle = _handle_from_url(link)
            if handle:
                result.entity(EntityType.USERNAME, handle, relation="linked-account",
                              evidence="gravatar-hash", url=link,
                              detail=f"account Gravatar verified on {label}")

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
            result.entity(EntityType.USERNAME, str(item.get("login")), relation="same-as",
                          evidence="commit-email",
                          detail="GitHub account registered to this address")


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


def _handle_from_url(url: str) -> str:
    """The guarded profile-URL parser the ``declared`` module uses."""
    from .declared import _handle_in

    return _handle_in(url) if url else ""
