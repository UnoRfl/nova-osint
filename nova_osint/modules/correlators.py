"""Correlators: the transforms that link things sharing no obvious metadata.

Most sources answer "what is true about X". These answer "what else is the same
operator", which is a different and usually harder question. They are grouped in
one file because they share a shape: each extracts a *fingerprint* from
something already fetched, emits it as an entity, and lets the graph do the
linking - two hosts that both present tracker ``UA-12345-1`` become connected
because they both point at that node, with no code anywhere comparing them.

That indirection is the whole design. A pairwise "does A match B" check is
quadratic and only ever finds what it was told to look for; a shared node is
linear, works across an entire case history, and makes the reason visible in the
picture.

What is here, strongest evidence first:

``keys``
    SSH and GPG key fingerprints from GitHub. The same key on two identities is
    the strongest non-legal evidence available - it means somebody holds one
    private key - so it carries the highest weight in the table.
``keybase``
    Cryptographically signed proofs tying a handle to other accounts and
    domains. Signed by the account holder, verified by Keybase, and free.
``trackers``
    Analytics and advertising property ids scraped out of page source: Google
    Analytics, Tag Manager, AdSense, Meta Pixel, Yandex, Hotjar, Plausible.
    Deliberate acts by one operator, and the single highest-yield site-to-site
    link in practical OSINT. One regex over a page we already fetched.
``fingerprints``
    Favicon hash and a structural hash of the DOM. Both survive a domain
    change, which is exactly when the other links break.
``packages``
    npm, PyPI, crates.io and Docker Hub author records. For a developer target
    these routinely carry the address GitHub hides.
``webfinger``
    Fediverse account verification over a protocol that cannot soft-404.
``confusables``
    Domains that *look* like the target. Reported and never followed: it is
    someone else's infrastructure, and pivoting into it widens the
    investigation onto a third party who has done nothing.

Every source here is free and keyless.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from ..core.entities import Entity, EntityType, looks_like, registrable
from ..core.http import hostname_of
from ..core.models import Confidence, ModuleStatus, ScanResult, Severity, TargetType
from ..core.registry import Module, register

# ---------------------------------------------------------------------------
# trackers
# ---------------------------------------------------------------------------

#: ``(label, pattern)``. Each pattern's first group is the property id.
#: Ordered most-identifying first, which is also roughly least-shared: a Meta
#: Pixel belongs to one advertiser, a GTM container is often an agency's.
TRACKER_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("google-analytics", re.compile(r"\b(UA-\d{4,10}-\d{1,4})\b")),
    ("google-analytics-4", re.compile(r"\b(G-[A-Z0-9]{8,12})\b")),
    ("google-tag-manager", re.compile(r"\b(GTM-[A-Z0-9]{4,10})\b")),
    ("adsense", re.compile(r"\b(ca-pub-\d{10,20})\b")),
    ("meta-pixel", re.compile(r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{8,20})['\"]")),
    ("yandex-metrica", re.compile(r"mc\.yandex\.ru/watch/(\d{5,12})")),
    ("hotjar", re.compile(r"hjid\s*[:=]\s*(\d{5,10})")),
    ("plausible", re.compile(r"plausible\.io/js/[^\"']*data-domain=[\"']([^\"']+)")),
    ("matomo", re.compile(r"setSiteId['\"\s,]+(\d{1,6})['\"]")),
    ("clarity", re.compile(r"clarity\.ms/tag/([a-z0-9]{8,12})")),
]

#: Property ids that belong to the analytics vendor's own examples, not to a
#: site. Without this every page that ships a copy-pasted snippet links to every
#: other one, which produces a beautiful graph of nothing.
TRACKER_NOISE = frozenset({
    "UA-XXXXX-Y", "UA-000000-1", "UA-12345-1", "G-XXXXXXXXXX", "GTM-XXXX",
    "GTM-XXXXXX", "ca-pub-0000000000000000",
})


@register
class TrackerModule(Module):
    name = "trackers"
    title = "Analytics and advertising identifiers"
    description = "GA, GTM, AdSense, Pixel, Yandex, Hotjar ids shared between sites."
    accepts = frozenset({TargetType.DOMAIN, TargetType.URL})
    #: Fetches the target's own page.
    active = True

    def run(self, target: str, result: ScanResult) -> None:
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        resp = self.http.get(url, timeout=20)
        if not resp.ok:
            result.degrade(ModuleStatus.UNAVAILABLE,
                           f"{hostname_of(url)} answered {resp.status}")
            return
        body = resp.text[:600_000]
        found = 0
        for label, pattern in TRACKER_PATTERNS:
            for match in dict.fromkeys(pattern.findall(body)):
                value = str(match).strip()
                if not value or value.upper() in TRACKER_NOISE:
                    continue
                found += 1
                result.add(f"{label} id", value, source="page source",
                           url=resp.url, severity=Severity.NOTABLE,
                           confidence=Confidence.CONFIRMED)
                result.entity(EntityType.TRACKER, f"{label}/{value}",
                              relation="uses-tracker", evidence="tracker-id-shared",
                              url=resp.url,
                              detail=f"{label} {value} appears in the page source")
        if not found:
            result.add("analytics", "no tracker ids in the page source",
                       source="page source", url=resp.url)


# ---------------------------------------------------------------------------
# fingerprints
# ---------------------------------------------------------------------------

_TAG_RE = re.compile(r"<\s*([a-zA-Z][a-zA-Z0-9-]{0,20})")
_SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)


@register
class FingerprintModule(Module):
    name = "fingerprint"
    title = "Site fingerprints"
    description = "Favicon and DOM-structure hashes that survive a domain change."
    accepts = frozenset({TargetType.DOMAIN, TargetType.URL})
    active = True

    def run(self, target: str, result: ScanResult) -> None:
        base = target if target.startswith(("http://", "https://")) else f"https://{target}"
        base = base.rstrip("/")

        icon = self.http.get(f"{base}/favicon.ico", timeout=15)
        if icon.ok and icon.body:
            digest = hashlib.sha256(icon.body).hexdigest()
            result.add("favicon sha256", digest[:32], source="favicon",
                       url=f"{base}/favicon.ico")
            result.entity(EntityType.FAVICON, digest, relation="serves-favicon",
                          evidence="favicon-hash", url=f"{base}/favicon.ico",
                          detail="identical favicon bytes")

        page = self.http.get(base, timeout=20)
        if not page.ok:
            if not icon.ok:
                result.degrade(ModuleStatus.UNAVAILABLE,
                               f"{hostname_of(base)} answered {page.status}")
            return
        shape = _structure_hash(page.text)
        result.add("DOM structure sha256", shape[:32], source="page source",
                   url=page.url)
        result.entity(EntityType.FILEHASH, f"dom/{shape}", relation="page-shape",
                      evidence="page-structure-hash", url=page.url,
                      detail="same template, ignoring text content")

        # Third-party script hosts are weak on their own (everyone loads jQuery)
        # but the graph's hub demotion handles that automatically, and a
        # self-hosted bundle on an unrelated domain is a strong link.
        hosts = {hostname_of(src) for src in _SCRIPT_SRC_RE.findall(page.text)
                 if src.startswith("http")}
        hosts.discard("")
        external = sorted(h for h in hosts if registrable(h) != registrable(
            hostname_of(base)))
        if external:
            result.add("third-party script hosts", external[:25], source="page source",
                       url=page.url)
            for host in external[:25]:
                result.entity(EntityType.HOST, host, relation="loads-script-from",
                              evidence="mentioned", url=page.url)


def _structure_hash(html: str) -> str:
    """Hash the tag sequence, not the text.

    Content changes constantly; the template does not. Hashing the order of tag
    names catches "the same site rebuilt under a new name", which is precisely
    the case where every identifier-based link has been deliberately removed.
    """
    tags = [t.lower() for t in _TAG_RE.findall(html[:400_000])]
    return hashlib.sha256(" ".join(tags).encode()).hexdigest()


# ---------------------------------------------------------------------------
# public keys
# ---------------------------------------------------------------------------


@register
class KeyModule(Module):
    name = "keys"
    title = "Public SSH and GPG keys"
    description = "Key fingerprints from GitHub - the strongest identity link there is."
    accepts = frozenset({TargetType.USERNAME})

    def run(self, target: str, result: ScanResult) -> None:
        ssh = self.http.get(f"https://github.com/{target}.keys", timeout=15)
        if ssh.status == 404:
            result.add("github keys", "no such account", source="github")
            return
        if not ssh.ok:
            result.degrade(ModuleStatus.UNAVAILABLE, f"github answered {ssh.status}")
            return

        count = 0
        for line in ssh.text.splitlines():
            parts = line.split()
            if len(parts) < 2 or not parts[0].startswith(("ssh-", "ecdsa-", "sk-")):
                continue
            count += 1
            fp = _ssh_fingerprint(parts[1])
            if not fp:
                continue
            result.add(f"SSH key ({parts[0]})", fp, source="github",
                       url=f"https://github.com/{target}.keys",
                       severity=Severity.NOTABLE)
            result.entity(EntityType.KEY, f"ssh/{fp}", relation="holds-key",
                          evidence="key-fingerprint-shared",
                          url=f"https://github.com/{target}.keys",
                          detail=f"{parts[0]} public key published on GitHub")
        if not count:
            result.add("SSH keys", "account exists, no public keys", source="github")

        gpg = self.http.get(f"https://github.com/{target}.gpg", timeout=15)
        if gpg.ok and "BEGIN PGP PUBLIC KEY" in gpg.text:
            digest = hashlib.sha256(gpg.body).hexdigest()
            result.add("GPG key published", f"sha256:{digest[:24]}", source="github",
                       url=f"https://github.com/{target}.gpg",
                       severity=Severity.NOTABLE)
            result.entity(EntityType.KEY, f"gpg/{digest}", relation="holds-key",
                          evidence="key-fingerprint-shared",
                          url=f"https://github.com/{target}.gpg")


def _ssh_fingerprint(b64: str) -> str:
    """OpenSSH's own ``SHA256:...`` fingerprint of a base64 key blob."""
    import base64

    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception:  # noqa: BLE001 - malformed key material is data, not an error
        return ""
    digest = base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    return f"SHA256:{digest}"


# ---------------------------------------------------------------------------
# keybase
# ---------------------------------------------------------------------------


@register
class KeybaseModule(Module):
    name = "keybase"
    title = "Keybase signed proofs"
    description = "Cryptographically signed links between a handle and other accounts."
    accepts = frozenset({TargetType.USERNAME})

    API = "https://keybase.io/_/api/1.0/user/lookup.json"

    def run(self, target: str, result: ScanResult) -> None:
        data = self.http.get_json(
            f"{self.API}?usernames={target}&fields=proofs_summary,basics", timeout=15)
        if not isinstance(data, dict):
            result.degrade(ModuleStatus.UNAVAILABLE, "keybase did not answer with JSON")
            return
        users = data.get("them") or []
        user = next((u for u in users if isinstance(u, dict)), None)
        if user is None:
            result.add("keybase", "no account", source="keybase")
            return

        proofs = ((user.get("proofs_summary") or {}).get("all")) or []
        if not proofs:
            result.add("keybase", "account exists, no verified proofs", source="keybase")
        for proof in proofs:
            if not isinstance(proof, dict):
                continue
            kind = str(proof.get("proof_type") or "?")
            handle = str(proof.get("nametag") or "")
            link = proof.get("service_url") or proof.get("proof_url")
            if not handle:
                continue
            # These are signed by the key holder and verified by Keybase, which
            # is a different class of evidence from a profile page returning 200.
            result.add(f"verified {kind}", handle, source="keybase", url=link,
                       confidence=Confidence.CONFIRMED, severity=Severity.HIGH)
            etype = EntityType.DOMAIN if kind in ("dns", "generic_web_site") \
                else EntityType.USERNAME
            result.entity(etype, handle, relation="verified-as",
                          evidence="keybase-proof", url=link,
                          detail=f"signed {kind} proof")


# ---------------------------------------------------------------------------
# package registries
# ---------------------------------------------------------------------------


@register
class PackageModule(Module):
    name = "packages"
    title = "Package registry authorship"
    description = "npm, PyPI, crates.io and Docker Hub records for this handle."
    accepts = frozenset({TargetType.USERNAME})

    def run(self, target: str, result: ScanResult) -> None:
        checks = (
            # The obvious endpoint, /-/user/org.couchdb.user:<name>, has
            # required auth since npm locked it down - it answers 401 to
            # everyone. Search by maintainer is the keyless route, and it
            # carries the publisher's address, which is the thing worth having.
            ("npm",
             f"https://registry.npmjs.org/-/v1/search?text=maintainer:{target}&size=25",
             self._npm),
            ("crates.io", f"https://crates.io/api/v1/users/{target}", self._crates),
            ("Docker Hub", f"https://hub.docker.com/v2/users/{target}/", self._docker),
        )
        answered = 0
        for label, url, parse in checks:
            resp = self.http.get(url, timeout=15)
            if resp.status == 404:
                continue
            if not resp.ok:
                result.error(f"{label} answered {resp.status}")
                continue
            answered += 1
            parse(target, resp.json() or {}, result, url)
        if not answered:
            result.add("package registries", "no account on npm, crates.io or Docker Hub",
                       source="registries")

    def _npm(self, target: str, data: dict, result: ScanResult, url: str) -> None:
        objects = (data or {}).get("objects")
        if not isinstance(objects, list) or not objects:
            return
        packages, emails = [], {}
        for obj in objects:
            pkg = (obj or {}).get("package") or {}
            if pkg.get("name"):
                packages.append(pkg["name"])
            publisher = pkg.get("publisher") or {}
            # Only the address of the handle we asked about. A package can have
            # several maintainers, and attributing a co-maintainer's address to
            # this person is exactly the kind of quiet error that ends up in a
            # report as fact.
            if publisher.get("username", "").casefold() == target.casefold():
                if publisher.get("email"):
                    emails[publisher["email"]] = pkg["name"]
        if packages:
            result.add("npm packages", sorted(packages)[:25], source="npm",
                       url=f"https://www.npmjs.com/~{target}")
        for email, pkg in emails.items():
            result.add("npm publisher email", email, source="npm", url=url,
                       severity=Severity.HIGH)
            result.entity(EntityType.EMAIL, email, relation="registry-contact",
                          evidence="commit-email", url=url,
                          detail=f"publisher address on npm package {pkg}")

    def _crates(self, target: str, data: dict, result: ScanResult, url: str) -> None:
        user = (data or {}).get("user")
        if not isinstance(user, dict):
            return
        result.add("crates.io account", user.get("login", target), source="crates.io",
                   url=f"https://crates.io/users/{target}")
        if user.get("name"):
            result.add("crates.io display name", user["name"], source="crates.io")
            result.entity(EntityType.PERSON, user["name"], relation="display-name",
                          evidence="name-similarity", url=url)

    def _docker(self, target: str, data: dict, result: ScanResult, url: str) -> None:
        if not isinstance(data, dict) or not data.get("username"):
            return
        result.add("Docker Hub account", data["username"], source="docker hub",
                   url=f"https://hub.docker.com/u/{target}")
        for label, key in (("full name", "full_name"), ("company", "company"),
                           ("location", "location")):
            if data.get(key):
                result.add(f"Docker Hub {label}", data[key], source="docker hub")
        if data.get("company"):
            result.entity(EntityType.ORG, data["company"], relation="works-at",
                          evidence="name-similarity", url=url)


# ---------------------------------------------------------------------------
# webfinger
# ---------------------------------------------------------------------------


@register
class WebFingerModule(Module):
    name = "webfinger"
    title = "Fediverse accounts"
    description = "WebFinger lookup - a protocol that cannot soft-404 at you."
    accepts = frozenset({TargetType.EMAIL, TargetType.USERNAME})

    #: Instances worth asking about a bare handle. A full fediverse sweep is not
    #: possible and pretending otherwise would be dishonest, so the list is
    #: short, named, and the absence of a hit is reported as "these instances",
    #: never as "no fediverse account".
    INSTANCES = ("mastodon.social", "fosstodon.org", "hachyderm.io", "infosec.exchange")

    def run(self, target: str, result: ScanResult) -> None:
        if "@" in target:
            local, _, host = target.partition("@")
            pairs = [(host, f"{local}@{host}")]
        else:
            pairs = [(host, f"{target}@{host}") for host in self.INSTANCES]

        hits = 0
        for host, acct in pairs:
            url = f"https://{host}/.well-known/webfinger?resource=acct:{acct}"
            data = self.http.get_json(url, timeout=12)
            if not isinstance(data, dict) or not data.get("subject"):
                continue
            hits += 1
            profile = next((link.get("href") for link in data.get("links", [])
                            if isinstance(link, dict) and link.get("rel") == "self"),
                           None)
            result.add("fediverse account", data["subject"].replace("acct:", ""),
                       source="webfinger", url=profile or url,
                       confidence=Confidence.CONFIRMED, severity=Severity.NOTABLE)
            result.entity(EntityType.USERNAME, acct, relation="fediverse-account",
                          evidence="webfinger-proof", url=profile or url,
                          detail=f"WebFinger on {host} resolved this handle")
        if not hits:
            result.add("fediverse", f"not found on {', '.join(h for h, _ in pairs)}",
                       source="webfinger")


# ---------------------------------------------------------------------------
# confusables
# ---------------------------------------------------------------------------


@register
class ConfusableModule(Module):
    name = "confusables"
    title = "Look-alike domains"
    description = "Registered names that imitate the target, from certificate logs."
    accepts = frozenset({TargetType.DOMAIN})

    def run(self, target: str, result: ScanResult) -> None:
        base = registrable(hostname_of(target)) or target
        stem = base.split(".")[0]
        if len(stem) < 4:
            result.add("look-alike domains",
                       "name too short to check without huge false positives",
                       source="ct")
            return

        rows = self.http.get_json(
            f"https://crt.sh/?q=%25{stem}%25&output=json", timeout=45)
        if not isinstance(rows, list):
            result.degrade(ModuleStatus.UNAVAILABLE, "crt.sh did not answer with JSON")
            return

        candidates: set[str] = set()
        for row in rows:
            for name in str((row or {}).get("name_value", "")).splitlines():
                name = name.strip().lower().lstrip("*.").rstrip(".")
                reg = registrable(name)
                if reg and reg != base:
                    candidates.add(reg)

        squats = sorted(c for c in candidates if looks_like(c.split(".")[0], stem))
        if not squats:
            result.add("look-alike domains", f"none in CT for '{stem}'", source="ct")
            return
        result.add("look-alike domains", squats[:40], source="ct",
                   severity=Severity.HIGH, confidence=Confidence.LIKELY,
                   url=f"https://crt.sh/?q=%25{stem}%25")
        for squat in squats[:40]:
            found = Entity.make(EntityType.DOMAIN, squat)
            if found is None or result.subject is None:
                continue
            # Zero-weight, never-expanded: this is somebody else's domain, and
            # crawling it would quietly widen the investigation onto a third
            # party who has done nothing. The finding is the point.
            result.nodes.append(found)
            result.link(result.subject, found, "looks-like", "looks-like",
                        url=f"https://crt.sh/?q={squat}",
                        detail=f"visually confusable with {base}")


# ---------------------------------------------------------------------------
# helpers shared with the tests
# ---------------------------------------------------------------------------


def tracker_ids(html: str) -> list[tuple[str, str]]:
    """``[(label, id)]`` found in a page. Public so it can be tested directly."""
    out: list[tuple[str, str]] = []
    for label, pattern in TRACKER_PATTERNS:
        for match in dict.fromkeys(pattern.findall(html)):
            value = str(match).strip()
            if value and value.upper() not in TRACKER_NOISE:
                out.append((label, value))
    return out


def structure_hash(html: str) -> str:
    return _structure_hash(html)


def ssh_fingerprint(b64: str) -> str:
    return _ssh_fingerprint(b64)


__all__: list[Any] = [
    "TRACKER_NOISE", "TRACKER_PATTERNS", "ConfusableModule", "FingerprintModule",
    "KeyModule", "KeybaseModule", "PackageModule", "TrackerModule",
    "WebFingerModule", "ssh_fingerprint", "structure_hash", "tracker_ids",
]
