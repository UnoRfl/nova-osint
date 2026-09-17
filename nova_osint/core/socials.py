"""The social accounts panel: one platform per row, with the link.

The profile's Accounts section lists handles, which is the right shape for the
graph and the wrong shape for a person reading a dossier. What a reader wants is
"here is the Instagram, here is the TikTok, here is the link" - so this collects
every profile URL the whole investigation produced, whichever module found it,
works out which platform it belongs to, and lays them out one per row.

Collecting by **URL** rather than by module is what makes it complete. The
username sweep, a Wikidata declared account, a Keybase proof, a GitHub profile
link and a Bluesky handle all arrive differently and all end up as a URL on some
platform's domain, so one hostname table catches all of them.

Platforms that cannot be checked
--------------------------------

Some of the biggest platforms refuse anonymous profile lookups - Facebook is the
obvious one, which is why it is absent from every public username-checking
catalogue including the one NOVA uses. A panel that silently omits Facebook lets
the reader conclude there is no Facebook account.

So those platforms get a row too, marked ``not checkable``, with a search URL to
open by hand. "We could not look" and "there is nothing there" stay different
answers here exactly as they do everywhere else in this tool.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Any

from .models import Investigation

# ---------------------------------------------------------------------------
# platforms
# ---------------------------------------------------------------------------

#: ``hostname fragment -> display name``. Matched against the host of any URL
#: the investigation produced, longest fragment first so "music.youtube.com"
#: does not land on a shorter entry by accident.
PLATFORMS: dict[str, str] = {
    "facebook.com": "Facebook",
    "instagram.com": "Instagram",
    "tiktok.com": "TikTok",
    "twitter.com": "X / Twitter",
    "x.com": "X / Twitter",
    "linkedin.com": "LinkedIn",
    "youtube.com": "YouTube",
    "reddit.com": "Reddit",
    "snapchat.com": "Snapchat",
    "pinterest.com": "Pinterest",
    "t.me": "Telegram",
    "telegram.me": "Telegram",
    "wa.me": "WhatsApp",
    "threads.net": "Threads",
    "bsky.app": "Bluesky",
    "mastodon.social": "Mastodon",
    "github.com": "GitHub",
    "gitlab.com": "GitLab",
    "keybase.io": "Keybase",
    "twitch.tv": "Twitch",
    "spotify.com": "Spotify",
    "soundcloud.com": "SoundCloud",
    "medium.com": "Medium",
    "tumblr.com": "Tumblr",
    "flickr.com": "Flickr",
    "vimeo.com": "Vimeo",
    "patreon.com": "Patreon",
    "steamcommunity.com": "Steam",
    "discord.com": "Discord",
    "npmjs.com": "npm",
    "crates.io": "crates.io",
    "hub.docker.com": "Docker Hub",
    "stackoverflow.com": "Stack Overflow",
    "about.me": "About.me",
    "gravatar.com": "Gravatar",
    "vk.com": "VK",
    "weibo.com": "Weibo",
    "line.me": "LINE",
    "kakao.com": "KakaoTalk",
}

#: Platforms worth a row even when nothing was found, because they refuse
#: anonymous lookups and their absence is therefore meaningless. The value is a
#: search URL to open by hand.
UNCHECKABLE: dict[str, tuple[str, str]] = {
    "Facebook": (
        "https://www.facebook.com/search/people/?q={q}",
        "Facebook blocks anonymous profile checks, so no catalogue can test it. "
        "Absence here means nothing was checked.",
    ),
    "LinkedIn": (
        "https://www.linkedin.com/search/results/people/?keywords={q}",
        "LinkedIn serves a login wall to anonymous visitors; a hit below, if "
        "any, is a URL pattern rather than a confirmed profile.",
    ),
    "Snapchat": (
        "https://www.snapchat.com/add/{q}",
        "Snapchat does not expose profile existence reliably without an app "
        "session.",
    ),
    "Threads": (
        "https://www.threads.net/@{q}",
        "Threads requires a session for most profile views.",
    ),
}

_HANDLE_FROM_URL = re.compile(r"/@?([A-Za-z0-9._\-]{2,64})/?$")

#: Last path segments that are a *file*, not a profile. github.com/x.keys and
#: github.com/x.gpg are real URLs on a platform domain whose final segment looks
#: exactly like a handle, and they appeared in the panel as the accounts
#: "@sindresorhus.keys" and "@sindresorhus.gpg".
_NOT_A_HANDLE = re.compile(
    r"\.(keys|gpg|asc|json|xml|rss|atom|txt|ico|png|jpg|svg|css|js|php|html?)$", re.I)

#: Path segments that are the platform's own furniture rather than somebody's
#: account name.
_RESERVED = frozenset({
    "search", "login", "signup", "register", "about", "help", "settings",
    "explore", "home", "terms", "privacy", "legal", "download", "pricing",
    "features", "blog", "news", "support", "contact", "api", "docs", "status",
})


@dataclass
class SocialAccount:
    platform: str
    handle: str
    url: str
    #: "confirmed" when a module verified the profile exists, "declared" when a
    #: source said so, "search" when this is a link to check by hand.
    basis: str
    source: str = ""
    note: str = ""

    @property
    def checkable(self) -> bool:
        return self.basis != "search"

    def to_dict(self) -> dict[str, Any]:
        return {"platform": self.platform, "handle": self.handle, "url": self.url,
                "basis": self.basis, "source": self.source, "note": self.note}


# ---------------------------------------------------------------------------
# collection
# ---------------------------------------------------------------------------


def platform_of(url: str) -> str:
    """Which platform a URL belongs to, or ``""``."""
    from .http import hostname_of

    host = (hostname_of(url) or "").lower().removeprefix("www.")
    if not host:
        return ""
    # Longest fragment first: "music.youtube.com" must not match a short entry
    # before the one that actually describes it.
    for fragment in sorted(PLATFORMS, key=len, reverse=True):
        if host == fragment or host.endswith("." + fragment):
            return PLATFORMS[fragment]
    return ""


def handle_from(url: str) -> str:
    """The account name in a profile URL, or ``""`` if the URL is not one."""
    path = urllib.parse.urlsplit(url).path.rstrip("/")
    if _NOT_A_HANDLE.search(path):
        return ""
    match = _HANDLE_FROM_URL.search(path)
    if not match:
        return ""
    handle = match.group(1)
    return "" if handle.casefold() in _RESERVED else handle


def collect(inv: Investigation, subject_handles: set[str] | None = None
            ) -> list[SocialAccount]:
    """Every social profile the investigation produced, one row per platform.

    Deduplicated on ``(platform, handle)``, keeping the strongest basis, because
    the same account routinely arrives from three modules and a reader does not
    want it three times.
    """
    rank = {"confirmed": 3, "declared": 2, "search": 1}
    best: dict[tuple[str, str], SocialAccount] = {}

    for result in inv.results:
        for finding in result.findings:
            for url in _urls_in(finding):
                platform = platform_of(url)
                if not platform:
                    continue
                handle = handle_from(url)
                if not handle:
                    continue
                basis = _basis(result.module, finding)
                account = SocialAccount(platform=platform, handle=handle, url=url,
                                        basis=basis, source=result.module)
                key = (platform, handle.casefold())
                if key not in best or rank[basis] > rank[best[key].basis]:
                    best[key] = account

    accounts = sorted(best.values(), key=lambda a: (a.platform.casefold(), a.handle))
    accounts.extend(_unchecked(inv, accounts, subject_handles))
    return accounts


def _urls_in(finding: Any) -> list[str]:
    urls = []
    if finding.url:
        urls.append(str(finding.url))
    value = finding.value
    if isinstance(value, str) and value.startswith(("http://", "https://")):
        urls.append(value)
    elif isinstance(value, (list, tuple)):
        urls += [str(v) for v in value
                 if isinstance(v, str) and v.startswith(("http://", "https://"))]
    return urls


def _basis(module: str, finding: Any) -> str:
    """How much the presence of this profile is actually worth.

    A link the tool generated for the reader to click is not evidence that the
    account exists, and must not sit in the same column as one a module checked.
    """
    if finding.source == "link" or str(finding.label).startswith("check manually"):
        return "search"
    if module == "username":
        # The username module confirms a profile responded, and re-tests it
        # against a control handle unless --no-verify was passed.
        return "confirmed"
    if module in ("keybase", "webfinger", "bluesky", "github", "packages"):
        return "confirmed"
    return "declared"


def _unchecked(inv: Investigation, found: list[SocialAccount],
               subject_handles: set[str] | None) -> list[SocialAccount]:
    """Rows for the platforms nobody could check, so their absence is explained."""
    seen = {a.platform for a in found}
    # The subject, not whichever handle sorts first. The graph contains every
    # account the scan touched - co-maintainers, followers, org colleagues - and
    # taking the alphabetically-first one sent the reader off to search Facebook
    # for somebody the subject merely shares an npm package with.
    if inv.target_type.value in ("username", "person"):
        subject = inv.target
    elif subject_handles:
        subject = sorted(subject_handles)[0]
    else:
        return []
    query = urllib.parse.quote(subject)

    out = []
    for platform, (template, note) in UNCHECKABLE.items():
        if platform in seen:
            continue
        out.append(SocialAccount(platform=platform, handle="-",
                                 url=template.format(q=query), basis="search",
                                 source="", note=note))
    return out


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

BASIS_MARK = {"confirmed": "+", "declared": "~", "search": "?"}


def render_text(accounts: list[SocialAccount]) -> str:
    if not accounts:
        return "  (no social profiles found)"
    width = max(len(a.platform) for a in accounts)
    out = []
    for a in accounts:
        handle = f"@{a.handle}" if a.handle != "-" else ""
        out.append(f"    {BASIS_MARK[a.basis]}  {a.platform.ljust(width)}  "
                   f"{handle:<22} {a.url}")
        if a.note:
            out.append(f"       {' ' * width}  {a.note}")
    out.append("")
    out.append("    + verified by a lookup   ~ declared by a source   "
               "? not checkable, open by hand")
    return "\n".join(out)


def render_html(accounts: list[SocialAccount]) -> str:
    import html as html_mod

    e = html_mod.escape
    if not accounts:
        return "<div class='empty'>no social profiles found</div>"
    rows = []
    for a in accounts:
        handle = f"@{e(a.handle)}" if a.handle != "-" else "<span class='dim'>-</span>"
        note = f"<br><span class='dim'>{e(a.note)}</span>" if a.note else ""
        rows.append(
            f"<tr><td><span class='g g{a.basis[0].upper()}'>"
            f"{BASIS_MARK[a.basis]}</span></td>"
            f"<td><b>{e(a.platform)}</b></td><td>{handle}</td>"
            f"<td><a href='{e(a.url)}' rel='noreferrer noopener'>{e(a.url)}</a>"
            f"{note}</td></tr>")
    return (
        "<table><thead><tr><th></th><th>Platform</th><th>Handle</th>"
        "<th>Link</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        "<p class='dim'>+ verified by a lookup &middot; ~ declared by a source "
        "&middot; ? not checkable anonymously, open by hand</p>"
    )
