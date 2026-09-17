"""Offline tests for the social accounts panel.

The panel is the part of a profile people read first, so the thing worth
protecting is that a row means what it looks like it means: a verified profile,
a source's claim, and a link to check by hand must never be indistinguishable.
"""

from __future__ import annotations

import pytest

from nova_osint.core.models import (
    Confidence,
    Investigation,
    ScanResult,
    Severity,
    TargetType,
)
from nova_osint.core.socials import (
    PLATFORMS,
    UNCHECKABLE,
    collect,
    handle_from,
    platform_of,
    render_html,
    render_text,
)


def _inv(target="alice", rows=(), ttype=TargetType.USERNAME):
    inv = Investigation(target=target, target_type=ttype)
    by_module: dict[str, ScanResult] = {}
    for module, label, value, url, source in rows:
        res = by_module.get(module)
        if res is None:
            res = ScanResult(module=module, target=target, target_type=ttype)
            by_module[module] = res
            inv.results.append(res)
        res.add(label, value, source=source, url=url, severity=Severity.NOTABLE)
    return inv.finish()


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url,expected", [
    ("https://www.instagram.com/alice", "Instagram"),
    ("https://instagram.com/alice/", "Instagram"),
    ("https://www.tiktok.com/@alice", "TikTok"),
    ("https://x.com/alice", "X / Twitter"),
    ("https://twitter.com/alice", "X / Twitter"),
    ("https://www.facebook.com/alice", "Facebook"),
    ("https://t.me/alice", "Telegram"),
    ("https://music.youtube.com/@alice", "YouTube"),
    ("https://example.com/alice", ""),
])
def test_platform_is_read_from_the_hostname(url, expected):
    assert platform_of(url) == expected


def test_a_longer_hostname_wins_over_a_shorter_match():
    """hub.docker.com must not be swallowed by a shorter entry."""
    assert platform_of("https://hub.docker.com/u/alice") == "Docker Hub"


@pytest.mark.parametrize("url,expected", [
    ("https://www.tiktok.com/@alice", "alice"),
    ("https://instagram.com/alice/", "alice"),
    ("https://reddit.com/user/alice", "alice"),
    ("https://github.com/alice.keys", ""),      # a key file, not a profile
    ("https://github.com/alice.gpg", ""),
    ("https://medium.com/feed.rss", ""),
    ("https://twitter.com/search", ""),         # platform furniture
    ("https://facebook.com/login", ""),
])
def test_handle_extraction_rejects_files_and_furniture(url, expected):
    assert handle_from(url) == expected


def test_key_files_do_not_appear_as_accounts():
    """Caught live: github.com/x.keys showed up as the account @x.keys."""
    inv = _inv(rows=[
        ("keys", "SSH key", "SHA256:abc", "https://github.com/alice.keys", "github"),
        ("keys", "GPG key", "present", "https://github.com/alice.gpg", "github"),
        ("username", "GitHub", "https://github.com/alice",
         "https://github.com/alice", "username"),
    ])
    handles = {a.handle for a in collect(inv) if a.platform == "GitHub"}
    assert handles == {"alice"}


# ---------------------------------------------------------------------------
# what a row means
# ---------------------------------------------------------------------------


def test_a_verified_hit_and_a_manual_link_are_not_the_same_row():
    """A link the tool generated is not evidence the account exists."""
    inv = _inv(rows=[
        ("username", "Instagram", "https://instagram.com/alice",
         "https://instagram.com/alice", "username"),
        ("phone", "check manually: Telegram", "https://t.me/alice",
         "https://t.me/alice", "link"),
    ])
    basis = {a.platform: a.basis for a in collect(inv)}
    assert basis["Instagram"] == "confirmed"
    assert basis["Telegram"] == "search"


def test_a_declared_account_ranks_below_a_verified_one():
    inv = _inv(rows=[
        ("wikidata", "X/Twitter", "alice", "https://x.com/alice", "wikidata"),
    ])
    assert collect(inv)[0].basis == "declared"


def test_the_strongest_basis_wins_when_a_profile_arrives_twice():
    inv = _inv(rows=[
        ("wikidata", "GitHub", "alice", "https://github.com/alice", "wikidata"),
        ("username", "GitHub", "https://github.com/alice",
         "https://github.com/alice", "username"),
    ])
    rows = [a for a in collect(inv) if a.platform == "GitHub"]
    assert len(rows) == 1 and rows[0].basis == "confirmed"


def test_the_legend_explains_every_mark_it_uses():
    inv = _inv(rows=[
        ("username", "Instagram", "https://instagram.com/alice",
         "https://instagram.com/alice", "username"),
    ])
    text = render_text(collect(inv))
    for mark in ("+", "~", "?"):
        assert mark in text
    assert "verified by a lookup" in text and "open by hand" in text


# ---------------------------------------------------------------------------
# platforms nobody can check
# ---------------------------------------------------------------------------


def test_facebook_gets_a_row_even_though_it_cannot_be_checked():
    """Silently omitting it lets a reader conclude there is no account."""
    accounts = collect(_inv())
    facebook = next(a for a in accounts if a.platform == "Facebook")
    assert facebook.basis == "search"
    assert "blocks anonymous profile checks" in facebook.note
    assert "Absence here means nothing was checked" in facebook.note
    assert "alice" in facebook.url


def test_an_unchecked_platform_disappears_once_it_is_actually_found():
    inv = _inv(rows=[
        ("username", "Facebook", "https://facebook.com/alice",
         "https://facebook.com/alice", "username"),
    ])
    rows = [a for a in collect(inv) if a.platform == "Facebook"]
    assert len(rows) == 1 and rows[0].basis == "confirmed"


def test_every_unchecked_entry_explains_itself():
    for platform, (template, note) in UNCHECKABLE.items():
        assert "{q}" in template, platform
        assert len(note) > 30, platform
        assert platform in PLATFORMS.values(), platform


def test_no_unchecked_rows_without_a_handle_to_search_for():
    """A search link needs something to search for."""
    inv = Investigation(target="203.0.113.1", target_type=TargetType.IP).finish()
    assert collect(inv) == []


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def test_the_panel_is_empty_rather_than_absent_when_nothing_was_found():
    inv = Investigation(target="203.0.113.1", target_type=TargetType.IP).finish()
    assert "no social profiles found" in render_text(collect(inv))


def test_html_links_are_clickable_and_escaped():
    inv = _inv(rows=[
        ("username", "Instagram", "https://instagram.com/alice",
         "https://instagram.com/alice?x=<script>", "username"),
    ])
    html = render_html(collect(inv))
    assert "<a href=" in html and "rel='noreferrer noopener'" in html
    assert "<script>" not in html


def test_the_panel_reaches_the_profile_and_its_json():
    import json

    from nova_osint.core.profile import build
    from nova_osint.core.report import RENDERERS

    inv = _inv(rows=[
        ("username", "TikTok", "https://www.tiktok.com/@alice",
         "https://www.tiktok.com/@alice", "username"),
    ])
    profile = build(inv)
    assert any(a.platform == "TikTok" for a in profile.socials)
    assert "SOCIAL ACCOUNTS" in RENDERERS["profile"](inv)
    assert "Social accounts" in RENDERERS["profile-html"](inv)
    payload = json.loads(RENDERERS["profile-json"](inv))
    assert payload["social_accounts"][0]["platform"] == "TikTok"


def test_the_panel_sits_above_the_entity_sections():
    """It is what people look for first; burying it wastes the document."""
    from nova_osint.core.report import RENDERERS

    inv = _inv(rows=[
        ("username", "Instagram", "https://instagram.com/alice",
         "https://instagram.com/alice", "username"),
    ])
    text = RENDERERS["profile"](inv)
    assert text.index("SOCIAL ACCOUNTS") < text.index("INFRASTRUCTURE")


def test_the_search_link_looks_for_the_subject_not_a_bystander():
    """Caught in a screenshot: ?q=novemberborn on a scan of sindresorhus.

    The graph holds every handle the scan touched - co-maintainers, followers,
    org colleagues - and picking the alphabetically first one sent the reader to
    search Facebook for somebody the subject merely shares a package with.
    """
    inv = _inv(target="sindresorhus", rows=[
        ("username", "GitHub", "https://github.com/sindresorhus",
         "https://github.com/sindresorhus", "username"),
    ])
    accounts = collect(inv, subject_handles={"novemberborn", "avajs", "sindresorhus"})
    facebook = next(a for a in accounts if a.platform == "Facebook")
    assert "q=sindresorhus" in facebook.url
    assert "novemberborn" not in facebook.url


def test_a_non_person_target_falls_back_to_a_discovered_handle():
    inv = Investigation(target="example.com", target_type=TargetType.DOMAIN).finish()
    accounts = collect(inv, subject_handles={"acmecorp"})
    assert any("acmecorp" in a.url for a in accounts if a.platform == "Facebook")


def test_a_name_match_is_not_a_confirmed_account() -> None:
    """"Is this account real?" is not the question a reader is asking.

    A Bluesky name search returns accounts that certainly exist and may belong
    to someone else entirely. Filing those under "verified by a lookup" put a
    stranger's profile in the subject's account list with a tick beside it.
    """
    from nova_osint.core.socials import collect

    inv = Investigation(target="Ada Lovelace", target_type=TargetType.PERSON)
    res = ScanResult(module="bluesky", target="Ada Lovelace",
                     target_type=TargetType.PERSON)
    res.add("bluesky @someone.bsky.social", "Ada Lovelace - display name matches",
            source="bluesky", url="https://bsky.app/profile/someone.bsky.social",
            confidence=Confidence.POSSIBLE)
    res.add("bluesky @real.bsky.social", "the subject's own profile",
            source="bluesky", url="https://bsky.app/profile/real.bsky.social",
            confidence=Confidence.CONFIRMED)
    inv.results = [res]

    by_handle = {a.handle: a.basis for a in collect(inv)}
    assert by_handle["someone.bsky.social"] == "possible"
    assert by_handle["real.bsky.social"] == "confirmed"
