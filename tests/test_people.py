"""Offline tests for name search and relationship discovery.

The property under test throughout is **restraint**. A name identifies a set of
people, not a person, and the failure mode for this kind of module is not
missing data — it is confidently attaching one person's employer, accounts and
associates to a different person who happens to share their name.
"""

from __future__ import annotations

import json

import pytest

from nova_osint.core.config import Config
from nova_osint.core.engine import Engine
from nova_osint.core.entities import Entity, EntityType
from nova_osint.core.graph import EVIDENCE, EntityGraph
from nova_osint.core.http import Response
from nova_osint.core.models import ModuleStatus, ScanResult, TargetType
from nova_osint.core.registry import detect_type
from nova_osint.modules.people import BlueskyModule, SocialGraphModule, WikidataModule


class FakeHttp:
    def __init__(self, routes: dict[str, Response], default: int = 404) -> None:
        self.routes = routes
        self.default = default
        self.calls: list[str] = []

    def get(self, url: str, **kw) -> Response:
        self.calls.append(url)
        for fragment, response in self.routes.items():
            if fragment in url:
                return response
        return Response(url=url, status=self.default)

    def get_json(self, url: str, default=None, **kw):
        return self.get(url, **kw).json(default)

    def map(self, fn, items):
        return [fn(i) for i in items]


def _json(payload, status: int = 200) -> Response:
    return Response(url="https://x.test", status=status,
                    headers={"content-type": "application/json"},
                    body=json.dumps(payload).encode())


def _run(cls, http, target, ttype) -> ScanResult:
    res = ScanResult(module=cls.name, target=target, target_type=ttype)
    etype = (EntityType.PERSON if ttype is TargetType.PERSON
             else EntityType.USERNAME if ttype is TargetType.USERNAME
             else EntityType.DOMAIN)
    res.subject = Entity.make(etype, target)
    cls(http, Config(cache_dir=None)).run(target, res)
    return res


def _labels(res):
    return {f.label for f in res.findings}


def _links(res):
    return {(link.src.value, link.label, link.dst.value, link.kind)
            for link in res.links}


# ---------------------------------------------------------------------------
# a name is a target
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("text,expected", [
    ("Ada Lovelace", "person"),
    ("Jean-Luc Picard", "person"),
    ("J. R. R. Tolkien", "person"),
    ("Ursula K. Le Guin", "person"),
    ("O'Brien Smith", "person"),
    ("torvalds", "username"),          # a handle is still a handle
    ("example.com", "domain"),
    ("alice@example.com", "email"),
    ("8.8.8.8", "ip"),
    ("user 123", "unknown"),           # digits are not names
    ("this is a whole sentence here", "unknown"),
])
def test_name_detection_is_conservative(text, expected):
    assert detect_type(text).value == expected


def test_name_detection_cannot_steal_an_existing_type():
    """It only fires on input that previously resolved to UNKNOWN.

    The username pattern rejects spaces, so nothing that used to be recognised
    as a handle, domain, email, IP or phone can be reinterpreted as a name.
    """
    for handle in ("torvalds", "a.b-c_d", "x1"):
        assert detect_type(handle) is TargetType.USERNAME


# ---------------------------------------------------------------------------
# wikidata
# ---------------------------------------------------------------------------

WD_SEARCH = {"search": [
    {"id": "Q1", "label": "Matthew Prince", "description": "American businessman"},
    {"id": "Q2", "label": "Matt Prince", "description": "professional wrestler"},
]}

WD_ENTITIES = {"entities": {
    "Q1": {
        "labels": {"en": {"value": "Matthew Prince"}},
        "claims": {
            "P108": [{"mainsnak": {"datavalue": {"value": {"id": "Q99"}}}}],
            "P106": [{"mainsnak": {"datavalue": {"value": {"id": "Q98"}}}}],
            "P2002": [{"mainsnak": {"datavalue": {"value": "eastdakota"}}}],
        },
    },
    "Q2": {
        "labels": {"en": {"value": "Matt Prince"}},
        "claims": {"P106": [{"mainsnak": {"datavalue": {"value": {"id": "Q97"}}}}]},
    },
}}

WD_LABELS = {"entities": {
    "Q99": {"labels": {"en": {"value": "Cloudflare"}}},
    "Q98": {"labels": {"en": {"value": "entrepreneur"}}},
    "Q97": {"labels": {"en": {"value": "wrestler"}}},
}}


def _wikidata_http():
    return FakeHttp({
        "wbsearchentities": _json(WD_SEARCH),
        "ids=Q1|Q2": _json(WD_ENTITIES),
        "ids=Q99": _json({"entities": {"Q99": WD_LABELS["entities"]["Q99"]}}),
        "ids=Q98": _json({"entities": {"Q98": WD_LABELS["entities"]["Q98"]}}),
        "ids=Q97": _json({"entities": {"Q97": WD_LABELS["entities"]["Q97"]}}),
    })


def test_a_name_returns_candidates_not_an_answer():
    res = _run(WikidataModule, _wikidata_http(), "Matthew Prince", TargetType.PERSON)
    candidates = next(f for f in res.findings if f.label == "wikidata candidates")
    assert len(candidates.value) == 2
    assert any("businessman" in c for c in candidates.value)
    assert any("wrestler" in c for c in candidates.value)


def test_an_ambiguous_name_says_so_out_loud():
    """Silence about ambiguity reads as an identification."""
    res = _run(WikidataModule, _wikidata_http(), "Matthew Prince", TargetType.PERSON)
    note = next(f for f in res.findings if f.label == "ambiguity")
    assert "2 entities share this name" in str(note.value)
    assert "which one is yours" in str(note.value)


def test_a_name_edge_is_worth_almost_nothing():
    """It takes several more observations to outweigh one verified proof."""
    res = _run(WikidataModule, _wikidata_http(), "Matthew Prince", TargetType.PERSON)
    name_edges = [x for x in res.links if x.kind == "name-similarity"]
    assert name_edges
    assert EVIDENCE["name-similarity"] < EVIDENCE["keybase-proof"] / 20


def test_affiliations_link_the_candidate_not_the_search_term():
    """The employer belongs to one candidate, not to the name they share.

    Caught live: the candidate whose Wikidata label equalled the search term was
    keyed on that label, so it *became* the seed node and its employer, schools
    and accounts attached to a name two different people use. Candidates are
    keyed on their Q-id now, which is the only thing about them that is unique.
    """
    res = _run(WikidataModule, _wikidata_http(), "Matthew Prince", TargetType.PERSON)
    links = _links(res)
    assert ("matthew prince (q1)", "works-at", "cloudflare", "wikidata-claim") in links
    # The bare name - the thing the two candidates share - owns nothing but the
    # weak candidate-for edges.
    from_bare = {(rel, kind) for src, rel, _, kind in links if src == "matthew prince"}
    assert from_bare == {("candidate-for", "name-similarity")}


def test_two_candidates_stay_two_entities():
    res = _run(WikidataModule, _wikidata_http(), "Matthew Prince", TargetType.PERSON)
    people = {e.value for e in res.nodes if e.etype is EntityType.PERSON}
    assert "matthew prince (q1)" in people and "matt prince (q2)" in people


def test_declared_accounts_become_entities():
    res = _run(WikidataModule, _wikidata_http(), "Matthew Prince", TargetType.PERSON)
    assert "username:eastdakota" in {e.eid for e in res.nodes}
    assert any(x.label == "declared-account" for x in res.links)


def test_an_unknown_name_is_reported_plainly():
    http = FakeHttp({"wbsearchentities": _json({"search": []})})
    res = _run(WikidataModule, http, "Nobody Here", TargetType.PERSON)
    assert "no entity called" in str(res.findings[0].value)
    assert not res.links


def test_wikidata_html_error_is_unavailable_not_empty():
    http = FakeHttp({"wbsearchentities": Response(url="u", status=503)})
    res = _run(WikidataModule, http, "Ada Lovelace", TargetType.PERSON)
    assert res.status is ModuleStatus.UNAVAILABLE


# ---------------------------------------------------------------------------
# bluesky
# ---------------------------------------------------------------------------

BSKY_SEARCH = {"actors": [
    {"handle": "eastdakota.com", "displayName": "Matthew Prince"},
    {"handle": "the-mrp.bsky.social", "displayName": "Matthew Prince"},
    {"handle": "someone.bsky.social", "displayName": "Someone Else"},
]}


def test_display_name_search_returns_every_candidate_and_flags_the_clash():
    http = FakeHttp({"searchActors": _json(BSKY_SEARCH)})
    res = _run(BlueskyModule, http, "Matthew Prince", TargetType.PERSON)
    assert "bluesky candidates" in _labels(res)
    note = next(f for f in res.findings if f.label == "ambiguity")
    assert "2 Bluesky accounts use exactly this display name" in str(note.value)


def test_the_handle_stem_is_emitted_so_sources_can_corroborate():
    """Two independent sources naming one account must converge on one node.

    A Bluesky handle is a domain; every other platform uses the bare stem. Left
    unlinked, a handle Wikidata declares and the same handle found here are two
    nodes and the agreement between them is invisible.
    """
    http = FakeHttp({"searchActors": _json(BSKY_SEARCH)})
    res = _run(BlueskyModule, http, "Matthew Prince", TargetType.PERSON)
    values = {e.value for e in res.nodes}
    assert "eastdakota.com" in values and "eastdakota" in values


def test_corroborated_accounts_outrank_uncorroborated_ones():
    """End to end: the arithmetic does the ranking, nothing special-cases it."""
    graph = EntityGraph(Entity.make(EntityType.PERSON, "Matthew Prince"))
    Engine.merge(graph, _run(WikidataModule, _wikidata_http(), "Matthew Prince",
                             TargetType.PERSON))
    Engine.merge(graph, _run(BlueskyModule, FakeHttp({"searchActors": _json(BSKY_SEARCH)}),
                             "Matthew Prince", TargetType.PERSON))
    graph.rescore()
    # Ranked the way the dossier ranks: strongest evidence first. Relevance
    # alone ties these, because the Wikidata path reaches eastdakota through a
    # candidate nobody has confirmed is the subject. That low relevance is the
    # honest number, which is exactly why corroboration is shown beside it.
    def strength(node):
        edges = graph.edges_of(node.entity.eid)
        return max((e.llr for e in edges), default=0.0), len(node.sources)

    handles = sorted((n for n in graph if n.entity.etype is EntityType.USERNAME),
                     key=strength, reverse=True)
    assert handles[0].entity.value == "eastdakota"
    assert strength(handles[0])[0] > strength(handles[1])[0] * 2
    sources = {o.module for e in graph.edges_of("username:eastdakota")
               for o in e.observations}
    assert sources == {"wikidata", "bluesky"}, "two independent sources agree"


def test_a_profile_lookup_records_the_did_not_just_the_handle():
    """The handle is a rented domain; the DID is the identity that survives it."""
    http = FakeHttp({"getProfile": _json({
        "did": "did:plc:abc123", "handle": "alice.bsky.social",
        "displayName": "Alice", "createdAt": "2023-05-01T00:00:00Z",
        "followersCount": 10, "followsCount": 5, "postsCount": 3})})
    res = _run(BlueskyModule, http, "alice.bsky.social", TargetType.USERNAME)
    assert next(f for f in res.findings if f.label == "bluesky DID").value == \
        "did:plc:abc123"


def test_mutual_follows_outweigh_one_way_follows():
    """A mutual follow is a relationship; a one-way follow is an interest."""
    http = FakeHttp({
        "getProfile": _json({"did": "did:plc:x", "handle": "alice.bsky.social"}),
        "getFollows": _json({"follows": [{"handle": "bob.bsky.social"},
                                         {"handle": "carol.bsky.social"}]}),
        "getFollowers": _json({"followers": [{"handle": "bob.bsky.social"},
                                             {"handle": "dave.bsky.social"}]}),
    })
    res = _run(BlueskyModule, http, "alice.bsky.social", TargetType.USERNAME)
    # Keyed on the other party, whichever end of the edge it sits on: a
    # follower's edge points *at* the target, and that direction is the point.
    kinds = {(src if dst == "alice.bsky.social" else dst): kind
             for src, _, dst, kind in _links(res)}
    assert kinds["bob.bsky.social"] == "mutual-follow"
    assert kinds["carol.bsky.social"] == "social-follow"
    assert kinds["dave.bsky.social"] == "social-follow"
    assert EVIDENCE["mutual-follow"] > EVIDENCE["social-follow"] * 3


def test_the_direction_of_a_one_way_follow_is_preserved():
    """Who follows whom is the information; collapsing it loses the asymmetry."""
    http = FakeHttp({
        "getProfile": _json({"did": "did:plc:x", "handle": "alice.bsky.social"}),
        "getFollows": _json({"follows": [{"handle": "carol.bsky.social"}]}),
        "getFollowers": _json({"followers": [{"handle": "dave.bsky.social"}]}),
    })
    res = _run(BlueskyModule, http, "alice.bsky.social", TargetType.USERNAME)
    links = _links(res)
    assert ("alice.bsky.social", "follows", "carol.bsky.social", "social-follow") in links
    assert ("dave.bsky.social", "follows", "alice.bsky.social", "social-follow") in links


def test_placeholder_handles_are_dropped():
    """Bluesky returns handle.invalid for accounts whose domain no longer resolves."""
    http = FakeHttp({
        "getProfile": _json({"did": "did:plc:x", "handle": "alice.bsky.social"}),
        "getFollows": _json({"follows": [{"handle": "handle.invalid"},
                                         {"handle": "bob.bsky.social"}]}),
        "getFollowers": _json({"followers": []}),
    })
    res = _run(BlueskyModule, http, "alice.bsky.social", TargetType.USERNAME)
    assert "handle.invalid" not in {dst for _, _, dst, _ in _links(res)}


# ---------------------------------------------------------------------------
# github / npm relationships
# ---------------------------------------------------------------------------


def test_github_mutuals_orgs_and_co_maintainers_become_edges():
    http = FakeHttp({
        "/followers": _json([{"login": "bob"}, {"login": "dave"}]),
        "/following": _json([{"login": "bob"}, {"login": "carol"}]),
        # Most specific first: the fake router matches on substring, and
        # "/orgs" is a prefix of the members URL.
        "/orgs/acme/members": _json([{"login": "erin"}, {"login": "alice"}]),
        "/orgs": _json([{"login": "acme"}]),
        "registry.npmjs.org": _json({"objects": [
            {"package": {"name": "left-pad",
                         "maintainers": [{"username": "alice"},
                                         {"username": "frank"}]}}]}),
    })
    res = _run(SocialGraphModule, http, "alice", TargetType.USERNAME)
    links = {(dst, kind) for _, _, dst, kind in _links(res)}
    assert ("bob", "mutual-follow") in links
    assert ("carol", "social-follow") in links
    assert ("acme", "org-member") in links
    assert ("erin", "org-member") in links, "fellow public org members are colleagues"
    assert ("frank", "co-maintainer") in links
    # dave follows alice, so alice is legitimately the destination there. What
    # must never appear is a self-loop.
    assert not any(src == dst for src, _, dst, _ in _links(res)), "self-loop"
    assert ("alice", "org-member") not in links, "not a member alongside themself"


def test_github_rate_limited_is_unavailable_not_a_lonely_person():
    """No followers and 403 are the same empty list and opposite conclusions."""
    res = _run(SocialGraphModule, FakeHttp({}, default=403), "alice",
               TargetType.USERNAME)
    assert res.status is ModuleStatus.UNAVAILABLE
    assert "GITHUB_TOKEN" in res.status_reason


def test_an_account_with_no_connections_says_so():
    http = FakeHttp({"/followers": _json([]), "/following": _json([]),
                     "/orgs": _json([])})
    res = _run(SocialGraphModule, http, "alice", TargetType.USERNAME)
    assert "no public followers or following" in str(
        next(f for f in res.findings if f.label == "github social graph").value)


def test_relationship_evidence_is_ordered_sensibly():
    """The weights encode a claim about the world; check it is the right one."""
    assert (EVIDENCE["corporate-officer"] > EVIDENCE["wikidata-claim"]
            > EVIDENCE["org-member"] > EVIDENCE["co-maintainer"]
            > EVIDENCE["mutual-follow"] > EVIDENCE["social-follow"]
            > EVIDENCE["name-similarity"])
