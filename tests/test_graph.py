"""Offline tests for entity canonicalisation and the weighted entity graph.

Nothing here touches the network; the graph is a pure data structure and that is
the property worth protecting. Most of these tests encode a decision that was
expensive to get right, so a failure means "you changed the meaning", not "you
renamed a variable".
"""

from __future__ import annotations

import math

import pytest

from nova_osint.core.entities import (
    Entity,
    EntityType,
    canonical,
    edit_distance,
    looks_like,
    registrable,
    skeleton,
    split_host,
)
from nova_osint.core.graph import (
    EVIDENCE,
    EntityGraph,
    Observation,
    admiralty,
    probability,
)

# ---------------------------------------------------------------------------
# canonicalisation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw,expected", [
    ("Example.COM.", "example.com"),
    ("  www.Example.com  ", "www.example.com"),
    ("*.example.com", "example.com"),
    ("example..com", "example.com"),
    ("notadomain", ""),
    ("has space.com", ""),
])
def test_host_canonicalisation(raw, expected):
    assert canonical(EntityType.DOMAIN, raw) == expected


def test_unicode_domain_folds_to_punycode():
    # The unicode spelling and its punycode form must be one node, or a CT log
    # hit and a DNS answer for the same name never connect.
    assert canonical(EntityType.DOMAIN, "bücher.de") == canonical(
        EntityType.DOMAIN, "xn--bcher-kva.de")


def test_ipv6_is_compressed():
    assert canonical(EntityType.IP, "2001:0db8:0000::0001") == "2001:db8::1"


def test_email_keeps_tags_and_dots():
    # Folding +tags away here would destroy evidence about how the address was
    # handed out. The email module reports the base inbox as a separate finding.
    assert canonical(EntityType.EMAIL, "First.Last+Signup@Example.COM") == \
        "first.last+signup@example.com"


def test_email_rejects_nonsense():
    assert canonical(EntityType.EMAIL, "not@an@address") == ""
    assert canonical(EntityType.EMAIL, "@example.com") == ""


def test_phone_keeps_international_prefix():
    assert canonical(EntityType.PHONE, "+44 (0)20 7946 0958") == "+442079460958"
    assert canonical(EntityType.PHONE, "0044 20 7946 0958") == "+442079460958"
    # No country code means no guess: inventing one would be inventing a region.
    assert canonical(EntityType.PHONE, "020 7946 0958") == "02079460958"


def test_username_is_not_stripped_of_separators():
    # john.doe and johndoe are different accounts everywhere NOVA looks.
    assert canonical(EntityType.USERNAME, "@John.Doe") == "john.doe"
    assert canonical(EntityType.USERNAME, "johndoe") != canonical(
        EntityType.USERNAME, "john.doe")


@pytest.mark.parametrize("host,domain,sub", [
    ("example.com", "example.com", None),
    ("www.example.com", "example.com", "www"),
    ("a.b.example.co.uk", "example.co.uk", "a.b"),
    ("user.github.io", "user.github.io", None),
])
def test_split_host(host, domain, sub):
    assert split_host(host) == (domain, sub)


def test_entity_promotes_subdomain_to_host():
    e = Entity.make(EntityType.DOMAIN, "mail.example.com")
    assert e is not None and e.etype is EntityType.HOST
    assert registrable(e.value) == "example.com"


def test_entity_make_returns_none_rather_than_raising():
    assert Entity.make(EntityType.IP, "999.999.999.999") is None
    assert Entity.make(EntityType.DOMAIN, "") is None


def test_entity_keeps_the_raw_spelling():
    e = Entity.make(EntityType.DOMAIN, "Example.COM.")
    assert e is not None and e.value == "example.com" and e.raw == "Example.COM."


# ---------------------------------------------------------------------------
# confusables
# ---------------------------------------------------------------------------


def test_confusables_are_detected_but_never_merged():
    a, b = "paypal.com", "paypa1.com"
    assert looks_like(a, b)
    # ...and they stay two distinct entities, because the impersonation is the
    # finding. Merging them would delete it.
    assert canonical(EntityType.DOMAIN, a) != canonical(EntityType.DOMAIN, b)


def test_cyrillic_homoglyph_domain():
    assert skeleton("аpple.com") == skeleton("apple.com")


def test_rn_folds_to_m():
    assert looks_like("rnicrosoft.com", "microsoft.com")


def test_edit_distance_caps_out():
    assert edit_distance("abc", "abd") == 1
    assert edit_distance("abc", "xyzzy", cap=2) == 3  # cap + 1, bailed early


# ---------------------------------------------------------------------------
# evidence arithmetic
# ---------------------------------------------------------------------------


def test_probability_is_monotonic_and_clamped():
    assert probability(-10) < probability(0) < probability(10)
    assert probability(-999) > 0 and probability(999) < 1


def test_independent_evidence_adds():
    e = _edge_with(["tracker-id-shared", "handle-unverified"])
    assert e.llr == pytest.approx(
        EVIDENCE["tracker-id-shared"] + EVIDENCE["handle-unverified"])


def test_repeat_evidence_of_one_kind_is_discounted():
    """crt.sh and CertSpotter read the same CT logs - that is one fact, twice.

    The second observation still counts for something (the logs could have
    diverged) but at half weight, and the third at a quarter.
    """
    one = _edge_with(["cert-san"]).llr
    two = _edge_with(["cert-san", "cert-san"]).llr
    assert one < two < 2 * one


def test_disconfirming_evidence_pulls_an_edge_down():
    strong = _edge_with(["handle-unverified"])
    assert strong.llr > 0
    weak = _edge_with(["handle-unverified", "control-handle-matched"])
    assert weak.llr < 0, "a site that says yes to everyone must not support a link"


def test_hub_demotes_positive_edges_only():
    e = _edge_with(["dns-a"])
    assert e.effective_llr(2) == pytest.approx(e.llr)
    assert e.effective_llr(200) < e.llr / 2
    bad = _edge_with(["explicit-denial"])
    assert bad.effective_llr(200) == pytest.approx(bad.llr)


def test_admiralty_grades():
    assert admiralty(7.0, 3).startswith("A")
    assert admiralty(0.2, 0)[0] == "D"
    assert admiralty(-2, 0) == "E5"
    assert admiralty(4.0, 2) == "B2"


def _edge_with(kinds):
    g = EntityGraph()
    a = Entity.make(EntityType.DOMAIN, "a.test")
    b = Entity.make(EntityType.DOMAIN, "b.test")
    edge = None
    for i, kind in enumerate(kinds):
        edge = g.connect(a, b, "rel", Observation(kind, module=f"m{i}"))
    return edge


# ---------------------------------------------------------------------------
# the graph
# ---------------------------------------------------------------------------


def _seeded():
    seed = Entity.make(EntityType.DOMAIN, "example.com")
    return EntityGraph(seed), seed


def test_seed_scores_one():
    g, seed = _seeded()
    g.rescore()
    assert g.nodes[seed.eid].score == 1.0


def test_relevance_decays_with_distance():
    g, seed = _seeded()
    hop1 = Entity.make(EntityType.IP, "203.0.113.10")
    hop2 = Entity.make(EntityType.DOMAIN, "other.test")
    g.connect(seed, hop1, "resolves-to", Observation("dns-a", "domain"))
    g.connect(hop1, hop2, "hosts", Observation("reverse-dns", "ip"))
    g.rescore()
    assert 1.0 > g.nodes[hop1.eid].score > g.nodes[hop2.eid].score > 0


def test_strong_evidence_outranks_a_shorter_weak_path():
    """Widest path, not shortest path - the whole reason for scoring at all."""
    g, seed = _seeded()
    near = Entity.make(EntityType.USERNAME, "weaklink")
    far_a = Entity.make(EntityType.EMAIL, "dev@example.com")
    far_b = Entity.make(EntityType.USERNAME, "stronglink")
    g.connect(seed, near, "mentions", Observation("name-similarity", "web"))
    g.connect(seed, far_a, "contact", Observation("rdap-contact", "domain"))
    g.connect(far_a, far_b, "same-as", Observation("keybase-proof", "keybase"))
    g.rescore()
    assert g.nodes[far_b.eid].depth == 2 and g.nodes[near.eid].depth == 1
    assert g.nodes[far_b.eid].score > g.nodes[near.eid].score


def test_hub_specificity_drops_as_neighbours_accumulate():
    g, seed = _seeded()
    hub = Entity.make(EntityType.IP, "198.51.100.1")
    g.connect(seed, hub, "resolves-to", Observation("dns-a", "domain"))
    alone = g.specificity(hub.eid)
    for i in range(60):
        other = Entity.make(EntityType.DOMAIN, f"tenant{i}.test")
        g.connect(hub, other, "hosts", Observation("reverse-dns", "ip"))
    assert g.specificity(hub.eid) < alone / 3
    assert hub.eid in {n.entity.eid for n in g.hubs()}


def test_shared_hosting_does_not_drag_the_whole_internet_in():
    """The failure mode this design exists to prevent."""
    g, seed = _seeded()
    cdn = Entity.make(EntityType.IP, "198.51.100.1")
    g.connect(seed, cdn, "resolves-to", Observation("dns-a", "domain"))
    tenants = []
    for i in range(500):
        t = Entity.make(EntityType.DOMAIN, f"tenant{i}.test")
        tenants.append(t)
        g.connect(cdn, t, "hosts", Observation("shared-hosting", "ip"))
    g.rescore()
    frontier = {n.entity.eid for n in g.frontier()}
    assert not any(t.eid in frontier for t in tenants), \
        "co-tenants on shared hosting must not be queued for expansion"


def test_frontier_is_ordered_by_relevance_and_skips_expanded():
    g, seed = _seeded()
    strong = Entity.make(EntityType.EMAIL, "admin@example.com")
    weak = Entity.make(EntityType.USERNAME, "maybe")
    g.connect(seed, strong, "contact", Observation("rdap-contact", "domain"))
    g.connect(seed, weak, "mentions", Observation("name-similarity", "web"))
    g.rescore()
    order = [n.entity.eid for n in g.frontier()]
    assert order.index(strong.eid) < order.index(weak.eid)
    g.nodes[strong.eid].expanded = True
    assert strong.eid not in {n.entity.eid for n in g.frontier()}


def test_non_lookupable_entities_never_enter_the_frontier():
    g, seed = _seeded()
    spki = Entity.make(EntityType.SPKI, "a" * 64)
    g.connect(seed, spki, "presents", Observation("spki-shared", "tls"))
    g.rescore()
    assert spki.eid not in {n.entity.eid for n in g.frontier()}


def test_typosquat_neighbour_is_reported_but_not_crawled():
    g, seed = _seeded()
    squat = Entity.make(EntityType.DOMAIN, "exampIe.com")
    g.connect(seed, squat, "looks-like", Observation("looks-like", "confusables"))
    g.rescore()
    assert squat.eid in g.nodes
    assert squat.eid not in {n.entity.eid for n in g.frontier()}


def test_max_depth_bounds_the_walk():
    g, seed = _seeded()
    prev = seed
    chain = []
    for i in range(6):
        nxt = Entity.make(EntityType.DOMAIN, f"hop{i}.test")
        chain.append(nxt)
        g.connect(prev, nxt, "same-as", Observation("key-fingerprint-shared", "ssh"))
        prev = nxt
    g.rescore()
    assert all(n.depth <= 2 for n in g.frontier(max_depth=2, min_score=0.0))


def test_path_back_to_the_seed_is_reconstructable():
    g, seed = _seeded()
    mid = Entity.make(EntityType.EMAIL, "dev@example.com")
    end = Entity.make(EntityType.USERNAME, "dev")
    g.connect(seed, mid, "contact", Observation("rdap-contact", "domain"))
    g.connect(mid, end, "same-as", Observation("commit-email", "github"))
    g.rescore()
    assert g.path(end.eid) == [seed.eid, mid.eid, end.eid]


def test_merging_a_node_keeps_the_union_of_sources():
    g, seed = _seeded()
    sub = Entity.make(EntityType.DOMAIN, "mail.example.com")
    g.add(sub, source="crtsh")
    g.add(sub, source="dns")
    assert g.nodes[sub.eid].sources == {"crtsh", "dns"}


def test_identical_observations_are_not_double_counted():
    g, seed = _seeded()
    other = Entity.make(EntityType.IP, "203.0.113.5")
    ob = Observation("dns-a", "domain", url="https://dns.google/resolve")
    first = g.connect(seed, other, "resolves-to", ob)
    again = g.connect(seed, other, "resolves-to",
                      Observation("dns-a", "domain", url="https://dns.google/resolve"))
    assert first is again and len(again.observations) == 1


def test_serialisation_round_trips_the_summary():
    g, seed = _seeded()
    ip = Entity.make(EntityType.IP, "203.0.113.5")
    g.connect(seed, ip, "resolves-to", Observation("dns-a", "domain"))
    g.rescore()
    d = g.to_dict()
    assert d["seed"] == seed.eid
    assert d["summary"]["entities"] == 2 and d["summary"]["edges"] == 1
    assert d["summary"]["by_type"]["ip"] == 1
    assert all(math.isfinite(e["llr"]) for e in d["edges"])
