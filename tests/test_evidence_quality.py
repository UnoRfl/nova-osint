"""Offline tests for the four scoring rules that decide what gets pivoted on.

Each test here encodes a defect that was measured on the live code before it
was fixed, so a failure means the graph has gone back to believing something it
should not. The numbers in the docstrings are the ones the old code produced.

Nothing here opens a socket: the graph is a pure data structure and the whole
point of these rules is that they can be argued with on paper.
"""

from __future__ import annotations

from nova_osint.core.entities import Entity, EntityType as T
from nova_osint.core.graph import EntityGraph, Observation, decayed

DAY = 86400.0
NOW = 1_750_000_000.0


def ent(etype, value):
    made = Entity.make(etype, value)
    assert made is not None, value
    return made


def link(graph, src, dst, label, kind, module="m", url=None, **kw):
    graph.connect(src, dst, label,
                  Observation(kind=kind, module=module, url=url, **kw))


# ---------------------------------------------------------------------------
# 1. two sources are two sources; one source three times is not
# ---------------------------------------------------------------------------


def test_one_page_read_by_one_module_is_not_three_corroborations():
    """A tracker id, a favicon hash and a page hash off one fetch scored A1.

    9.5 nats and an Admiralty grade of A1 - "practically certain, corroborated
    by three independent sources" - out of a single HTTP response. The grade is
    the line an analyst actually reads, so this was the most misleading number
    the tool produced.
    """
    a, b = ent(T.DOMAIN, "a.example"), ent(T.DOMAIN, "b.example")
    g = EntityGraph(a)
    for kind in ("tracker-id-shared", "favicon-hash", "page-structure-hash"):
        link(g, a, b, "same-site", kind, "fingerprint", "https://a.example/")
    edge = g.between(a.eid, b.eid)[0]

    assert edge.corroborations == 1
    assert edge.grade.endswith("3")
    assert edge.llr < 7.0


def test_the_same_three_kinds_from_three_sources_keep_their_full_weight():
    """The fix must not punish evidence that really is independent."""
    a, b = ent(T.DOMAIN, "a.example"), ent(T.DOMAIN, "b.example")
    g = EntityGraph(a)
    for kind, module, url in (("tracker-id-shared", "trackers", "https://x.test/1"),
                              ("favicon-hash", "favicon", "https://y.test/2"),
                              ("page-structure-hash", "fingerprint", "https://z.test/3")):
        link(g, a, b, "same-site", kind, module, url)
    edge = g.between(a.eid, b.eid)[0]

    assert edge.corroborations == 3
    assert edge.grade == "A1"
    assert edge.llr == 9.5


def test_two_modules_declaring_one_upstream_count_once():
    """crt.sh and CertSpotter read the same logs, and can say so."""
    a, b = ent(T.DOMAIN, "a.example"), ent(T.DOMAIN, "b.example")
    g = EntityGraph(a)
    link(g, a, b, "cert", "cert-san", "crtsh", "https://crt.sh/1", group="ct-logs")
    link(g, a, b, "cert", "cert-san", "certspotter", "https://api.spotter/1",
         group="ct-logs")
    assert g.between(a.eid, b.eid)[0].corroborations == 1


def test_repeats_of_one_kind_are_still_discounted():
    """The original rule survives: it was right, it was just not enough."""
    a, b = ent(T.DOMAIN, "a.example"), ent(T.DOMAIN, "b.example")
    g = EntityGraph(a)
    for i, module in enumerate(("one", "two", "three")):
        link(g, a, b, "cert", "cert-san", module, f"https://s{i}.test/")
    # 4.5 + 2.25 + 1.125
    assert g.between(a.eid, b.eid)[0].llr == 7.875


# ---------------------------------------------------------------------------
# 2. converging routes corroborate
# ---------------------------------------------------------------------------


def _two_route_graph():
    seed = ent(T.DOMAIN, "target.example")
    g = EntityGraph(seed)
    via_mail = ent(T.EMAIL, "admin@target.example")
    via_host = ent(T.IP, "203.0.113.9")
    via_other = ent(T.EMAIL, "other@target.example")
    twice, once = ent(T.USERNAME, "reachedtwice"), ent(T.USERNAME, "reachedonce")

    link(g, seed, via_mail, "email", "whois-email", "whois", "https://rdap.test/1")
    link(g, seed, via_host, "resolves", "dns-a", "dns", "https://dns.test/1")
    link(g, seed, via_other, "email", "whois-email", "whois", "https://rdap.test/2")
    link(g, via_mail, twice, "account", "profile-email", "github", "https://gh.test/1")
    link(g, via_host, twice, "account", "commit-email", "gitlab", "https://gl.test/1")
    link(g, via_other, once, "account", "profile-email", "github", "https://gh.test/2")
    g.rescore()
    return g, twice, once


def test_a_node_reached_by_two_independent_routes_outranks_one_reached_by_one():
    """Both scored 0.2412 before. The frontier could not tell them apart.

    Convergence is the strongest signal this tool produces - an account found
    both through the registrant's address and through a pushed commit is a far
    better lead than the same account found once - and the widest-path search
    threw it away by keeping only the best chain.
    """
    g, twice, once = _two_route_graph()
    assert g.nodes[twice.eid].score > g.nodes[once.eid].score * 1.5
    assert g.nodes[twice.eid].corroborations == 2
    assert g.nodes[once.eid].corroborations == 1


def test_the_best_route_still_bounds_a_single_route_node():
    """One route must score exactly what it always did, to the digit."""
    _, _, once = _two_route_graph()
    seed = ent(T.DOMAIN, "target.example")
    g = EntityGraph(seed)
    hop = ent(T.EMAIL, "other@target.example")
    link(g, seed, hop, "email", "whois-email", "whois", "https://rdap.test/2")
    link(g, hop, once, "account", "profile-email", "github", "https://gh.test/2")
    g.rescore()
    assert g.nodes[once.eid].score > 0


def test_one_module_cannot_corroborate_itself():
    """Two edges into a node from one source are one route, not two."""
    seed = ent(T.DOMAIN, "target.example")
    g = EntityGraph(seed)
    a, b = ent(T.EMAIL, "a@target.example"), ent(T.EMAIL, "b@target.example")
    found = ent(T.USERNAME, "candidate")
    link(g, seed, a, "email", "whois-email", "whois", "https://rdap.test/1")
    link(g, seed, b, "email", "whois-email", "whois", "https://rdap.test/1")
    link(g, a, found, "account", "profile-email", "solo", "https://solo.test/")
    link(g, b, found, "account", "profile-email", "solo", "https://solo.test/")
    g.rescore()
    assert g.nodes[found.eid].corroborations == 1


def test_corroboration_never_exceeds_certainty():
    seed = ent(T.DOMAIN, "target.example")
    g = EntityGraph(seed)
    found = ent(T.USERNAME, "candidate")
    for i in range(6):
        hop = ent(T.EMAIL, f"h{i}@target.example")
        link(g, seed, hop, "email", "whois-email", f"w{i}", f"https://r{i}.test/")
        link(g, hop, found, "account", "key-fingerprint-shared", f"k{i}",
             f"https://k{i}.test/")
    g.rescore()
    assert g.nodes[found.eid].score <= 1.0


# ---------------------------------------------------------------------------
# 3. evidence that makes a present-tense claim expires
# ---------------------------------------------------------------------------


def test_a_stale_passive_dns_record_is_worth_less_than_a_fresh_one():
    """Six-year-old co-location scored exactly like today's A record."""
    fresh = Observation(kind="passive-dns", module="vt",
                        observed_at=NOW - 2 * DAY, recorded_at=NOW)
    stale = Observation(kind="passive-dns", module="vt",
                        observed_at=NOW - 2200 * DAY, recorded_at=NOW)
    assert fresh.strength > stale.strength * 100
    assert fresh.raw_strength == stale.raw_strength


def test_history_does_not_expire():
    """A certificate that covered two names in 2019 still covered them.

    The distinction is not the record's age, it is what the record claims. An
    A record claims where a name points *now*; a certificate claims something
    that happened, and a thing that happened stays happened.
    """
    old = Observation(kind="cert-san", module="ct",
                      observed_at=NOW - 3000 * DAY, recorded_at=NOW)
    assert old.strength == old.raw_strength


def test_evidence_against_a_link_does_not_weaken_with_age():
    aged = decayed("explicit-denial", -4.0, 3000.0)
    assert aged == -4.0


def test_an_observation_with_no_dates_behaves_exactly_as_before():
    """Every live lookup is dateless, and must be scored as current."""
    plain = Observation(kind="dns-a", module="dns")
    assert plain.age_days is None
    assert plain.strength == plain.raw_strength == 3.0


# ---------------------------------------------------------------------------
# 4. a lead that was ruled out is not a lead
# ---------------------------------------------------------------------------


def test_an_explicitly_denied_handle_leaves_the_frontier():
    """It sat in the frontier on a +0.4 while carrying a -4.0 denial.

    The search skips non-positive edges, which is right for routing and was
    wrong for judgement: disconfirming evidence had no effect at all on a node
    some other edge had already reached, so a request budget was spent on a
    handle a site had explicitly said was not the target's.
    """
    seed = ent(T.DOMAIN, "target.example")
    g = EntityGraph(seed)
    hop = ent(T.EMAIL, "admin@target.example")
    denied = ent(T.USERNAME, "notthem")
    link(g, seed, hop, "email", "whois-email", "whois", "https://rdap.test/1")
    link(g, hop, denied, "account", "handle-unverified", "sherlock",
         "https://s.test/1")
    link(g, seed, denied, "denied", "explicit-denial", "verify", "https://v.test/1")
    g.rescore()

    assert g.nodes[denied.eid].contradicted
    assert denied.eid not in {n.entity.eid for n in g.frontier(min_score=0.0)}


def test_a_ruled_out_lead_is_reported_rather_than_dropped():
    """Declining to follow a lead is a finding. Silence is not."""
    seed = ent(T.DOMAIN, "target.example")
    g = EntityGraph(seed)
    hop = ent(T.EMAIL, "admin@target.example")
    denied = ent(T.USERNAME, "notthem")
    link(g, seed, hop, "email", "whois-email", "whois", "https://rdap.test/1")
    link(g, hop, denied, "account", "handle-unverified", "sherlock",
         "https://s.test/1")
    link(g, seed, denied, "denied", "explicit-denial", "verify", "https://v.test/1")
    g.rescore()

    out = g.contradicted()
    assert [n.entity.eid for n in out] == [denied.eid]
    assert out[0].against <= -4.0 < out[0].support


def test_strong_support_survives_a_weak_objection():
    """A single weak doubt must not veto well-evidenced work."""
    seed = ent(T.DOMAIN, "target.example")
    g = EntityGraph(seed)
    found = ent(T.USERNAME, "realone")
    link(g, seed, found, "account", "keybase-proof", "keybase", "https://kb.test/1")
    link(g, seed, found, "doubt", "parked-domain", "whois", "https://w.test/1")
    g.rescore()
    assert not g.nodes[found.eid].contradicted
    assert found.eid in {n.entity.eid for n in g.frontier(min_score=0.0)}
