"""A shared mailbox is not a person, in the graph as well as in the frontier.

``core/addresses.py`` has said since it was written that a role address is
"demoted, not suppressed" and "must never be treated as evidence about" a
person. Only half of that was ever implemented: the pivot decision consulted
it, edge weighting did not. So ``sales@example.com`` appearing on two sites
still scored as identity evidence linking whoever ran them - the precise
failure the module exists to prevent.

What the demotion must *not* do is throw the link away. The sites really do
share a mailbox; a GitHub noreply alias really does belong to the account it
was minted for. Half these tests are about the weight going down and half are
about the edge staying put.
"""

from __future__ import annotations

from nova_osint.core.entities import Entity
from nova_osint.core.entities import EntityType as T
from nova_osint.core.graph import (
    AUTOMATED_ADDRESS_IDENTITY,
    ROLE_ADDRESS_IDENTITY,
    EntityGraph,
    Observation,
    identity_discount,
)


def ent(etype, value):
    made = Entity.make(etype, value)
    assert made is not None, value
    return made


def edge_between(graph, a, b):
    edges = graph.between(a.eid, b.eid)
    assert len(edges) == 1
    return edges[0]


# ---------------------------------------------------------------------------
# the rule
# ---------------------------------------------------------------------------


def test_a_personal_address_is_not_demoted():
    assert identity_discount(ent(T.EMAIL, "j.rafael@example.com"),
                             ent(T.USERNAME, "unorfl")) == 1.0


def test_a_role_address_demotes_an_identity_claim():
    assert identity_discount(ent(T.EMAIL, "sales@example.com"),
                             ent(T.USERNAME, "unorfl")) == ROLE_ADDRESS_IDENTITY


def test_an_automated_address_is_demoted_further_but_not_to_zero():
    """The GitHub alias really is the account's. It just tells you nothing new."""
    factor = identity_discount(
        ent(T.EMAIL, "unorfl@users.noreply.github.com"),
        ent(T.USERNAME, "unorfl"))
    assert factor == AUTOMATED_ADDRESS_IDENTITY
    assert factor > 0.0


def test_the_worst_end_decides():
    assert identity_discount(ent(T.EMAIL, "sales@a.example"),
                             ent(T.EMAIL, "noreply@b.example")) == \
        AUTOMATED_ADDRESS_IDENTITY


def test_a_mailbox_linked_to_a_domain_keeps_its_full_weight():
    """That edge is about infrastructure, and a shared mailbox has plenty."""
    assert identity_discount(ent(T.EMAIL, "sales@example.com"),
                             ent(T.DOMAIN, "example.com")) == 1.0


def test_two_non_email_entities_are_never_touched():
    assert identity_discount(ent(T.USERNAME, "unorfl"),
                             ent(T.PERSON, "Ada Lovelace")) == 1.0


# ---------------------------------------------------------------------------
# in the graph
# ---------------------------------------------------------------------------


def test_the_raw_strength_of_the_observation_is_left_alone():
    """What a source said is a fact about what was seen and stays reportable."""
    mail, user = ent(T.EMAIL, "sales@example.com"), ent(T.USERNAME, "unorfl")
    graph = EntityGraph(mail)
    graph.connect(mail, user, "account",
                  Observation(kind="profile-email", module="github"))
    edge = edge_between(graph, mail, user)
    assert edge.llr == 3.5
    assert edge.effective_llr(2) == 3.5 * ROLE_ADDRESS_IDENTITY


def test_a_shared_mailbox_no_longer_welds_two_handles_together():
    """The scan that prompted this: one role address, two unrelated handles."""
    mail = ent(T.EMAIL, "sales@example.com")
    shop, designer = ent(T.USERNAME, "theshop"), ent(T.USERNAME, "thedesigner")
    graph = EntityGraph(mail)
    for handle in (shop, designer):
        graph.connect(mail, handle, "account",
                      Observation(kind="profile-email", module="web",
                                  url=f"https://{handle.value}.test/"))
    graph.rescore()
    # Still present - the finding is real and stays in the report ...
    assert graph.nodes[shop.eid] is not None
    # ... but nowhere near the relevance a personal address would carry.
    with_role = graph.nodes[shop.eid].score

    personal = ent(T.EMAIL, "j.rafael@example.com")
    other = EntityGraph(personal)
    other.connect(personal, shop, "account",
                  Observation(kind="profile-email", module="web",
                              url="https://theshop.test/"))
    other.rescore()
    assert with_role < other.nodes[shop.eid].score


def test_the_edge_survives_the_demotion():
    mail, user = ent(T.EMAIL, "info@example.com"), ent(T.USERNAME, "unorfl")
    graph = EntityGraph(mail)
    graph.connect(mail, user, "account",
                  Observation(kind="profile-email", module="web"))
    graph.rescore()
    assert user.eid in graph.nodes
    assert graph.nodes[user.eid].score > 0


def test_a_denial_through_a_role_address_is_not_softened():
    """"This site says the handle is free" is just as true whoever asked."""
    mail, user = ent(T.EMAIL, "sales@example.com"), ent(T.USERNAME, "unorfl")
    graph = EntityGraph(mail)
    graph.connect(mail, user, "denied",
                  Observation(kind="explicit-denial", module="username"))
    edge = edge_between(graph, mail, user)
    assert edge.effective_llr(2) == edge.llr == -4.0


def test_the_demotion_is_named_in_the_serialised_edge():
    mail, user = ent(T.EMAIL, "sales@example.com"), ent(T.USERNAME, "unorfl")
    graph = EntityGraph(mail)
    graph.connect(mail, user, "account",
                  Observation(kind="profile-email", module="web"))
    d = edge_between(graph, mail, user).to_dict()
    assert d["identity_factor"] == ROLE_ADDRESS_IDENTITY
    assert "does not identify a person" in d["identity_note"]


def test_an_ordinary_edge_says_nothing_about_identity_factors():
    a, b = ent(T.DOMAIN, "a.example"), ent(T.DOMAIN, "b.example")
    graph = EntityGraph(a)
    graph.connect(a, b, "cert", Observation(kind="cert-san", module="tls"))
    assert "identity_factor" not in edge_between(graph, a, b).to_dict()
