"""Offline tests for the brief and identity resolution.

The thing worth protecting here is that the arithmetic stays honest. It is very
easy to write a resolver that always produces a confident-looking winner, and
the whole value of this one is that it produces an unconvincing answer when the
evidence is unconvincing - and says so.
"""

from __future__ import annotations

import pytest

from nova_osint.core.brief import (
    Brief,
    BriefError,
    Claim,
    ClaimKind,
    canonical,
    from_mapping,
    from_pairs,
    parse_pair,
)
from nova_osint.core.entities import Entity, EntityType
from nova_osint.core.graph import EntityGraph, Observation
from nova_osint.core.identity import Verdict, compare, resolve
from nova_osint.core.models import Investigation, ScanResult, TargetType

# ---------------------------------------------------------------------------
# the brief
# ---------------------------------------------------------------------------


def _claim(kind: ClaimKind, value: str, **kw) -> Claim:
    return Claim(kind=kind, value=canonical(kind, value), raw=value, **kw)


def test_a_name_is_the_weakest_identifier_in_the_table() -> None:
    """The tool's whole thesis, as arithmetic.

    If a name ever outweighs a phone number the ranking is worthless, because
    every search result carries the name by construction - it is what was
    searched for.
    """
    name = _claim(ClaimKind.NAME, "Ada Lovelace")
    phone = _claim(ClaimKind.PHONE, "+14155552671")
    email = _claim(ClaimKind.EMAIL, "a@b.com")
    assert name.power.confirm < phone.power.confirm
    assert name.power.confirm < email.power.confirm
    # And a lone given name is weaker still.
    assert _claim(ClaimKind.NAME, "Ada").power.confirm < name.power.confirm


def test_confirming_and_contradicting_are_not_mirror_images() -> None:
    """People change jobs; nobody changes their date of birth.

    Treating disagreement as symmetric with agreement is how a resolver talks
    itself out of the right candidate because a profile is three years stale.
    """
    org = _claim(ClaimKind.ORG, "Acme")
    born = _claim(ClaimKind.BORN, "1815")
    assert abs(org.power.contradict) < org.power.confirm / 4
    assert abs(born.power.contradict) >= born.power.confirm * 0.8


def test_an_uncertain_claim_cannot_bury_a_candidate() -> None:
    sure = _claim(ClaimKind.CITY, "London")
    unsure = _claim(ClaimKind.CITY, "London", certain=False)
    assert unsure.power.confirm == pytest.approx(sure.power.confirm / 2)
    assert unsure.power.contradict == pytest.approx(sure.power.contradict / 2)


def test_a_handle_and_a_domain_are_derived_from_an_address() -> None:
    brief = from_pairs(["email=R.Rafael+news@acme.com"]).expand()
    kinds = {(c.kind, c.value): c for c in brief.claims}
    assert (ClaimKind.USERNAME, "r.rafael") in kinds
    assert (ClaimKind.DOMAIN, "acme.com") in kinds
    assert kinds[(ClaimKind.USERNAME, "r.rafael")].derived_from is ClaimKind.EMAIL


def test_a_free_mail_domain_is_not_derived_as_something_to_investigate() -> None:
    """Deriving gmail.com from an address and scanning it profiles Google."""
    brief = from_pairs(["email=someone@gmail.com"]).expand()
    assert not brief.of(ClaimKind.DOMAIN)
    # The handle is still worth having.
    assert brief.first(ClaimKind.USERNAME) == "someone"


def test_seeds_are_ordered_by_identifying_power() -> None:
    """A budget that runs out must spend itself on the address, not the name."""
    brief = from_pairs(["name=Ada Lovelace", "email=a@b.com", "username=ada"])
    assert brief.seeds[0].kind is ClaimKind.EMAIL
    assert brief.seeds[-1].kind is ClaimKind.NAME


def test_a_fact_stated_directly_outranks_the_same_fact_derived() -> None:
    brief = Brief()
    brief.add(ClaimKind.USERNAME, "ada", derived_from=ClaimKind.EMAIL)
    brief.add(ClaimKind.USERNAME, "ada")
    assert len(brief.of(ClaimKind.USERNAME)) == 1
    assert not brief.of(ClaimKind.USERNAME)[0].derived


def test_unparseable_facts_say_what_to_write_instead() -> None:
    with pytest.raises(BriefError, match="key=value"):
        parse_pair("just some text")
    with pytest.raises(BriefError, match="not something NOVA knows"):
        parse_pair("favourite-colour=blue")


def test_aliases_and_the_uncertainty_marker() -> None:
    assert parse_pair("employer=Acme")[0] is ClaimKind.ORG
    assert parse_pair("dob=1815")[0] is ClaimKind.BORN
    assert parse_pair("lives-in=Cambridge")[0] is ClaimKind.CITY
    assert parse_pair("city?=KL")[2] is False


def test_a_brief_file_may_give_several_values_for_one_fact() -> None:
    brief = from_mapping({"email": ["a@x.com", "b@x.com"], "city": "Cambridge"})
    assert len(brief.of(ClaimKind.EMAIL)) == 2


# ---------------------------------------------------------------------------
# comparison
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind,want,got,expect", [
    # Tags are one mailbox handing out many addresses.
    (ClaimKind.EMAIL, "r+news@acme.com", "r@acme.com", Verdict.CONFIRMS),
    # Compare only as much of a date as both sides state.
    (ClaimKind.BORN, "1815", "1815-12-10", Verdict.CONSISTENT),
    (ClaimKind.BORN, "1815", "1985-01-01", Verdict.CONTRADICTS),
    (ClaimKind.CITY, "Kuala Lumpur", "Kuala Lumpur, Malaysia", Verdict.CONSISTENT),
    (ClaimKind.CITY, "Kuala Lumpur", "London", Verdict.CONTRADICTS),
    # Separators differ between platforms; the same person owns both.
    (ClaimKind.USERNAME, "ryan.rafael", "ryan_rafael", Verdict.CONFIRMS),
    (ClaimKind.COUNTRY, "Malaysia", "United Kingdom", Verdict.CONTRADICTS),
    (ClaimKind.DOMAIN, "acme.com", "mail.acme.com", Verdict.CONSISTENT),
])
def test_comparison_matrix(kind, want, got, expect) -> None:
    assert compare(_claim(kind, want), got)[0] is expect


def test_having_a_second_address_does_not_contradict_having_the_first() -> None:
    """Multi-valued kinds can never contradict on difference alone.

    A person with two email addresses is ordinary. Scoring the second one as
    evidence against them would penalise exactly the well-documented subjects
    the tool is best at.
    """
    assert compare(_claim(ClaimKind.EMAIL, "a@x.com"), "b@x.com")[0] is Verdict.UNKNOWN
    assert compare(_claim(ClaimKind.USERNAME, "ada"), "bob")[0] is Verdict.UNKNOWN


def test_a_missing_keyword_is_never_evidence_against() -> None:
    """People do not list everything true of them in a bio."""
    claim = _claim(ClaimKind.KEYWORD, "rust")
    assert compare(claim, "I write Python")[0] is Verdict.UNKNOWN
    assert claim.power.contradict == 0.0


# ---------------------------------------------------------------------------
# resolution
# ---------------------------------------------------------------------------


def _investigation(subjects: dict[str, list[tuple[str, str]]]) -> Investigation:
    """An investigation whose wikidata module reported these people.

    ``{"Ada (Q1)": [("date of birth", "1815-12-10"), ...]}`` - the label prefix
    is what the biography layer splits on, so this mirrors the real shape.
    """
    inv = Investigation(target="Ada Lovelace", target_type=TargetType.PERSON)
    res = ScanResult(module="wikidata", target="Ada Lovelace",
                     target_type=TargetType.PERSON)
    graph = EntityGraph(Entity.make(EntityType.PERSON, "Ada Lovelace"))
    for who, facts in subjects.items():
        ent = Entity.make(EntityType.PERSON, who)
        graph.add(ent)
        for label, value in facts:
            res.add(f"{who}: {label}", value, source="wikidata")
    inv.results = [res]
    inv.graph = graph
    return inv


def test_the_candidate_matching_more_of_the_brief_wins() -> None:
    inv = _investigation({
        "Ada Lovelace (Q1)": [("date of birth", "1815-12-10"),
                              ("occupation", "mathematician"),
                              ("citizenship", "United Kingdom")],
        "Ada Lovelace (Q2)": [("date of birth", "1974-03-02"),
                              ("occupation", "wrestler")],
    })
    brief = from_pairs(["name=Ada Lovelace", "born=1815", "role=mathematician"])
    res = resolve(inv, brief)

    assert res.leader is not None
    assert res.leader.label.startswith("Ada Lovelace (Q1)")
    # And the wrong one is pushed below zero by the birth year, not merely
    # left behind: a contradicted date of birth is an argument, not a shrug.
    loser = next(c for c in res.candidates if "Q2" in c.label)
    assert loser.score < 0
    assert any(c.verdict is Verdict.CONTRADICTS for c in loser.against)


def test_the_seed_is_not_a_candidate_for_itself() -> None:
    """Otherwise the thing you searched for tops its own results.

    It matches every claim perfectly because the claims are where it came
    from - a tool agreeing with itself and presenting that as evidence.
    """
    inv = _investigation({"Ada Lovelace (Q1)": [("occupation", "mathematician")]})
    res = resolve(inv, from_pairs(["name=Ada Lovelace", "role=mathematician"]))
    assert all(c.label.casefold() != "ada lovelace" for c in res.candidates)


def test_one_weak_match_is_reported_as_weak() -> None:
    inv = _investigation({"Ada Lovelace (Q1)": [("occupation", "mathematician")]})
    res = resolve(inv, from_pairs(["name=Ada Lovelace", "role=mathematician",
                                   "born=1815", "city=London"]))
    assert res.leader is not None
    assert res.leader.answered < len(res.leader.checks)
    assert "not an identification" in res.reading or "weak" in res.reading


def test_a_claim_no_reachable_module_could_answer_is_unchecked_not_unknown() -> None:
    """"Could not look" and "found nothing" stay different answers here too.

    A candidate must not be marked down for a silence that belongs to a rate
    limit rather than to them.
    """
    inv = _investigation({"Ada Lovelace (Q1)": [("occupation", "mathematician")]})
    # born is only answerable by wikidata; drop it from the completed set.
    inv.results[0].degrade(inv.results[0].status.__class__.RATE_LIMITED, "429")
    res = resolve(inv, from_pairs(["name=Ada Lovelace", "born=1815"]))
    cand = res.candidates[0] if res.candidates else None
    assert cand is not None
    born = next(c for c in cand.checks if c.claim.kind is ClaimKind.BORN)
    assert born.verdict is Verdict.UNCHECKED
    assert born.llr == 0.0


def test_a_derived_claim_is_not_counted_as_independent_evidence() -> None:
    """A handle taken from an address is the same observation, not a second.

    Counting both at full weight lets one fact - that you know someone's email
    address - pay out twice, and ten nats of "evidence" turn out to be one
    thing said in two ways.
    """
    def score_for(claim: Claim) -> float:
        inv = _investigation({"Ada Lovelace (Q1)": []})
        person = Entity.make(EntityType.PERSON, "Ada Lovelace (Q1)")
        handle = Entity.make(EntityType.USERNAME, "ada")
        inv.graph.connect(person, handle, "same-as",
                          Observation(kind="keybase-proof", module="keybase"))
        brief = Brief()
        brief.claims = [claim]
        return max(c.score for c in resolve(inv, brief).candidates)

    plain = score_for(_claim(ClaimKind.USERNAME, "ada"))
    derived = score_for(_claim(ClaimKind.USERNAME, "ada",
                               derived_from=ClaimKind.EMAIL))
    assert plain > 0
    assert derived < plain / 2


def test_related_is_not_the_same_as_identical() -> None:
    """A university and a spouse are strong edges and different people.

    Clustering on edge *strength* merged them into the subject, because
    "educated-at" scores well precisely by being well attested. Only evidence
    that one actor controls both ends may merge.
    """
    inv = _investigation({"Ada Lovelace (Q1)": [("occupation", "mathematician")]})
    ada = Entity.make(EntityType.PERSON, "Ada Lovelace (Q1)")
    school = Entity.make(EntityType.ORG, "University of Cambridge")
    inv.graph.add(ada)
    inv.graph.add(school)
    inv.graph.connect(ada, school, "educated-at",
                      Observation(kind="wikidata-claim", module="wikidata"))
    res = resolve(inv, from_pairs(["name=Ada Lovelace", "role=mathematician"]))
    ada_cand = next(c for c in res.candidates if "Q1" in c.label)
    assert "University of Cambridge" not in ada_cand.members


def test_no_brief_means_no_invented_ranking() -> None:
    inv = _investigation({"Ada Lovelace (Q1)": []})
    res = resolve(inv, Brief())
    assert res.candidates == []
    assert "--know" in res.reading
