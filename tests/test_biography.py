"""Offline tests for the biographical block.

The failure this file exists to prevent is the one it was caught making: fusing
two people who share a name into a single subject born in two different years,
working two unrelated jobs. Every test below is about keeping strangers apart
and about not overstating what a row means.
"""

from __future__ import annotations

import json

import pytest

from nova_osint.core.biography import (
    ATTRIBUTES,
    extract,
    render_html,
    render_text,
)
from nova_osint.core.models import (
    Confidence,
    Investigation,
    ScanResult,
    TargetType,
)


def _inv(rows, target="Matthew Prince", ttype=TargetType.PERSON,
         module="wikidata", confidence=Confidence.CONFIRMED):
    inv = Investigation(target=target, target_type=ttype)
    res = ScanResult(module=module, target=target, target_type=ttype)
    for label, value in rows:
        res.add(label, value, source=module, confidence=confidence)
    inv.results.append(res)
    return inv.finish()


TWO_PEOPLE = [
    ("Matthew Prince: date of birth", "1974-11-13"),
    ("Matthew Prince: occupation", "entrepreneur"),
    ("Matthew Prince: employer", "Cloudflare"),
    ("Matthew Prince: place of birth", "Salt Lake City"),
    ("Matt Prince: date of birth", "1973-07-13"),
    ("Matt Prince: occupation", "professional wrestler"),
    ("Matt Prince: place of birth", "Dallas"),
]


# ---------------------------------------------------------------------------
# keeping strangers apart
# ---------------------------------------------------------------------------


def test_two_people_sharing_a_name_stay_two_people():
    """The bug this module was caught committing, in one test.

    Merged, this produced a subject born in both 1973 and 1974 who was
    simultaneously an entrepreneur and a professional wrestler. Every fact was
    true of somebody; none were true of one body.
    """
    subjects = extract(_inv(TWO_PEOPLE))
    assert len(subjects) == 2
    by_name = {s.name: s for s in subjects}

    founder = {a.label: [v.text for v in a.values]
               for a in by_name["Matthew Prince"].attributes}
    wrestler = {a.label: [v.text for v in a.values]
                for a in by_name["Matt Prince"].attributes}

    assert founder["Date of birth"] == ["1974-11-13"]
    assert wrestler["Date of birth"] == ["1973-07-13"]
    assert founder["Occupation"] == ["entrepreneur"]
    assert wrestler["Occupation"] == ["professional wrestler"]
    assert "Cloudflare" not in str(wrestler)
    assert "Dallas" not in str(founder)


def test_each_candidate_block_is_labelled_as_a_candidate():
    text = render_text(extract(_inv(TWO_PEOPLE)))
    assert "if this is Matthew Prince" in text
    assert "if this is Matt Prince" in text


def test_a_single_subject_needs_no_candidate_heading():
    subjects = extract(_inv([("stated location", "Oslo")], target="alice",
                            ttype=TargetType.USERNAME, module="github"))
    assert len(subjects) == 1 and not subjects[0].candidate
    assert "if this is" not in render_text(subjects)


def test_unprefixed_facts_are_offered_to_every_candidate_not_just_the_first():
    """A fact from scanning the seed belongs to none of them in particular."""
    rows = [*TWO_PEOPLE, ("stated location", "San Francisco")]
    subjects = extract(_inv(rows))
    for subject in subjects:
        based = next(a for a in subject.attributes if a.label == "Based in")
        assert [v.text for v in based.values] == ["San Francisco"]


# ---------------------------------------------------------------------------
# what a row claims
# ---------------------------------------------------------------------------


def test_several_answers_from_one_source_is_not_a_disagreement():
    """Three degrees from one encyclopaedia is multi-valued, not contradictory.

    Crying disagreement here devalues the flag that is supposed to mean
    "somebody is wrong".
    """
    subjects = extract(_inv([
        ("Ada Lovelace: educated at", ["Cambridge", "Oxford", "Imperial"]),
    ]))
    education = next(a for a in subjects[0].attributes if a.label == "Education")
    assert education.multivalued and not education.disputed
    assert "(several)" in render_text(subjects)
    assert "sources disagree" not in render_text(subjects)


def test_two_sources_with_different_answers_is_a_disagreement():
    inv = _inv([("Ada Lovelace: date of birth", "1815-12-10")])
    other = ScanResult(module="github", target="Ada Lovelace",
                       target_type=TargetType.PERSON)
    other.add("Ada Lovelace: date of birth", "1816-01-01", source="github")
    inv.results.append(other)
    dob = next(a for a in extract(inv)[0].attributes if a.label == "Date of birth")
    assert dob.disputed
    assert "sources disagree" in render_text(extract(inv))


def test_agreeing_sources_collapse_to_one_row_that_credits_both():
    inv = _inv([("Ada Lovelace: citizenship", "United Kingdom")])
    other = ScanResult(module="github", target="Ada Lovelace",
                       target_type=TargetType.PERSON)
    other.add("Ada Lovelace: citizenship", "United Kingdom", source="github")
    inv.results.append(other)
    nat = next(a for a in extract(inv)[0].attributes if a.label == "Nationality")
    assert len(nat.values) == 1 and not nat.disputed
    assert "wikidata" in nat.values[0].source and "github" in nat.values[0].source


def test_the_name_row_is_filled_from_the_candidate_it_heads():
    """'Name: not established' under a heading carrying that name is absurd."""
    subjects = extract(_inv(TWO_PEOPLE))
    for subject in subjects:
        name = next(a for a in subject.attributes if a.label == "Name")
        assert [v.text for v in name.values] == [subject.name]


# ---------------------------------------------------------------------------
# honesty about gaps
# ---------------------------------------------------------------------------


def test_the_core_rows_are_printed_even_when_empty():
    """An omitted row reads as 'not relevant'; an empty one reads as 'unknown'."""
    text = render_text(extract(_inv([("stated location", "Oslo")], target="alice",
                                    ttype=TargetType.USERNAME, module="github")))
    for label in ("Name:", "Date of birth:", "Nationality:", "Based in:"):
        assert label in text
    assert "not established" in text


def test_placeholder_values_are_not_treated_as_answers():
    subjects = extract(_inv([("Ada Lovelace: citizenship", "unknown"),
                             ("Ada Lovelace: occupation", "n/a")]))
    nat = next(a for a in subjects[0].attributes if a.label == "Nationality")
    assert not nat.established
    assert not any(a.label == "Occupation" for a in subjects[0].attributes)


def test_self_reported_location_says_it_is_self_reported():
    text = render_text(extract(_inv([("stated location", "Oslo")], target="alice",
                                    ttype=TargetType.USERNAME, module="github")))
    assert "self-reported" in text


def test_a_non_person_target_gets_no_biography():
    """A domain does not have a date of birth."""
    inv = Investigation(target="example.com", target_type=TargetType.DOMAIN).finish()
    assert extract(inv) == []
    assert render_text(extract(inv)) == ""


# ---------------------------------------------------------------------------
# ordering and wiring
# ---------------------------------------------------------------------------


def test_the_attribute_order_is_most_important_first():
    labels = [a[0] for a in ATTRIBUTES]
    assert labels[:5] == ["Name", "Also known as", "Date of birth",
                          "Date of death", "Nationality"]
    assert labels.index("Based in") < labels.index("Occupation")
    assert labels.index("Occupation") < labels.index("Bio")


def test_a_person_profile_leads_with_who_and_ends_with_infrastructure():
    from nova_osint.core.profile import sections_for

    order = [name for name, _k, _n in sections_for("person")]
    assert order[0] == "Identity"
    assert order.index("Accounts") < order.index("Infrastructure")


def test_a_domain_profile_leads_with_infrastructure_instead():
    from nova_osint.core.profile import sections_for

    order = [name for name, _k, _n in sections_for("domain")]
    assert order[0] == "Infrastructure"
    assert order[-1] == "Identity"


def test_the_block_reaches_every_profile_format():
    from nova_osint.core.report import RENDERERS

    inv = _inv(TWO_PEOPLE)
    text = RENDERERS["profile"](inv)
    assert "## WHO" in text and "1974-11-13" in text
    assert text.index("## WHO") < text.index("ASSESSMENT")

    html = RENDERERS["profile-html"](inv)
    assert "Who" in html and "1974-11-13" in html

    payload = json.loads(RENDERERS["profile-json"](inv))
    names = {s["name"] for s in payload["biography"]}
    assert names == {"Matthew Prince", "Matt Prince"}


@pytest.mark.parametrize("bad", ["<script>alert(1)</script>", "a & b"])
def test_html_escapes_attribute_values(bad):
    html = render_html(extract(_inv([("Ada Lovelace: occupation", bad)])))
    assert bad not in html
