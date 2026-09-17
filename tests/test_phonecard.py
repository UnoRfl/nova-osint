"""Offline tests for the phone answer card.

Two things are being protected here. The first is the verdict logic: an
unallocated number means a spoofed caller ID, and that has to be the loudest
thing on the card. The second is the boundary - the card must never let a
reader infer that the absence of a subscriber name means the number is
unlisted, when it actually means NOVA had no lawful way to look.
"""

from __future__ import annotations

import argparse
import json

import pytest

from nova_osint.core.entities import Entity, EntityType
from nova_osint.core.graph import EntityGraph, Observation
from nova_osint.core.models import (
    Investigation,
    ModuleStatus,
    ScanResult,
    TargetType,
)
from nova_osint.core.phonecard import NAME_NOTE, build, render_json, render_text
from nova_osint.core.store import CaseStore


def _inv(number="+442079460958", **values):
    inv = Investigation(target=number, target_type=TargetType.PHONE)
    res = ScanResult(module="phone", target=number, target_type=TargetType.PHONE)
    defaults = {
        "valid": "yes", "E.164": number, "international": "+44 20 7946 0958",
        "country code": "+44", "region": "London", "line type": "fixed line",
        "carrier at allocation": "", "timezone(s)": ["Europe/London"],
    }
    defaults.update(values)
    for label, value in defaults.items():
        if value != "":
            res.add(label, value, source="libphonenumber")
    res.add("check manually: WhatsApp", f"https://wa.me/{number.lstrip('+')}",
            source="link")
    inv.results.append(res)
    return inv.finish()


# ---------------------------------------------------------------------------
# the verdict
# ---------------------------------------------------------------------------


def test_a_normal_number_reads_as_one_line():
    card = build(_inv(**{"carrier at allocation": "BT"}))
    assert card.verdict == "fixed line / BT / London"
    assert card.risk == "low"


def test_an_unallocated_number_is_the_loudest_thing_on_the_card():
    """A caller ID showing an unallocated number was forged. Say so first."""
    card = build(_inv(valid="no - not an allocated number"))
    assert card.risk == "high"
    assert card.verdict.startswith("NOT A REAL NUMBER")
    assert "spoofing the caller ID" in card.risk_notes[0]
    text = render_text(card)
    assert text.index("NOT A REAL NUMBER") < text.index("LINE")
    assert "spoofing the caller ID" in _flat(text)


def test_voip_is_flagged_as_a_weak_identity_signal():
    card = build(_inv(**{"line type": "VoIP"}))
    assert card.risk == "medium"
    assert "cheap to obtain and discard" in " ".join(card.risk_notes)


def test_premium_rate_warns_about_the_cost_to_the_caller():
    card = build(_inv(**{"line type": "premium rate"}))
    assert card.risk == "high"
    assert "charges you" in " ".join(card.risk_notes)


def test_a_business_line_is_not_treated_as_a_person():
    for kind in ("toll free", "shared cost", "UAN"):
        card = build(_inv(**{"line type": kind}))
        notes = " ".join(card.risk_notes)
        assert card.risk == "low"
        assert "business" in notes or "organisation" in notes, kind


def test_risk_notes_describe_the_line_never_its_owner():
    """A disposable line is a fact about the line, not about who answers it."""
    notes = " ".join(build(_inv(**{"line type": "VoIP"})).risk_notes).lower()
    for accusation in ("scammer", "fraudster", "criminal", "spam caller"):
        assert accusation not in notes


def test_a_missing_library_is_reported_rather_than_guessed_around():
    inv = _inv()
    inv.results[0].add("library", "phonenumbers not installed", source="local")
    card = build(inv)
    assert card.risk == "unknown"
    assert "phonenumbers is not installed" in " ".join(card.risk_notes)
    assert "install phonenumbers" in card.verdict


# ---------------------------------------------------------------------------
# the boundary
# ---------------------------------------------------------------------------


def _flat(text: str) -> str:
    """Collapse the card's wrapping, so a phrase can be asserted across lines."""
    return " ".join(text.split())


def test_the_card_states_that_it_cannot_name_the_subscriber():
    """Silence here reads as 'unlisted', which is a different claim."""
    text = _flat(render_text(build(_inv())))
    assert "NOT KNOWN" in text
    assert "cannot tell you the subscriber" in text
    assert "no lawful way to look" in text


def test_the_json_carries_the_same_caveat_not_just_a_null():
    payload = json.loads(render_json(build(_inv())))
    assert payload["subscriber_name"] is None
    assert payload["subscriber_name_note"] == NAME_NOTE
    assert "harvesting" in payload["subscriber_name_note"]


def test_manual_check_links_are_offered_not_followed():
    card = build(_inv())
    assert dict(card.links)["WhatsApp"].startswith("https://wa.me/")


# ---------------------------------------------------------------------------
# your own contact book
# ---------------------------------------------------------------------------


@pytest.fixture()
def store(tmp_path):
    with CaseStore(tmp_path / "cases") as s:
        yield s


def _case_containing_the_number(store, number="+442079460958",
                                target="example.com", case_id="c1"):
    seed = Entity.make(EntityType.DOMAIN, target)
    phone = Entity.make(EntityType.PHONE, number)
    email = Entity.make(EntityType.EMAIL, "alice@example.com")
    g = EntityGraph(seed)
    g.connect(seed, phone, "contact", Observation("rdap-contact", "whois"))
    g.connect(phone, email, "same-contact", Observation("rdap-contact", "whois"))
    g.rescore()
    inv = Investigation(target=target, target_type=TargetType.DOMAIN).finish()
    return store.save(inv, g, case_id=case_id)


def test_a_number_seen_in_an_earlier_case_is_reported(store):
    _case_containing_the_number(store)
    card = build(_inv(), store)
    assert card.seen_before
    case_id, _when, target, context = card.seen_before[0]
    assert case_id == "c1" and target == "example.com"
    assert "alice@example.com" in context, "say what it sat next to"


def test_the_card_says_plainly_when_it_has_never_seen_the_number(store):
    card = build(_inv(), store)
    assert card.seen_before == []
    assert "never, in any saved case" in render_text(card)


def test_the_lookup_matches_on_the_canonical_form_not_the_typing(store):
    """+44 20 7946 0958 and +442079460958 are the same number."""
    _case_containing_the_number(store, number="+44 20 7946 0958")
    card = build(_inv(number="+442079460958"), store)
    assert card.seen_before


def test_a_broken_store_costs_the_history_not_the_card():
    class Broken:
        def seen_elsewhere(self, entity):
            raise RuntimeError("database is gone")

    card = build(_inv(), Broken())
    assert card.seen_before == []
    assert card.verdict, "the rest of the card still renders"


# ---------------------------------------------------------------------------
# wiring
# ---------------------------------------------------------------------------


def test_coverage_gaps_reach_the_card():
    inv = _inv()
    inv.results[0].status = ModuleStatus.PARTIAL
    inv.results[0].status_reason = "a source timed out"
    card = build(inv)
    assert any("timed out" in g for g in card.gaps)
    assert "COVERAGE GAPS" in render_text(card)


def test_the_card_renderer_is_registered_for_scan():
    from nova_osint.core.report import RENDERERS

    assert "card" in RENDERERS
    assert "NOT KNOWN" in RENDERERS["card"](_inv())


def test_cmd_phone_records_the_lookup_in_the_audit_chain(store, capsys, monkeypatch):
    from nova_osint import commands
    from nova_osint.core.config import Config

    monkeypatch.setattr(commands, "__name__", commands.__name__)
    args = argparse.Namespace(number="+442079460958", format="card", output=None)
    code = commands.cmd_phone(args, Config(cache_dir=None), store)
    assert code == 0
    entries = store.audit.entries()
    assert entries[-1]["action"] == "phone-lookup"
    assert entries[-1]["number"] == "+442079460958"
    assert store.audit.verify()[0]
    assert "NOT KNOWN" in capsys.readouterr().out
