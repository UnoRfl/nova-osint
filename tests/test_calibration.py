"""Offline tests for the calibration harness.

The harness is the instrument that judges every other number in this project,
so most of these tests are about the instrument being *honest* rather than
being clever: refusing to recommend on thin data, refusing to claim skill it
cannot compute, and noticing an inflated table when it is shown one.

The synthetic corpora are generated from the evidence table itself, so ground
truth is known by construction and no socket is involved.
"""

from __future__ import annotations

import json
import math
import random

import pytest

from nova_osint.calibration_cli import _synthesise
from nova_osint.core.calibration import (
    MIN_CASES,
    Case,
    ObservationSpec,
    evaluate,
    fit,
    load_corpus,
    render_text,
    save_corpus,
)
from nova_osint.core.graph import EVIDENCE


def case(kinds, label, *, hub=0, cid="c", **kw):
    return Case(id=cid, label=label, hub_degree=hub,
                observations=tuple(ObservationSpec(kind=k, module=f"m{i}",
                                                   url=f"https://s{i}.test/")
                                   for i, k in enumerate(kinds)), **kw)


# ---------------------------------------------------------------------------
# it measures the real scoring code, not a copy of it
# ---------------------------------------------------------------------------


def test_a_case_is_scored_by_the_same_edge_the_graph_would_build():
    """A reimplementation here would measure the reimplementation."""
    c = case(["cert-san"], True)
    assert c.predicted() == pytest.approx(
        1.0 / (1.0 + math.exp(-EVIDENCE["cert-san"])), rel=1e-6)


def test_the_independence_discount_is_part_of_what_is_measured():
    """Three kinds off one source must score lower than off three."""
    one_source = Case(id="a", label=True, observations=tuple(
        ObservationSpec(kind=k, module="same", url="https://one.test/")
        for k in ("tracker-id-shared", "favicon-hash", "page-structure-hash")))
    three = case(["tracker-id-shared", "favicon-hash", "page-structure-hash"], True)
    assert one_source.predicted() < three.predicted()


def test_hub_demotion_is_part_of_what_is_measured():
    assert case(["dns-a"], True, hub=200).predicted() < \
        case(["dns-a"], True, hub=0).predicted()


def test_an_aged_observation_is_scored_as_aged():
    fresh = Case(id="f", label=True, observations=(
        ObservationSpec(kind="passive-dns", age_days=1.0),))
    stale = Case(id="s", label=True, observations=(
        ObservationSpec(kind="passive-dns", age_days=2000.0),))
    assert stale.predicted() < fresh.predicted()


# ---------------------------------------------------------------------------
# refusing to say more than the data supports
# ---------------------------------------------------------------------------


def test_a_kind_with_too_few_cases_gets_no_suggested_weight():
    """A table retuned on one afternoon would be worse than the judgements it
    replaced, and would carry the authority of a measurement."""
    cases = [case(["cert-san"], i % 2 == 0, cid=f"c{i}") for i in range(4)]
    report = evaluate(cases)
    suggestion = next(s for s in report.suggestions if s.kind == "cert-san")
    assert suggestion.fitted is None
    assert str(MIN_CASES) in suggestion.reason


def test_a_kind_that_was_always_right_gets_no_weight_either():
    """Perfect separation: the fit runs to infinity and the honest answer is
    that the corpus cannot bound the number."""
    cases = [case(["keybase-proof"], True, cid=f"c{i}") for i in range(40)]
    suggestion = next(s for s in evaluate(cases).suggestions
                      if s.kind == "keybase-proof")
    assert suggestion.fitted is None
    assert "same outcome" in suggestion.reason


def test_a_corpus_of_only_true_links_reports_no_skill_rather_than_bad_skill():
    """The first version called this "WORSE THAN GUESSING".

    It is not. An all-true corpus makes the base-rate baseline perfect by
    construction, so there is nothing for the scores to be better than, and
    saying otherwise insults a table the corpus cannot judge.
    """
    report = evaluate([case(["site-owner"], True, cid=f"c{i}") for i in range(5)])
    assert report.one_sided
    assert report.auc is None
    text = render_text(report)
    assert "WORSE THAN GUESSING" not in text
    assert "nothing for the scores to be better" in text


def test_a_kind_no_table_entry_scores_is_called_out():
    """A module emitting an unscored kind is silently worth 0.1."""
    cases = [case(["invented-by-a-module"], i % 2 == 0, cid=f"c{i}")
             for i in range(20)]
    report = evaluate(cases)
    assert report.unknown_kinds == ["invented-by-a-module"]
    assert "not in the evidence table" in next(
        s.reason for s in report.suggestions if s.kind == "invented-by-a-module")


def test_an_empty_corpus_says_so_rather_than_dividing_by_zero():
    report = evaluate([])
    assert report.cases == 0 and report.problems == ["no cases"]


# ---------------------------------------------------------------------------
# does it notice a table that is wrong?
# ---------------------------------------------------------------------------


def test_a_table_generating_its_own_cases_reads_as_calibrated():
    """If this fails the harness has a sign error or a double-counted discount."""
    report = evaluate(_synthesise(1200, seed=3))
    assert report.ece <= 0.06
    assert report.skill > 0.15
    assert report.auc is not None and report.auc > 0.75


def test_an_inflated_table_reads_as_over_confident():
    """The failure that matters most: claiming more than the evidence bought."""
    honest = evaluate(_synthesise(1200, seed=3))
    inflated = evaluate(_synthesise(1200, seed=5, distort=0.4))
    assert inflated.ece > honest.ece
    high = [b for b in inflated.bins if b.count and b.low >= 0.6]
    assert high, "the inflated corpus should produce confident predictions"
    assert sum(b.predicted - b.observed for b in high) / len(high) > 0.05


def test_the_fit_pulls_inflated_weights_down():
    report = evaluate(_synthesise(1500, seed=9, distort=0.4))
    moved = [s for s in report.suggestions if s.fitted is not None]
    assert moved, "1500 cases should be enough to suggest something"
    assert sum(1 for s in moved if s.shift < 0) >= len(moved) * 0.6


def test_the_fit_has_no_intercept_so_a_lopsided_corpus_cannot_inflate_everything():
    """A free intercept would let the corpus's base rate leak into every kind.

    Feed it cases that are mostly true *regardless* of evidence and the fitted
    weights must not all march upward to explain the base rate.
    """
    rng = random.Random(4)
    kinds = ["name-similarity", "handle-unverified"]
    cases = [case([rng.choice(kinds)], rng.random() < 0.85, cid=f"c{i}")
             for i in range(400)]
    fitted = fit(cases, kinds, prior_strength=1.0)
    assert all(v < 3.0 for v in fitted.values()), fitted


def test_the_prior_keeps_a_small_corpus_from_overturning_the_table():
    kinds = ["cert-san"]
    cases = [case(kinds, i < 2, cid=f"c{i}") for i in range(14)]
    anchored = fit(cases, kinds, prior_strength=1000.0)["cert-san"]
    loose = fit(cases, kinds, prior_strength=0.01)["cert-san"]
    assert abs(anchored - EVIDENCE["cert-san"]) < abs(loose - EVIDENCE["cert-san"])


# ---------------------------------------------------------------------------
# reliability bins and AUC
# ---------------------------------------------------------------------------


def test_the_bins_say_which_direction_the_error_runs():
    report = evaluate(_synthesise(1200, seed=5, distort=0.4))
    used = [b for b in report.bins if b.count]
    assert used
    assert all(0.0 <= b.observed <= 1.0 for b in used)
    assert sum(b.count for b in used) == report.cases


def test_auc_is_one_when_the_ordering_is_perfect():
    cases = ([case(["keybase-proof"], True, cid=f"t{i}") for i in range(10)]
             + [case(["name-similarity"], False, cid=f"f{i}") for i in range(10)])
    assert evaluate(cases).auc == pytest.approx(1.0)


def test_auc_is_a_half_when_every_score_is_identical():
    """Perfectly calibrated and completely useless: only the AUC notices."""
    cases = [case(["dns-ns"], i % 2 == 0, cid=f"c{i}") for i in range(20)]
    assert evaluate(cases).auc == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# the corpus file
# ---------------------------------------------------------------------------


def test_a_corpus_round_trips(tmp_path):
    cases = [case(["cert-san", "dns-a"], True, hub=30, cid="one",
                  basis="checked by hand")]
    path = tmp_path / "c.jsonl"
    save_corpus(cases, path)
    back, problems = load_corpus(path)
    assert not problems
    assert back[0].id == "one" and back[0].hub_degree == 30
    assert back[0].kinds() == {"cert-san", "dns-a"}
    assert back[0].predicted() == pytest.approx(cases[0].predicted())


def test_one_bad_line_does_not_cost_the_rest_of_the_corpus(tmp_path):
    """A corpus is built by hand over months; a stray comma is not data loss."""
    path = tmp_path / "c.jsonl"
    path.write_text(
        "# a comment\n"
        '{"id":"a","label":true,"observations":[{"kind":"cert-san"}]}\n'
        "{oh no\n"
        '{"id":"b","label":false,"observations":[{"kind":"dns-a"}]}\n'
        '{"id":"c","label":true,"observations":[]}\n'
        '{"id":"a","label":true,"observations":[{"kind":"dns-a"}]}\n',
        encoding="utf-8")
    cases, problems = load_corpus(path)
    assert [c.id for c in cases] == ["a", "b"]
    assert len(problems) == 3
    assert any("no observations" in p for p in problems)
    assert any("duplicate" in p for p in problems)


def test_an_unlabelled_row_is_not_quietly_counted_as_false(tmp_path):
    """``label: null`` is what `calibrate export` writes, and it means
    *nobody has adjudicated this yet* - not *this link was fake*."""
    path = tmp_path / "c.jsonl"
    path.write_text(
        '{"id":"a","label":null,"observations":[{"kind":"cert-san"}]}\n',
        encoding="utf-8")
    cases, _ = load_corpus(path)
    # It loads as a case, but the report must not be built from unadjudicated
    # rows - the CLI's export writes null precisely so they stand out.
    assert len(cases) == 1
    assert cases[0].label is False
    assert json.loads(path.read_text())["label"] is None
