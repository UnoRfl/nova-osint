"""Offline tests for the chronology layer.

Two things are being defended here. The first is that the timeline is built
from what *sources* said, never from when NOVA read them - a chronology of our
own scanning looks exactly like a real one and is worth nothing. The second is
that precision is carried the whole way through, because the cheapest way to
invent an impossibility is to compare a date known to the year against one
known to the day and call the eleven-month gap a contradiction.
"""

from __future__ import annotations

from datetime import datetime, timezone

from nova_osint.core import temporal
from nova_osint.core.contradictions import ContradictionType, Severity
from nova_osint.core.entities import Entity
from nova_osint.core.entities import EntityType as T
from nova_osint.core.graph import EntityGraph, Observation
from nova_osint.core.models import Finding, Investigation, ScanResult, TargetType
from nova_osint.core.temporal import DAY, EventKind

NOW = datetime(2026, 9, 19, tzinfo=timezone.utc).timestamp()


def ts(text: str) -> float:
    parsed = temporal.parse_date(text)
    assert parsed is not None, text
    return parsed[0]


def inv_with(*findings: tuple[str, str], module: str = "github",
             target: str = "unorfl") -> Investigation:
    result = ScanResult(module=module, target=target,
                        target_type=TargetType.USERNAME)
    for label, value in findings:
        result.findings.append(Finding(label=label, value=value, source=module))
    investigation = Investigation(target=target, target_type=TargetType.USERNAME,
                                  started_at=NOW)
    investigation.results.append(result)
    return investigation


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------


def test_precision_is_kept_not_rounded_away():
    assert temporal.parse_date("2025-07-29")[1] == "day"
    assert temporal.parse_date("2025-07")[1] == "month"
    assert temporal.parse_date("created in 2025")[1] == "year"


def test_a_hash_that_starts_with_digits_is_not_a_date():
    """The label gate is what keeps sha256 out of the chronology."""
    line = temporal.build(inv_with(("Fingerprint", "20250729abcdef")))
    assert line.events == []


def test_an_impossible_calendar_date_is_not_a_date():
    assert temporal.parse_date("2024-02-31") is None


def test_epoch_zero_defaults_are_rejected():
    """Badly parsed records leak 1970 and 0001; both are parse artefacts."""
    assert temporal.parse_date("1970-01-01") is None
    assert temporal.parse_date("0001-01-01") is None


# ---------------------------------------------------------------------------
# building
# ---------------------------------------------------------------------------


def test_the_event_kind_comes_from_the_label():
    line = temporal.build(inv_with(
        ("Account created", "2025-07-29"),
        ("Last commit", "2026-09-01"),
        ("Certificate expires", "2027-01-01"),
    ))
    kinds = {e.label: e.kind for e in line.events}
    assert kinds["Account created"] is EventKind.CREATED
    assert kinds["Last commit"] is EventKind.LAST_ACTIVITY
    assert kinds["Certificate expires"] is EventKind.EXPIRES


def test_two_modules_reporting_one_creation_date_is_one_event():
    """A chronology that lists a thing happening twice is worse than useless."""
    investigation = inv_with(("Account created", "2025-07-29"))
    second = ScanResult(module="websearch", target="unorfl",
                        target_type=TargetType.USERNAME)
    second.findings.append(Finding(label="Account created", value="2025-07-29",
                                   source="websearch"))
    investigation.results.append(second)
    line = temporal.build(investigation)
    assert len(line.events) == 1


def test_the_graph_contributes_only_dated_observations():
    """``recorded_at`` is when we read it, and must never reach the timeline."""
    a, b = Entity.make(T.DOMAIN, "a.example"), Entity.make(T.DOMAIN, "b.example")
    graph = EntityGraph(a)
    graph.connect(a, b, "resolved",
                  Observation(kind="passive-dns", module="dns",
                              observed_at=ts("2021-03-04"), recorded_at=NOW))
    graph.connect(a, b, "current",
                  Observation(kind="dns-a", module="dns", recorded_at=NOW))
    investigation = Investigation(target="a.example",
                                  target_type=TargetType.DOMAIN, started_at=NOW)
    investigation.graph = graph
    line = temporal.build(investigation)
    assert [e.iso for e in line.events] == ["2021-03-04"]


def test_as_of_is_the_scan_clock_not_the_wall_clock():
    """Rendered twice, a case must read the same way both times."""
    line = temporal.build(inv_with(("Account created", "2025-07-29")))
    assert line.as_of == NOW


def test_dormancy_is_measured_from_the_scan():
    line = temporal.build(inv_with(("Last commit", "2020-01-01")))
    assert line.dormant
    subject, days = line.dormant[0]
    assert days > temporal.DORMANT_DAYS
    # and measured from the scan, not from today
    assert abs(days - (NOW - ts("2020-01-01")) / DAY) < 1.0


def test_a_recently_active_account_is_not_called_dormant():
    line = temporal.build(inv_with(("Last commit", "2026-09-01")))
    assert line.dormant == []


def test_accounts_created_together_are_flagged_as_a_question():
    investigation = inv_with(("alpha: account created", "2025-07-29"),
                             ("beta: account created", "2025-07-30"))
    line = temporal.build(investigation)
    assert line.clustered
    a, b, gap = line.clustered[0]
    assert {a, b} == {"alpha", "beta"}
    assert gap == 1.0


def test_clustering_never_pairs_a_subject_with_itself():
    investigation = inv_with(("alpha: account created", "2025-07-29"),
                             ("alpha: registered", "2025-07-29"))
    assert temporal.build(investigation).clustered == []


# ---------------------------------------------------------------------------
# conflicts
# ---------------------------------------------------------------------------


def test_activity_before_creation_is_a_high_severity_conflict():
    """An account cannot have committed before it existed."""
    found = temporal.chronology_conflicts(inv_with(
        ("Account created", "2025-07-29"),
        ("First commit", "2019-04-02"),
    ))
    assert len(found) == 1
    assert found[0].type is ContradictionType.CHRONOLOGY
    assert found[0].severity is Severity.HIGH
    assert "renamed" in " ".join(found[0].possible_explanations)


def test_a_year_and_a_day_inside_it_do_not_contradict():
    """Created "in 2019", first commit 2019-04-02. Rounding, not impossibility."""
    assert temporal.chronology_conflicts(inv_with(
        ("Account created", "created in 2019"),
        ("First commit", "2019-04-02"),
    )) == []


def test_two_sources_two_creation_dates_is_a_conflict():
    investigation = inv_with(("Account created", "2025-07-29"))
    second = ScanResult(module="wikidata", target="unorfl",
                        target_type=TargetType.USERNAME)
    second.findings.append(Finding(label="Account created", value="2019-01-05",
                                   source="wikidata"))
    investigation.results.append(second)
    found = temporal.chronology_conflicts(investigation)
    assert [c.severity for c in found] == [Severity.MEDIUM]
    assert {c.source for c in found[0].claims} == {"github", "wikidata"}


def test_one_source_giving_two_dates_is_not_a_source_disagreement():
    """That is a record with two fields, or our own parser. Not a clash."""
    found = temporal.chronology_conflicts(inv_with(
        ("Account created", "2025-07-29"),
        ("Registered", "2019-01-05"),
    ))
    assert found == []


def test_a_bare_investigation_produces_nothing_rather_than_raising():
    empty = Investigation(target="x", target_type=TargetType.UNKNOWN,
                          started_at=NOW)
    assert temporal.build(empty).events == []
    assert temporal.chronology_conflicts(empty) == []
