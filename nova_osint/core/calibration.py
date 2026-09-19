"""Measuring the evidence table instead of asserting it.

``graph.EVIDENCE`` says a shared tracker id is worth 5.0 nats and a matching
handle 0.4. Those numbers were chosen carefully and they have never been
*checked*, which the module's own docstring admits: "These are judgements, not
measurements". Every downstream number inherits that - the Admiralty grade, the
frontier ordering, the dossier's confidence, the line in the report that says
*probable*. A tool that reports probabilities it has never scored is asserting
calibration, and asserting calibration is the thing this whole project exists
not to do.

This file closes that loop. Give it cases whose truth somebody adjudicated -
these two really were the same person, these two really were not - and it says:

* **Brier score**, and the skill against just guessing the base rate. A model
  that cannot beat "always say 31%" has no business ordering a request budget.
* **Reliability**, bin by bin. Of the links the tool called 90% likely, how many
  were real? Overconfidence and underconfidence are different diseases and the
  bins tell them apart; a single accuracy number hides both.
* **Discrimination** (AUC). Separate from calibration on purpose: a tool can be
  perfectly calibrated and useless (emit the base rate every time), or sharply
  discriminating and badly scaled. Only the second is fixable by editing a
  table, and the report should say which one you have.
* **A suggested weight per evidence kind**, fitted from the cases.

Why the fit is a logistic regression, and why that is not a coincidence
----------------------------------------------------------------------

The graph already assumes log-odds add across independent evidence. That
assumption *is* the logistic model. So fitting a logistic regression with one
binary-ish feature per evidence kind and no intercept recovers coefficients
that are, exactly and without rescaling, the numbers ``EVIDENCE`` holds. The
harness is not approximating the scoring model - it is the same model, fitted
rather than guessed.

Two deliberate conservatisms:

**It regularises toward the current table**, not toward zero. Forty cases
should nudge a number the authors reasoned about, not overturn it. The prior
strength is a flag, so an operator with three thousand adjudicated links can
turn it down and let their data speak.

**It refuses to recommend on thin evidence.** A kind seen in fewer than
:data:`MIN_CASES` cases gets no suggestion at all, and says so. The failure
mode this guards against is a table retuned on one afternoon's cases, which
would be worse than the judgements it replaced *and* would carry the authority
of a measurement.

Nothing here writes to ``EVIDENCE``. It prints a diff and the operator decides.

Stdlib only, no clock, no socket: a calibration run has to be reproducible from
its corpus or it is not a measurement either.
"""

from __future__ import annotations

import json
import math
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .graph import EVIDENCE, Edge, Observation, probability

__all__ = ["Case", "ObservationSpec", "Report", "Suggestion", "Bin",
           "load_corpus", "save_corpus", "evaluate", "fit", "render_text",
           "MIN_CASES"]

#: Below this many cases mentioning a kind, no weight is suggested for it. A
#: table retuned on a handful of examples would be worse than the judgements it
#: replaced while carrying the authority of a measurement.
MIN_CASES = 12

#: How hard the fit is pulled back toward the existing table, in pseudo-cases.
#: At 25 a kind needs roughly that many real examples before the data
#: outweighs the prior, which is about the point where a proportion stops
#: moving wildly with one more observation.
PRIOR_STRENGTH = 25.0

BINS = 10


# ---------------------------------------------------------------------------
# the corpus
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ObservationSpec:
    """One observation on a labelled case, as it is stored on disk."""

    kind: str
    module: str = ""
    url: str | None = None
    group: str = ""
    age_days: float | None = None

    def to_observation(self) -> Observation:
        """The real :class:`~nova_osint.core.graph.Observation`.

        Built rather than imitated, so the harness measures the code that runs
        in an investigation - the independence discount, the temporal decay and
        the evidence table all included. A reimplementation here would measure
        the reimplementation.
        """
        recorded = observed = None
        if self.age_days is not None:
            recorded, observed = 0.0, -self.age_days * 86400.0
        return Observation(kind=self.kind, module=self.module or "corpus",
                           url=self.url, group=self.group,
                           observed_at=observed, recorded_at=recorded)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": self.kind}
        for name in ("module", "url", "group"):
            if value := getattr(self, name):
                out[name] = value
        if self.age_days is not None:
            out["age_days"] = self.age_days
        return out


@dataclass(frozen=True)
class Case:
    """One adjudicated link: what was observed, and whether it was real."""

    id: str
    label: bool
    observations: tuple[ObservationSpec, ...] = ()
    #: Degree of the busier endpoint, so hub demotion is measured too. A link
    #: through a nameserver with 50,000 customers and a link through a private
    #: one are not the same case and must not be scored as one.
    hub_degree: int = 0
    #: How the truth was established. Required in spirit: an unsourced label is
    #: somebody's recollection, and calibrating against recollection produces a
    #: number that measures the adjudicator.
    basis: str = ""
    note: str = ""

    def edge(self) -> Edge:
        e = Edge("a", "b", "calibration")
        e.observations = [o.to_observation() for o in self.observations]
        return e

    def predicted(self) -> float:
        """What NOVA would say today, as a probability."""
        edge = self.edge()
        return probability(edge.effective_llr(self.hub_degree))

    def kinds(self) -> set[str]:
        return {o.kind for o in self.observations}

    def to_dict(self) -> dict[str, Any]:
        out = {"id": self.id, "label": self.label,
               "observations": [o.to_dict() for o in self.observations]}
        if self.hub_degree:
            out["hub_degree"] = self.hub_degree
        for name in ("basis", "note"):
            if value := getattr(self, name):
                out[name] = value
        return out

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> Case:
        obs = tuple(
            ObservationSpec(
                kind=str(o.get("kind", "")), module=str(o.get("module", "")),
                url=o.get("url"), group=str(o.get("group", "")),
                age_days=(float(o["age_days"]) if o.get("age_days") is not None
                          else None))
            for o in row.get("observations", []) if isinstance(o, dict)
            and o.get("kind"))
        return cls(id=str(row.get("id", "")), label=bool(row.get("label")),
                   observations=obs, hub_degree=int(row.get("hub_degree", 0) or 0),
                   basis=str(row.get("basis", "")), note=str(row.get("note", "")))


def load_corpus(path: Path | str) -> tuple[list[Case], list[str]]:
    """Read a JSONL corpus. Returns the cases and any lines that were rejected.

    A bad line is named and skipped rather than fatal: a corpus is built by
    hand over months, and losing three hundred good adjudications to one stray
    comma would be its own kind of data loss.
    """
    cases: list[Case] = []
    problems: list[str] = []
    seen: set[str] = set()
    text = Path(path).read_text(encoding="utf-8")
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            row = json.loads(line)
        except ValueError as exc:
            problems.append(f"line {n}: {exc}")
            continue
        if not isinstance(row, dict) or "label" not in row:
            problems.append(f"line {n}: not a case (needs at least 'label')")
            continue
        case = Case.from_dict(row)
        if not case.observations:
            problems.append(f"line {n}: case {case.id or '?'} has no observations")
            continue
        if case.id and case.id in seen:
            problems.append(f"line {n}: duplicate id {case.id}")
            continue
        seen.add(case.id)
        cases.append(case)
    return cases, problems


def save_corpus(cases: Iterable[Case], path: Path | str) -> int:
    rows = [json.dumps(c.to_dict(), sort_keys=True) for c in cases]
    Path(path).write_text("\n".join(rows) + "\n", encoding="utf-8")
    return len(rows)


# ---------------------------------------------------------------------------
# metrics
# ---------------------------------------------------------------------------


@dataclass
class Bin:
    """One reliability bucket: what was promised against what happened."""

    low: float
    high: float
    count: int = 0
    predicted: float = 0.0
    observed: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {"range": [round(self.low, 2), round(self.high, 2)],
                "n": self.count, "predicted": round(self.predicted, 3),
                "observed": round(self.observed, 3)}


@dataclass
class Suggestion:
    """What the cases say one evidence kind is worth."""

    kind: str
    current: float
    fitted: float | None = None
    cases: int = 0
    positives: int = 0
    reason: str = ""

    @property
    def shift(self) -> float:
        return 0.0 if self.fitted is None else self.fitted - self.current

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "current": round(self.current, 3),
                "fitted": None if self.fitted is None else round(self.fitted, 3),
                "cases": self.cases, "positives": self.positives,
                "shift": round(self.shift, 3), "reason": self.reason}


@dataclass
class Report:
    """Everything a calibration run measured."""

    cases: int = 0
    base_rate: float = 0.0
    brier: float = 0.0
    brier_baseline: float = 0.0
    ece: float = 0.0
    auc: float | None = None
    bins: list[Bin] = field(default_factory=list)
    suggestions: list[Suggestion] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    unknown_kinds: list[str] = field(default_factory=list)

    @property
    def one_sided(self) -> bool:
        """Every case had the same outcome, so skill and AUC mean nothing.

        A corpus of only-true links makes the base-rate baseline perfect by
        construction, and the skill score then reads ``+0.000`` - which the
        first version of this file rendered as "worse than guessing". It is
        not: there is nothing to be better than. An adjudicator who only
        records the links that turned out real has built a corpus that cannot
        measure anything, and the report has to say that instead of insulting
        the table.
        """
        return self.brier_baseline <= 1e-12

    @property
    def skill(self) -> float:
        """1.0 perfect, 0.0 no better than the base rate, negative = worse."""
        if self.one_sided:
            return 0.0
        return 1.0 - (self.brier / self.brier_baseline)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cases": self.cases, "base_rate": round(self.base_rate, 4),
            "brier": round(self.brier, 4),
            "brier_baseline": round(self.brier_baseline, 4),
            "skill": round(self.skill, 4), "ece": round(self.ece, 4),
            "auc": None if self.auc is None else round(self.auc, 4),
            "bins": [b.to_dict() for b in self.bins],
            "suggestions": [s.to_dict() for s in self.suggestions],
            "problems": self.problems, "unknown_kinds": self.unknown_kinds,
        }


def _reliability(pairs: Sequence[tuple[float, bool]]) -> tuple[list[Bin], float]:
    bins = [Bin(i / BINS, (i + 1) / BINS) for i in range(BINS)]
    for p, y in pairs:
        idx = min(BINS - 1, int(p * BINS))
        b = bins[idx]
        b.count += 1
        b.predicted += p
        b.observed += 1.0 if y else 0.0
    total = len(pairs)
    ece = 0.0
    for b in bins:
        if b.count:
            b.predicted /= b.count
            b.observed /= b.count
            ece += (b.count / total) * abs(b.predicted - b.observed)
    return bins, ece


def _auc(pairs: Sequence[tuple[float, bool]]) -> float | None:
    """Mann-Whitney U: the chance a real link outscores a false one.

    Reported apart from the Brier score because they answer different
    questions. A tool that emits the base rate for everything is perfectly
    calibrated and completely useless, and only the AUC notices.
    """
    pos = [p for p, y in pairs if y]
    neg = [p for p, y in pairs if not y]
    if not pos or not neg:
        return None
    ranked = sorted(range(len(pairs)), key=lambda i: pairs[i][0])
    ranks = [0.0] * len(pairs)
    i = 0
    while i < len(ranked):
        j = i
        while j + 1 < len(ranked) and pairs[ranked[j + 1]][0] == pairs[ranked[i]][0]:
            j += 1
        shared = (i + j) / 2.0 + 1.0            # average rank, 1-based
        for k in range(i, j + 1):
            ranks[ranked[k]] = shared
        i = j + 1
    rank_sum = sum(r for r, (_, y) in zip(ranks, pairs) if y)
    return (rank_sum - len(pos) * (len(pos) + 1) / 2.0) / (len(pos) * len(neg))


# ---------------------------------------------------------------------------
# the fit
# ---------------------------------------------------------------------------


def _features(case: Case, kinds: Sequence[str]) -> list[float]:
    """How much of each kind this case carries, after the edge's own discounts.

    Not a count. The edge halves repeated kinds and repeated sources, and the
    hub divides the total, so the feature is the weight that kind actually
    contributes - which keeps the fitted coefficient in the same units as the
    table it is going to be compared against.
    """
    edge = case.edge()
    weights = edge.weights()
    totals: Counter[str] = Counter()
    for ob, w in zip(edge.observations, weights):
        # Strength over raw strength recovers the temporal decay factor without
        # re-deriving it here; a kind with no table entry contributes its shape
        # but not a second opinion about its size.
        base = ob.raw_strength
        decay = (ob.strength / base) if base else 1.0
        totals[ob.kind] += w * decay
    scale = 1.0
    if case.hub_degree > 2:
        scale = 1.0 / (1.0 + math.log(case.hub_degree / 2.0))
    return [totals.get(k, 0.0) * scale for k in kinds]


def fit(cases: Sequence[Case], kinds: Sequence[str], *,
        prior_strength: float = PRIOR_STRENGTH,
        iterations: int = 600, rate: float = 0.08) -> dict[str, float]:
    """Logistic regression, no intercept, regularised toward the current table.

    No intercept on purpose: the graph's model says an edge with no evidence is
    at log-odds zero, and fitting a free intercept would let the corpus's own
    base rate leak into every score - so a corpus of mostly-true cases would
    make *every* kind look stronger.
    """
    if not cases or not kinds:
        return {}
    rows = [(_features(c, kinds), 1.0 if c.label else 0.0) for c in cases]
    prior = [EVIDENCE.get(k, 0.0) for k in kinds]
    coef = list(prior)
    n = float(len(rows))
    lam = prior_strength / n if n else 0.0

    # The ridge term's own gradient is ``lam * (coef - prior)``, so a fixed
    # step diverges the moment ``rate * lam`` approaches 2 - which a strong
    # prior on a small corpus reaches easily, and which produced NaN weights
    # rather than the conservative answer the prior was there to give. Scaling
    # the step by the curvature keeps that branch stable, and a strong prior
    # now does what it says: it holds the fit near the current table.
    step = rate / (1.0 + lam)

    for _ in range(iterations):
        grad = [0.0] * len(kinds)
        for x, y in rows:
            z = sum(c * xi for c, xi in zip(coef, x))
            p = 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, z))))
            err = p - y
            for j, xi in enumerate(x):
                if xi:
                    grad[j] += err * xi
        for j in range(len(kinds)):
            grad[j] = grad[j] / n + lam * (coef[j] - prior[j])
            coef[j] -= step * grad[j]
        if not all(math.isfinite(c) for c in coef):
            # Returning the table unchanged is the honest failure: a diverged
            # fit must never be printed as a measurement.
            return dict(zip(kinds, prior))
    return dict(zip(kinds, coef))


# ---------------------------------------------------------------------------
# the run
# ---------------------------------------------------------------------------


def evaluate(cases: Sequence[Case], *, prior_strength: float = PRIOR_STRENGTH,
             min_cases: int = MIN_CASES) -> Report:
    """Score the current table against a corpus and say what to change."""
    report = Report(cases=len(cases))
    if not cases:
        report.problems.append("no cases")
        return report

    pairs = [(c.predicted(), c.label) for c in cases]
    report.base_rate = sum(1 for _, y in pairs if y) / len(pairs)
    report.brier = sum((p - (1.0 if y else 0.0)) ** 2 for p, y in pairs) / len(pairs)
    base = report.base_rate
    report.brier_baseline = sum((base - (1.0 if y else 0.0)) ** 2
                                for _, y in pairs) / len(pairs)
    report.bins, report.ece = _reliability(pairs)
    report.auc = _auc(pairs)

    counts: Counter[str] = Counter()
    positives: Counter[str] = Counter()
    for case in cases:
        for kind in case.kinds():
            counts[kind] += 1
            if case.label:
                positives[kind] += 1
    report.unknown_kinds = sorted(k for k in counts if k not in EVIDENCE)

    fittable = sorted(k for k in counts if k in EVIDENCE)
    fitted = fit(cases, fittable, prior_strength=prior_strength)
    for kind in sorted(counts):
        current = EVIDENCE.get(kind)
        if current is None:
            report.suggestions.append(Suggestion(
                kind, 0.0, None, counts[kind], positives[kind],
                "not in the evidence table - a module is emitting a kind "
                "nothing scores, and it is being taken as 0.1 by default"))
            continue
        if counts[kind] < min_cases:
            report.suggestions.append(Suggestion(
                kind, current, None, counts[kind], positives[kind],
                f"only {counts[kind]} case(s); {min_cases} needed before a "
                f"measurement beats the judgement it would replace"))
            continue
        if positives[kind] == 0 or positives[kind] == counts[kind]:
            # Perfect separation: the fit runs away to infinity and the honest
            # answer is "this kind has never been seen to be wrong here", which
            # is a statement about the corpus, not about the weight.
            report.suggestions.append(Suggestion(
                kind, current, None, counts[kind], positives[kind],
                "every case with this kind had the same outcome; the corpus "
                "cannot bound the weight, only widen it"))
            continue
        report.suggestions.append(Suggestion(
            kind, current, fitted.get(kind), counts[kind], positives[kind]))

    report.suggestions.sort(key=lambda s: -abs(s.shift))
    return report


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def _verdict(report: Report) -> list[str]:
    """Calibration and discrimination are different diseases. Name which."""
    out: list[str] = []
    if report.one_sided:
        side = "real" if report.base_rate >= 0.5 else "false"
        out.append(f"Every case in this corpus was a {side} link, so there is "
                   f"nothing for the scores to be better *than*. Skill and AUC "
                   f"cannot be computed. Add cases that went the other way - a "
                   f"corpus of only the links that turned out real measures "
                   f"nothing.")
        return out
    if report.skill <= 0:
        out.append("WORSE THAN GUESSING. The scores carry no information the "
                   "base rate did not already have.")
    elif report.skill < 0.15:
        out.append("Barely better than guessing the base rate.")
    if report.auc is not None:
        if report.auc >= 0.85:
            out.append(f"Discrimination is good (AUC {report.auc:.2f}): real "
                       f"links do outrank false ones.")
        elif report.auc >= 0.65:
            out.append(f"Discrimination is fair (AUC {report.auc:.2f}).")
        else:
            out.append(f"Discrimination is poor (AUC {report.auc:.2f}): the "
                       f"ordering is close to arbitrary, and no amount of "
                       f"retuning the table fixes that - the evidence kinds "
                       f"themselves are not separating these cases.")
    if report.ece > 0.10:
        over = sum(1 for b in report.bins if b.count and b.predicted > b.observed)
        under = sum(1 for b in report.bins if b.count and b.predicted < b.observed)
        lean = "over-confident" if over > under else "under-confident"
        out.append(f"Calibration is off by {report.ece:.0%} on average, "
                   f"mostly {lean}.")
    elif report.ece <= 0.05:
        out.append(f"Calibration is close ({report.ece:.0%} mean error).")
    return out


def render_text(report: Report, *, width: int = 78) -> str:
    lines = ["calibration", "=" * 11, ""]
    lines.append(f"cases            {report.cases}"
                 f"   ({report.base_rate:.0%} of them were real links)")
    lines.append(f"Brier            {report.brier:.4f}"
                 f"   (base rate alone: {report.brier_baseline:.4f})")
    lines.append("skill            "
                 + ("n/a - every case had the same outcome" if report.one_sided
                    else f"{report.skill:+.3f}   (1.0 perfect, 0.0 no better "
                         f"than the base rate)"))
    lines.append(f"calibration err  {report.ece:.4f}   mean gap between "
                 f"promised and observed")
    lines.append(f"AUC              "
                 + ("n/a - the corpus has only one outcome"
                    if report.auc is None else f"{report.auc:.4f}"))
    lines.append("")

    for line in _verdict(report):
        lines.append(f"  {line}")
    if report.problems:
        lines.append("")
        for p in report.problems[:10]:
            lines.append(f"  corpus problem: {p}")

    lines += ["", "reliability", "-" * 11,
              "  of the links NOVA called X% likely, how many were real",
              ""]
    lines.append(f"  {'promised':<14}{'n':>6}  {'said':>7}  {'was':>7}   gap")
    for b in report.bins:
        if not b.count:
            continue
        gap = b.predicted - b.observed
        mark = "  ok" if abs(gap) <= 0.1 else ("  over" if gap > 0 else "  under")
        lines.append(f"  {b.low:.0%}-{b.high:.0%}".ljust(16)
                     + f"{b.count:>6}  {b.predicted:>6.1%}  {b.observed:>6.1%}"
                     + f"  {gap:+.2f}{mark}")

    lines += ["", "suggested weights", "-" * 17,
              "  nothing here is applied. Edit graph.EVIDENCE yourself, or do not.",
              ""]
    lines.append(f"  {'kind':<28}{'now':>7}{'fitted':>9}{'shift':>8}"
                 f"{'n':>6}  note")
    for s in report.suggestions:
        if s.fitted is None:
            lines.append(f"  {s.kind:<28}{s.current:>7.2f}{'-':>9}{'-':>8}"
                         f"{s.cases:>6}  {s.reason}")
        else:
            flag = "  <-- worth a look" if abs(s.shift) >= 0.5 else ""
            lines.append(f"  {s.kind:<28}{s.current:>7.2f}{s.fitted:>9.2f}"
                         f"{s.shift:>+8.2f}{s.cases:>6}{flag}")
    if report.unknown_kinds:
        lines += ["", "  kinds no table entry scores (worth 0.1 by default):"]
        lines += [f"    {k}" for k in report.unknown_kinds]
    return "\n".join(lines)
