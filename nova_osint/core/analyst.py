"""The analyst's note: what NOVA actually thinks, said in sentences.

Every other renderer in this project answers a question with a table. Tables
are right for evidence and wrong for conclusions, because a reader handed eight
ranked rows and forty log-odds has been given the *working* and left to do the
last step themselves - and the last step is the one they came for.

So this says it outright. Conclusion first, then why, then what argues against
it, then what nobody could check, then what to do next. It is written in the
first person because a hedge in the first person is honest ("I cannot separate
these two") where the same hedge in the passive voice reads as a malfunction
("the candidates could not be separated").

The three rules
---------------

**Never claim more than the arithmetic.** Every confidence word here is derived
from the score and the margin, not chosen for tone. If two candidates are a
tenth of a nat apart the note says so and refuses to pick, however unsatisfying
that is to read. A tool that sounds certain is worse than useless when it is
wrong about a real person.

**Always end with an action.** A note that stops at "inconclusive" has told the
user their afternoon was wasted. A note that stops at "inconclusive, and the
one fact that would settle it is their employer" has told them what to do in
the next five minutes. The second is computable, so there is no excuse for the
first.

**Say what was not looked at, every time.** A confident note produced by a scan
where six of nine sources were rate-limited is a lie of omission, and the
reader has no way to know unless the note tells them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import Investigation

#: ``(tone, text)`` - the tone is a hint for whichever surface renders it, so
#: the desktop app can colour a contradiction red without re-deriving why the
#: line exists.
Line = tuple[str, str]


@dataclass
class Note:
    """What NOVA thinks, in the order a person wants to read it."""

    headline: str = ""
    #: A word for how much to trust the headline: certain / likely / weak /
    #: split / nothing. Rendered, but also useful to branch on.
    confidence: str = "nothing"
    because: list[str] = field(default_factory=list)
    against: list[str] = field(default_factory=list)
    blind: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    did: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"headline": self.headline, "confidence": self.confidence,
                "because": self.because, "against": self.against,
                "blind": self.blind, "next_steps": self.next_steps,
                "did": self.did}

    def lines(self) -> list[Line]:
        """The note as tagged lines, for a terminal or a Tk text widget."""
        out: list[Line] = [("head", self.headline)]
        if self.did:
            out.append(("dim", self.did))
        for label, items, tone in (("Why I think so", self.because, "good"),
                                   ("What argues against it", self.against, "bad"),
                                   ("What nobody could check", self.blind, "warn"),
                                   ("What I would do next", self.next_steps, "next")):
            if not items:
                continue
            out.append(("h2", label))
            out.extend((tone, f"- {item}") for item in items)
        return out


# ---------------------------------------------------------------------------
# writing the note
# ---------------------------------------------------------------------------


def write(inv: Investigation) -> Note:
    """Read an investigation and say what it amounts to."""
    note = Note()
    note.did = _did(inv)
    res = getattr(inv, "resolution", None)

    if res is None or not res.candidates:
        return _without_a_brief(inv, note)

    leader = res.candidates[0]
    runner = res.candidates[1] if len(res.candidates) > 1 else None
    note.confidence = _confidence(res, leader, runner)
    note.headline = _headline(res, leader, runner, note.confidence)

    from .identity import Verdict

    for check in sorted(leader.checks, key=lambda c: -c.llr):
        if check.verdict not in (Verdict.CONFIRMS, Verdict.CONSISTENT):
            continue
        found = f" (it says {check.found})" if check.found else ""
        note.because.append(
            f"their {check.claim.kind.value} is {check.claim.raw}{found}"
            f" - {check.why}, worth {check.llr:+.1f}")
    for check in leader.against:
        note.against.append(
            f"their {check.claim.kind.value} does not match: you said "
            f"{check.claim.raw}, the sources say {check.found} ({check.llr:+.1f})")
    if runner is not None and runner.score > 0:
        note.against.append(
            f"{runner.label} also fits, on {runner.answered} point(s), "
            f"{res.margin:.1f} nats behind")

    for check in leader.unchecked:
        note.blind.append(
            f"{check.claim.kind.value} - no source that could answer it "
            f"finished cleanly this run")
    note.blind.extend(res.untestable)
    note.blind.extend(_coverage(inv))

    note.next_steps = _next_steps(inv, res, leader)
    return note


def _did(inv: Investigation) -> str:
    """One line on the work behind the answer, so the note can be weighed."""
    brief = getattr(inv, "brief", None)
    facts = len(brief) if brief else 0
    ran = len([r for r in inv.results if r.status.is_complete])
    parts = [f"Checked {facts} thing(s) you told me" if facts else "Ran a scan",
             f"against {ran} of {len(inv.results)} source(s) that answered"]
    graph = inv.graph
    if graph is not None:
        parts.append(f"{len(graph)} entities")
    parts.append(f"{inv.duration:.1f}s")
    return " · ".join(parts) + "."


def _confidence(res: Any, leader: Any, runner: Any) -> str:
    from .identity import Verdict

    if leader.score <= 0:
        return "nothing"
    decisive = any(c.decisive and c.verdict is Verdict.CONFIRMS
                   for c in leader.checks)
    if runner is not None and res.margin < 1.0:
        return "split"
    if leader.answered <= 1 and not decisive:
        return "weak"
    if decisive and res.margin >= 2.0 and not leader.against:
        return "likely"
    if leader.answered >= 3 and res.margin >= 2.0 and not leader.against:
        return "likely"
    return "lead"


_HEADLINES = {
    "nothing": "None of what I found matches what you told me.",
    "split": "I cannot separate the top two.",
    "weak": "One weak lead, and one thing matching is what coincidence "
            "looks like.",
    "lead": "I have a best lead, but nothing decisive.",
    "likely": "I think I have them.",
}


def _headline(res: Any, leader: Any, runner: Any, confidence: str) -> str:
    if confidence == "nothing":
        return _HEADLINES["nothing"]
    if confidence == "split":
        return (f"I cannot separate {leader.label} from {runner.label} - "
                f"they are {res.margin:.1f} nats apart on what you gave me.")
    if confidence == "weak":
        return (f"{leader.label} is the only thing that matched at all, on "
                f"{leader.answered} point(s). Treat that as a coincidence "
                f"until something else agrees.")
    if confidence == "likely":
        return (f"{leader.label} is very likely your subject: "
                f"{leader.answered} of {len(leader.checks)} things you told me "
                f"line up and nothing contradicts them.")
    return (f"{leader.label} is my best lead - {leader.answered} of "
            f"{len(leader.checks)} points match - but nothing here is decisive "
            f"on its own.")


def _coverage(inv: Investigation) -> list[str]:
    """Sources that did not finish, phrased as what it cost you."""
    out = []
    for res in inv.incomplete:
        reason = res.errors[0] if res.errors else res.status.value
        out.append(f"{res.module} did not finish ({reason}), so anything only "
                   f"it could have found is missing")
    return out[:4]


def _next_steps(inv: Investigation, res: Any, leader: Any) -> list[str]:
    steps: list[str] = []
    if res.next_check:
        steps.append(res.next_check)

    brief = getattr(inv, "brief", None)
    if brief is not None:
        from .brief import ClaimKind

        missing = [k for k in (ClaimKind.EMAIL, ClaimKind.PHONE, ClaimKind.BORN,
                               ClaimKind.CITY, ClaimKind.ORG)
                   if not brief.of(k)]
        if missing and res.margin < 3.0:
            names = ", ".join(k.value for k in missing[:3])
            steps.append(f"add any of {names} to the brief - they are the "
                         f"heaviest things you have not told me")

    # A concrete command, because "gather more evidence" is not an instruction.
    lead_value = leader.members[0] if leader.members else leader.label
    if leader.etype in ("username", "email", "domain"):
        steps.append(f'scan the lead itself: nova scan "{lead_value}" --expand')
    for res_obj in inv.incomplete[:1]:
        steps.append(f"re-run once {res_obj.module} is answering again; "
                     f"nova doctor says whether it is back")
    return steps[:4]


def _without_a_brief(inv: Investigation, note: Note) -> Note:
    """What to say when there was nothing to cross-check against.

    This is the common first run, and it is the best moment to show that the
    tool does more than list findings - the user is looking straight at a pile
    of candidates with no way to rank them, which is exactly the problem a
    brief solves. Explaining it here costs one paragraph and saves the scan.
    """
    note.confidence = "nothing"
    candidates = _ambiguity(inv)
    if candidates:
        note.headline = (
            f"I found {candidates} possible {'matches' if candidates > 1 else 'match'}"
            f" and no way to tell them apart.")
        note.next_steps = [
            "tell me one more thing about them and I will rank these: "
            'nova scan "<target>" -K city=... -K employer=... -K born=...',
            "in the desktop app, use the 'also know' row above the target box",
        ]
        note.blind = _coverage(inv)
        return note

    note.headline = ("Scan complete. I was not given anything to cross-check "
                     "against, so this is a collection, not a conclusion.")
    note.next_steps = [
        "add what you already know and I will rank the candidates against it: "
        "-K name=... -K city=... -K born=...",
    ]
    note.blind = _coverage(inv)
    return note


def _ambiguity(inv: Investigation) -> int:
    """How many candidate identities a brief-less scan turned up."""
    graph = inv.graph
    if graph is None:
        return 0
    from .entities import EntityType

    return len([n for n in graph
                if n.entity.etype in (EntityType.PERSON, EntityType.ORG)
                and n.entity.eid != graph.seed])


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def render_text(note: Note, width: int = 92) -> str:
    import textwrap

    out: list[str] = []
    for tone, text in note.lines():
        if tone == "head":
            out += textwrap.wrap(text, width, initial_indent="  ",
                                 subsequent_indent="  ")
        elif tone == "h2":
            out += ["", f"  {text}"]
        elif tone == "dim":
            out += textwrap.wrap(text, width, initial_indent="  ",
                                 subsequent_indent="  ")
        else:
            out += textwrap.wrap(text, width, initial_indent="    ",
                                 subsequent_indent="      ")
    return "\n".join(out)


def render_markdown(note: Note) -> str:
    out = [f"**{note.headline}**", ""]
    if note.did:
        out += [f"*{note.did}*", ""]
    for label, items in (("Why I think so", note.because),
                         ("What argues against it", note.against),
                         ("What nobody could check", note.blind),
                         ("What I would do next", note.next_steps)):
        if not items:
            continue
        out += [f"**{label}**", ""]
        out += [f"- {item}" for item in items]
        out.append("")
    return "\n".join(out)


__all__ = ["Note", "render_markdown", "render_text", "write"]
