"""An optional local model that asks better questions - and never answers them.

Everything else in NOVA is deterministic. A finding traces to a request, a
request to a URL, a URL to stored bytes, and a score to a number in a table you
can argue with. That property is the product. A language model has none of it:
it is fluent, it is confident, and it will invent an address that looks exactly
like the real ones.

So this layer exists under one rule, and the rule is the whole design:

    **It produces questions and hypotheses. It never produces findings.**

Nothing here reaches the evidence graph. Not as a weak edge, not as a
``pivot-derived`` node, not as a finding with low confidence. The graph is for
things a source said; a model has no sources. What it is genuinely good at is
the thing the query planner does badly - looking at forty entities and a
half-finished picture and noticing *what has not been asked yet*.

Three guards, because "it never produces findings" has to be enforced rather
than promised
-------------------------------------------------------------------------------

**A hypothesis must cite evidence that exists.** Every hypothesis names the
entity ids it rests on, and any id the graph has never heard of means the whole
hypothesis is discarded and counted. This is the anti-fabrication check, and it
is cheap: a model that invents a connection almost always invents the node it
hangs off too.

**A question is a question, not an assertion.** Questions are run through the
same :class:`~nova_osint.core.search.SearchService` as every other query and
their results are scored exactly like any other search result - ``search-result``
at 0.25 nats. A lead the model suggested that turns out to be real is evidenced
by the page that confirmed it, never by the fact that a model said it.

**It runs on your machine or it does not run.** The default base URL is
loopback, private addresses are allowed, and a public one is refused unless the
operator explicitly opts in - at which point it says plainly that the
investigation's contents are leaving the building and that the endpoint may
charge. Free and local is the default because a tool that quietly ships a
target's details to a third party has no business calling itself OSINT.

Providers
---------

**Ollama** (``/api/chat``) and **anything OpenAI-compatible**
(``/v1/chat/completions``) - which covers llama.cpp's server, LM Studio, vLLM,
and Ollama's own compatibility endpoint. Both are free and both run locally.
Absent one, :func:`assist` returns an unavailable outcome with the reason in it
and the investigation carries on, exactly as it does without ``playwright`` or
``phonenumbers``.

Stdlib only, through the shared :class:`~nova_osint.core.http.Fetcher`, so rate
limiting, caching and the passive guard all apply without special cases.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

__all__ = ["AssistSettings", "Question", "Hypothesis", "AssistOutcome",
           "Assistant", "assist", "DEFAULT_MODEL"]

#: Small on purpose. The job is re-reading a structured digest and spotting a
#: gap, which a 3B model does perfectly well, and a 3B model is a two-gigabyte
#: download rather than a twenty-gigabyte one.
DEFAULT_MODEL = "llama3.2:3b"

#: How long to wait for a local model. Generous - a cold model loading from
#: disk on a laptop takes most of this - and bounded, because a hung endpoint
#: must degrade to a named gap rather than to a stalled investigation.
DEFAULT_TIMEOUT = 120.0

MAX_QUESTIONS = 6
MAX_HYPOTHESES = 5
MAX_QUERY_CHARS = 200
MAX_TEXT_CHARS = 400


# ---------------------------------------------------------------------------
# settings
# ---------------------------------------------------------------------------


@dataclass
class AssistSettings:
    """Where the model is, and what it is allowed to see."""

    enabled: bool = False
    provider: str = "ollama"          # "ollama" | "openai"
    base_url: str = "http://127.0.0.1:11434"
    model: str = DEFAULT_MODEL
    timeout: float = DEFAULT_TIMEOUT
    #: Opt-in required before the digest may leave this machine or network.
    allow_remote: bool = False
    #: Sent as a bearer token when a local server wants one. Never required.
    api_key: str = ""

    @classmethod
    def from_config(cls, config: Any) -> AssistSettings:
        def opt(name: str, default: Any) -> Any:
            value = config.option(name, None) if hasattr(config, "option") else None
            return default if value in (None, "") else value

        return cls(
            enabled=bool(opt("assist", False)),
            provider=str(opt("assist_provider", "ollama")).lower(),
            base_url=str(opt("assist_url", "http://127.0.0.1:11434")).rstrip("/"),
            model=str(opt("assist_model", DEFAULT_MODEL)),
            timeout=float(opt("assist_timeout", DEFAULT_TIMEOUT)),
            allow_remote=bool(opt("assist_allow_remote", False)),
            api_key=str(opt("assist_key", "") or ""),
        )

    def locality(self) -> tuple[bool, str]:
        """Is this endpoint on a machine the operator controls?

        Loopback and RFC1918 pass. A public address is refused by default, and
        the refusal is the point: enabling it sends entity values, findings and
        the operator's own brief to somebody else's server.
        """
        host = urllib.parse.urlsplit(self.base_url).hostname or ""
        if not host:
            return False, "no host in the assist URL"
        if host in ("localhost", "localhost.localdomain"):
            return True, "loopback"
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return False, f"{host} is a public name"
        if addr.is_loopback:
            return True, "loopback"
        if addr.is_private or addr.is_link_local:
            return True, "private network"
        return False, f"{host} is a public address"


# ---------------------------------------------------------------------------
# what the model is allowed to return
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Question:
    """Something worth asking that nothing has asked yet."""

    query: str
    why: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"query": self.query, "why": self.why}


@dataclass(frozen=True)
class Hypothesis:
    """A reading of the evidence, labelled as a reading for as long as it lives.

    ``supports`` is not decoration. It is the check: every id in it must be a
    node the graph actually holds, or the hypothesis is thrown away.
    """

    claim: str
    supports: tuple[str, ...] = ()
    confirm_with: str = ""
    refute_with: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"claim": self.claim, "supports": list(self.supports),
                "confirm_with": self.confirm_with, "refute_with": self.refute_with,
                "status": "hypothesis - not evidence, not a finding"}


@dataclass
class AssistOutcome:
    """What came back, what was thrown away, and why it could not run."""

    available: bool = False
    reason: str = ""
    model: str = ""
    provider: str = ""
    questions: list[Question] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    #: Rejected output, with the reason. Reported rather than silently dropped:
    #: a model that keeps inventing entity ids is a model producing nothing,
    #: and the operator deserves to see that rather than an empty section.
    discarded: list[str] = field(default_factory=list)
    elapsed: float = 0.0

    def __bool__(self) -> bool:
        return bool(self.questions or self.hypotheses)

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available, "reason": self.reason,
            "model": self.model, "provider": self.provider,
            "questions": [q.to_dict() for q in self.questions],
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "gaps": self.gaps, "discarded": self.discarded,
            "elapsed": round(self.elapsed, 2),
        }


# ---------------------------------------------------------------------------
# the prompt
# ---------------------------------------------------------------------------

SYSTEM = """You are an analyst's assistant inside an OSINT tool.

You do NOT report facts. You have no sources. Everything you know is in the
digest you are given, and the tool will verify anything you suggest.

Your two jobs:
1. QUESTIONS - searches nobody has run yet that would separate the candidates
   or fill a named gap. Concrete search queries, not topics.
2. HYPOTHESES - readings of the evidence, each citing the entity ids it rests
   on, and each saying what would confirm it and what would refute it.

Hard rules:
- Never invent an entity id. Cite only ids that appear in the digest.
- Never state a conclusion as fact. Every hypothesis must be refutable.
- If the evidence does not support a hypothesis, return none. An empty list is
  a correct answer and a far better one than a guess.

Reply with JSON only, in exactly this shape:
{"questions":[{"query":"...","why":"..."}],
 "hypotheses":[{"claim":"...","supports":["id"],"confirm_with":"...",
                "refute_with":"..."}],
 "gaps":["..."]}"""


def digest(inv: Any, *, subject: str, limit: int = 40) -> tuple[str, set[str]]:
    """The investigation, compressed to what a model can reason over.

    Returns the text and the set of entity ids that appeared in it - the second
    is what :func:`_validate` checks citations against, so the model can only
    ever cite something it was actually shown.
    """
    lines = [f"SUBJECT: {subject}", ""]
    known: set[str] = set()

    graph = getattr(inv, "graph", None)
    if graph is not None and getattr(graph, "nodes", None):
        nodes = sorted(graph.nodes.values(), key=lambda n: -getattr(n, "score", 0.0))
        lines.append("ENTITIES (id | kind | relevance | independent sources):")
        for node in nodes[:limit]:
            eid = node.entity.eid
            known.add(eid)
            kind = getattr(node.entity.etype, "value", str(node.entity.etype))
            flag = " RULED-OUT" if getattr(node, "contradicted", False) else ""
            lines.append(f"  {eid} | {kind} | {node.score:.3f} | "
                         f"{getattr(node, 'corroborations', 0)}{flag}")
        lines.append("")

        edges = sorted(graph.edges.values(), key=lambda e: -e.llr)[:limit]
        if edges:
            lines.append("CONNECTIONS (from -> to | grade | evidence):")
            for edge in edges:
                kinds = ",".join(sorted({o.kind for o in edge.observations})[:3])
                lines.append(f"  {edge.src} -> {edge.dst} | {edge.grade} | {kinds}")
            lines.append("")

    findings = list(getattr(inv, "findings", []) or [])[:limit]
    if findings:
        lines.append("FINDINGS (label | value | source):")
        for f in findings:
            value = str(getattr(f, "value", ""))[:120]
            lines.append(f"  {getattr(f, 'label', '')} | {value} | "
                         f"{getattr(f, 'source', '')}")
        lines.append("")

    # The gaps matter more than the findings. A model that can see "these four
    # sources refused" writes a better question than one shown only successes.
    gaps: list[str] = []
    for res in getattr(inv, "results", []) or []:
        status = getattr(getattr(res, "status", None), "value", "")
        if status and status not in ("ok", "success"):
            gaps.append(f"{getattr(res, 'module', '?')}: {status} "
                        f"{getattr(res, 'status_reason', '')}".strip())
    for module, why in list(getattr(inv, "skipped", []) or [])[:12]:
        gaps.append(f"{module}: skipped - {why}")
    expansion = getattr(inv, "expansion", None)
    for eid, score in list(getattr(expansion, "below_floor", []) or [])[:8]:
        gaps.append(f"lead not followed (too weak, {score:.3f}): {eid}")
    for eid, why in list(getattr(expansion, "ruled_out", []) or [])[:8]:
        gaps.append(f"lead ruled out: {eid} - {why}")
    if gaps:
        lines.append("GAPS AND UNFOLLOWED LEADS:")
        lines += [f"  {g}" for g in gaps[:limit]]

    return "\n".join(lines), known


# ---------------------------------------------------------------------------
# the client
# ---------------------------------------------------------------------------


class Assistant:
    """Talks to a local model, and refuses to believe most of what it says."""

    def __init__(self, http: Any, settings: AssistSettings) -> None:
        self.http = http
        self.settings = settings

    # -- availability --------------------------------------------------------

    def check(self) -> tuple[bool, str]:
        """Can this run, and if not, exactly why. Never raises."""
        s = self.settings
        local, where = s.locality()
        if not local and not s.allow_remote:
            return False, (f"{where}; refusing to send the investigation off "
                           f"this machine. Set assist_allow_remote to override - "
                           f"it may cost money and it discloses the target.")
        url = (f"{s.base_url}/api/tags" if s.provider == "ollama"
               else f"{s.base_url}/v1/models")
        try:
            resp = self.http.get(url, timeout=min(15.0, s.timeout),
                                 headers=self._headers())
        except Exception as exc:                       # noqa: BLE001
            return False, f"no model server at {s.base_url} ({type(exc).__name__})"
        if resp.status == 0:
            # The fetcher reports a connection that never happened as status 0,
            # and "answered 0" reads like the server said something.
            return False, (f"nothing is listening on {s.base_url} "
                           f"({getattr(resp, 'error', '') or 'connection refused'})")
        if resp.status != 200:
            return False, f"{s.base_url} answered {resp.status}"
        names = self._model_names(resp)
        if names and not self._has_model(names):
            return False, (f"server is up but does not have '{s.model}'. "
                           f"It has: {', '.join(sorted(names)[:6])}")
        return True, f"{s.provider} at {s.base_url}, model {s.model}"

    def _has_model(self, names: set[str]) -> bool:
        wanted = self.settings.model
        # ``llama3.2`` should match a server holding ``llama3.2:3b``.
        return any(n == wanted or n.split(":")[0] == wanted.split(":")[0]
                   for n in names)

    @staticmethod
    def _model_names(resp: Any) -> set[str]:
        data = resp.json() if hasattr(resp, "json") else None
        if not isinstance(data, dict):
            return set()
        rows = data.get("models") or data.get("data") or []
        out: set[str] = set()
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict):
                name = row.get("name") or row.get("model") or row.get("id")
                if isinstance(name, str):
                    out.add(name)
        return out

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.settings.api_key:
            headers["Authorization"] = f"Bearer {self.settings.api_key}"
        return headers

    # -- the call ------------------------------------------------------------

    def ask(self, prompt: str) -> tuple[str, str]:
        """Send one prompt. Returns ``(text, error)`` and never raises."""
        s = self.settings
        if s.provider == "ollama":
            url = f"{s.base_url}/api/chat"
            payload: dict[str, Any] = {
                "model": s.model, "stream": False, "format": "json",
                "messages": [{"role": "system", "content": SYSTEM},
                             {"role": "user", "content": prompt}],
                "options": {"temperature": 0.0},
            }
        else:
            url = f"{s.base_url}/v1/chat/completions"
            payload = {
                "model": s.model, "temperature": 0.0,
                "response_format": {"type": "json_object"},
                "messages": [{"role": "system", "content": SYSTEM},
                             {"role": "user", "content": prompt}],
            }
        try:
            resp = self.http.get(url, method="POST",
                                 data=json.dumps(payload).encode(),
                                 headers=self._headers(), timeout=s.timeout)
        except Exception as exc:                       # noqa: BLE001
            return "", f"{type(exc).__name__}: {exc}"
        if resp.status != 200:
            return "", f"model server answered {resp.status}"
        data = resp.json()
        if not isinstance(data, dict):
            return "", "model server did not return JSON"
        if s.provider == "ollama":
            text = ((data.get("message") or {}).get("content") or "")
        else:
            choices = data.get("choices") or []
            first = choices[0] if choices and isinstance(choices[0], dict) else {}
            text = ((first.get("message") or {}).get("content") or "")
        return str(text), "" if text else "model returned an empty message"


# ---------------------------------------------------------------------------
# validation - where most of the value is
# ---------------------------------------------------------------------------


def _json_in(text: str) -> Any:
    """The JSON object in a reply, even when the model wrapped it in prose.

    Small models fence their output, apologise before it, or add a sentence
    after it, and none of that is a reason to throw away good structure.
    """
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        _, _, text = text.partition("\n")
    try:
        return json.loads(text)
    except ValueError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except ValueError:
            return None
    return None


def _clean(value: Any, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def validate(text: str, known: set[str]) -> AssistOutcome:
    """Turn a model's reply into the little of it that survives scrutiny."""
    out = AssistOutcome()
    data = _json_in(text)
    if not isinstance(data, dict):
        out.discarded.append("reply was not JSON")
        return out

    for row in (data.get("questions") or [])[:MAX_QUESTIONS * 3]:
        if len(out.questions) >= MAX_QUESTIONS:
            break
        if isinstance(row, str):
            row = {"query": row}
        if not isinstance(row, dict):
            continue
        query = _clean(row.get("query") or row.get("search"), MAX_QUERY_CHARS)
        if len(query) < 3:
            out.discarded.append("question with no query")
            continue
        if any(q.query.casefold() == query.casefold() for q in out.questions):
            continue
        out.questions.append(Question(query, _clean(row.get("why"), MAX_TEXT_CHARS)))

    for row in (data.get("hypotheses") or [])[:MAX_HYPOTHESES * 3]:
        if len(out.hypotheses) >= MAX_HYPOTHESES:
            break
        if not isinstance(row, dict):
            continue
        claim = _clean(row.get("claim") or row.get("hypothesis"), MAX_TEXT_CHARS)
        if len(claim) < 8:
            out.discarded.append("hypothesis with no claim")
            continue
        cited = [str(s) for s in (row.get("supports") or []) if isinstance(s, str)]
        if not cited:
            out.discarded.append(f"hypothesis cites no evidence: {claim[:60]}")
            continue
        # The anti-fabrication check. A model that invents a connection almost
        # always invents the node it hangs off, so an id the graph has never
        # heard of condemns the whole hypothesis rather than just that id.
        unknown = [c for c in cited if c not in known]
        if unknown:
            out.discarded.append(
                f"hypothesis cites {len(unknown)} entity id(s) that do not exist "
                f"({', '.join(unknown[:3])}): {claim[:60]}")
            continue
        out.hypotheses.append(Hypothesis(
            claim=claim, supports=tuple(dict.fromkeys(cited)),
            confirm_with=_clean(row.get("confirm_with"), MAX_TEXT_CHARS),
            refute_with=_clean(row.get("refute_with"), MAX_TEXT_CHARS)))

    for row in (data.get("gaps") or [])[:10]:
        if gap := _clean(row, MAX_TEXT_CHARS):
            out.gaps.append(gap)
    return out


# ---------------------------------------------------------------------------
# the entry point
# ---------------------------------------------------------------------------


def assist(inv: Any, http: Any, settings: AssistSettings, *,
           subject: str = "") -> AssistOutcome:
    """Ask a local model what to look at next. Never raises, never asserts."""
    started = time.monotonic()
    out = AssistOutcome(provider=settings.provider, model=settings.model)
    if not settings.enabled:
        out.reason = "not enabled (--assist)"
        return out

    client = Assistant(http, settings)
    ok, why = client.check()
    if not ok:
        out.reason = why
        log.info("assist unavailable: %s", why)
        return out
    out.available = True

    prompt, known = digest(inv, subject=subject or getattr(inv, "target", ""))
    text, error = client.ask(prompt)
    if error:
        out.reason = error
        out.available = False
        return out

    got = validate(text, known)
    out.questions, out.hypotheses = got.questions, got.hypotheses
    out.gaps, out.discarded = got.gaps, got.discarded
    out.reason = why
    out.elapsed = time.monotonic() - started
    log.info("assist produced %d question(s), %d hypothesis(es), discarded %d",
             len(out.questions), len(out.hypotheses), len(out.discarded))
    return out
