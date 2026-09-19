"""Offline tests for the optional local model, and for the guards on it.

Most of this file is about what the assistant is **not** allowed to do. The
prompt is a suggestion; the validator is the contract, and the validator is
what these tests protect.

No socket: the transport is driven through a fake fetcher, which is also how
every branch was first exercised for real against a stub Ollama on loopback.
"""

from __future__ import annotations

import json

import pytest

from nova_osint.core.assist import (
    AssistSettings,
    Assistant,
    Hypothesis,
    assist,
    digest,
    validate,
)
from nova_osint.core.entities import Entity, EntityType as T
from nova_osint.core.graph import EntityGraph, Observation
from nova_osint.core.queryplan import QueryPlanner

KNOWN = {"domain:example.com", "email:webmaster@example.com"}


class FakeResponse:
    def __init__(self, status: int = 200, payload=None, error: str = "") -> None:
        self.status = status
        self._payload = payload
        self.error = error
        self.text = json.dumps(payload) if payload is not None else ""

    def json(self):
        return self._payload


class FakeHttp:
    """Answers /api/tags and /api/chat, and records what it was asked."""

    def __init__(self, reply: str = "{}", *, tags_status: int = 200,
                 chat_status: int = 200, models=("llama3.2:3b",)) -> None:
        self.reply = reply
        self.tags_status = tags_status
        self.chat_status = chat_status
        self.models = models
        self.calls: list[tuple[str, dict]] = []

    def get(self, url, *, method="GET", data=None, headers=None, timeout=None):
        self.calls.append((url, {"method": method, "data": data}))
        if url.endswith("/api/tags"):
            return FakeResponse(self.tags_status,
                                {"models": [{"name": m} for m in self.models]})
        if url.endswith("/v1/models"):
            return FakeResponse(self.tags_status,
                                {"data": [{"id": m} for m in self.models]})
        if self.chat_status != 200:
            return FakeResponse(self.chat_status, {})
        if "/api/chat" in url:
            return FakeResponse(200, {"message": {"content": self.reply}})
        return FakeResponse(200, {"choices": [{"message": {"content": self.reply}}]})


def local(**kw) -> AssistSettings:
    return AssistSettings(enabled=True, base_url="http://127.0.0.1:11434", **kw)


# ---------------------------------------------------------------------------
# the citation check - the anti-fabrication guard
# ---------------------------------------------------------------------------


def test_a_hypothesis_citing_an_entity_that_does_not_exist_is_discarded():
    """The whole reason this layer is allowed to exist.

    A model that invents a connection almost always invents the node it hangs
    off, so an id the graph has never heard of condemns the hypothesis rather
    than just the citation.
    """
    got = validate(json.dumps({"hypotheses": [
        {"claim": "Jane Doe of Acme Ltd registered the domain in 2011.",
         "supports": ["person:jane doe", "org:acme ltd"]}]}), KNOWN)
    assert got.hypotheses == []
    assert len(got.discarded) == 1
    assert "do not exist" in got.discarded[0]


def test_the_good_hypothesis_survives_alongside_the_fabricated_one():
    """One bad answer must not cost the operator a good one."""
    got = validate(json.dumps({"hypotheses": [
        {"claim": "Jane Doe of Acme Ltd registered the domain.",
         "supports": ["person:jane doe"]},
        {"claim": "The webmaster address is a role account, not a person.",
         "supports": ["email:webmaster@example.com"],
         "confirm_with": "a second role address on the domain"}]}), KNOWN)
    assert len(got.hypotheses) == 1
    assert got.hypotheses[0].supports == ("email:webmaster@example.com",)
    assert len(got.discarded) == 1


def test_a_hypothesis_citing_nothing_at_all_is_discarded():
    got = validate(json.dumps({"hypotheses": [{"claim": "They are the same person."}]}),
                   KNOWN)
    assert got.hypotheses == []
    assert "cites no evidence" in got.discarded[0]


def test_the_digest_only_shows_ids_the_model_may_then_cite():
    """The citation check is only as good as the set it checks against."""
    graph = EntityGraph(Entity.make(T.DOMAIN, "example.com"))
    mail = Entity.make(T.EMAIL, "webmaster@example.com")
    graph.connect(graph.nodes[graph.seed].entity, mail, "contact",
                  Observation(kind="published-contact", module="web"))
    graph.rescore()

    class Inv:
        target = "example.com"
        findings: list = []
        results: list = []
        skipped: list = []
        expansion = None

    inv = Inv()
    inv.graph = graph
    text, known = digest(inv, subject="example.com")
    assert known == {"domain:example.com", "email:webmaster@example.com"}
    for eid in known:
        assert eid in text


# ---------------------------------------------------------------------------
# a model that does not cooperate
# ---------------------------------------------------------------------------


def test_prose_around_the_json_is_not_a_reason_to_throw_it_away():
    """Small models fence their output and apologise before it."""
    body = json.dumps({"questions": [{"query": '"example.com" privacy policy'}]})
    got = validate(f"Sure! Here you go:\n```json\n{body}\n```\nHope that helps.",
                   KNOWN)
    assert [q.query for q in got.questions] == ['"example.com" privacy policy']


def test_a_reply_that_is_not_json_produces_nothing_and_says_so():
    got = validate("I'm sorry, I can't help with that request.", KNOWN)
    assert not got.questions and not got.hypotheses
    assert got.discarded == ["reply was not JSON"]


def test_an_empty_answer_is_a_correct_answer():
    got = validate(json.dumps({"questions": [], "hypotheses": []}), KNOWN)
    assert not got.questions and not got.hypotheses and not got.discarded


def test_output_is_capped_however_much_the_model_writes():
    flood = {"questions": [{"query": f"query number {i}"} for i in range(50)],
             "hypotheses": [{"claim": f"a claim about number {i}",
                             "supports": ["domain:example.com"]} for i in range(50)]}
    got = validate(json.dumps(flood), KNOWN)
    assert len(got.questions) <= 6
    assert len(got.hypotheses) <= 5


def test_duplicate_questions_collapse():
    got = validate(json.dumps({"questions": [
        {"query": "who owns example.com"}, {"query": "Who Owns Example.Com"}]}), KNOWN)
    assert len(got.questions) == 1


# ---------------------------------------------------------------------------
# it runs on your machine or it does not run
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url,ok", [
    ("http://127.0.0.1:11434", True),
    ("http://localhost:11434", True),
    ("http://192.168.1.50:11434", True),
    ("http://10.0.0.4:8000", True),
    ("https://api.example-llm.com", False),
    ("https://1.2.3.4:443", False),
])
def test_only_a_machine_the_operator_controls_is_allowed_by_default(url, ok):
    assert AssistSettings(base_url=url).locality()[0] is ok


def test_a_public_endpoint_is_refused_and_the_refusal_explains_itself():
    client = Assistant(FakeHttp(), AssistSettings(
        enabled=True, base_url="https://api.example-llm.com"))
    available, why = client.check()
    assert not available
    assert "off this machine" in why and "cost money" in why


def test_a_public_endpoint_is_allowed_once_the_operator_says_so():
    http = FakeHttp()
    client = Assistant(http, AssistSettings(
        enabled=True, base_url="https://api.example-llm.com", allow_remote=True))
    assert client.check()[0]


def test_refusing_a_public_endpoint_opens_no_socket():
    """The refusal must come before the request, not after it."""
    http = FakeHttp()
    Assistant(http, AssistSettings(enabled=True,
                                   base_url="https://api.example-llm.com")).check()
    assert http.calls == []


# ---------------------------------------------------------------------------
# degrading, which is the normal case
# ---------------------------------------------------------------------------


def test_disabled_is_not_an_error():
    out = assist(object(), FakeHttp(), AssistSettings(enabled=False))
    assert not out.available
    assert "not enabled" in out.reason


def test_a_server_without_the_model_says_which_models_it_has():
    client = Assistant(FakeHttp(models=("qwen2.5:7b", "mistral")),
                       local(model="llama3.2:3b"))
    available, why = client.check()
    assert not available
    assert "does not have" in why and "qwen2.5:7b" in why


def test_a_tag_without_a_size_matches_the_same_model_with_one():
    assert Assistant(FakeHttp(models=("llama3.2:3b",)),
                     local(model="llama3.2")).check()[0]


def test_a_server_that_errors_degrades_rather_than_raising():
    client = Assistant(FakeHttp(chat_status=500), local())
    text, error = client.ask("hello")
    assert text == "" and "500" in error


def test_a_transport_that_explodes_degrades_rather_than_raising():
    class Broken:
        def get(self, *a, **kw):
            raise OSError("connection reset")

    assert Assistant(Broken(), local()).check()[0] is False
    assert Assistant(Broken(), local()).ask("hi")[0] == ""


# ---------------------------------------------------------------------------
# what a surviving question turns into
# ---------------------------------------------------------------------------


def test_a_suggested_question_is_the_weakest_category_the_planner_has():
    """A question nobody has evidence for ranks below every evidenced one."""
    planner = QueryPlanner()
    suggested = planner.free_text('site:linkedin.com "example.com"',
                                  subject="example.com")
    evidenced = planner.expand("example.com", "domain", subject="example.com")[0]
    assert suggested is not None
    assert suggested.value < evidenced.value
    assert suggested.origin == "assist"


def test_operators_in_a_suggested_query_are_detected_not_trusted():
    """An engine without ``site:`` must get the degraded form, not the word."""
    query = QueryPlanner().free_text('site:linkedin.com "acme" filetype:pdf')
    assert query is not None
    assert query.operators == frozenset({"site", "filetype"})
    assert "site:" not in query.for_engine(frozenset())


def test_a_question_that_never_names_the_subject_is_flagged_ambiguous():
    planner = QueryPlanner()
    assert planner.free_text("jewellers in singapore", subject="Racquel").ambiguous
    assert not planner.free_text('"Racquel" jeweller', subject="Racquel").ambiguous


def test_an_unusable_suggestion_is_dropped():
    assert QueryPlanner().free_text("  ") is None
    assert QueryPlanner().free_text("a") is None


# ---------------------------------------------------------------------------
# the boundary itself
# ---------------------------------------------------------------------------


def test_nothing_the_model_returns_is_shaped_like_evidence():
    """No path from a hypothesis into the graph: it has no evidence kind.

    Stated as a test because the boundary is the entire justification for this
    layer, and the way it would be lost is somebody adding a plausible-looking
    ``EVIDENCE`` key for it.
    """
    from nova_osint.core.graph import EVIDENCE

    for key in EVIDENCE:
        assert "hypoth" not in key and "assist" not in key and "model" not in key
    assert not hasattr(Hypothesis, "llr")
    assert "hypothesis" in Hypothesis("a claim here", ("x",)).to_dict()["status"]
