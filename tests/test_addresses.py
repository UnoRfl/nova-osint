"""Offline tests for telling a person's mailbox from a machine's.

The numbers in these docstrings come from one real run: four email pivots,
seven modules each, about sixty seconds apiece - roughly 250 of that scan's
313 seconds - and two of the four could not have worked.
"""

from __future__ import annotations

import pytest

from nova_osint.core.addresses import AddressVerdict, judge_address
from nova_osint.core.engine import pivot_refusal
from nova_osint.core.models import TargetType


# ---------------------------------------------------------------------------
# the two that cost the scan two minutes
# ---------------------------------------------------------------------------


def test_a_platforms_own_commit_alias_is_not_a_lead():
    """GitHub invents this so a commit need not carry a real address.

    It *is* the subject's, and exactly one system on earth has heard of it, so
    asking breach corpora, DNS, WebFinger and a search engine about it is a
    guaranteed nothing at sixty seconds a go.
    """
    v = judge_address("unorfl@users.noreply.github.com")
    assert v.kind == "automated"
    assert not v.expandable


def test_a_ci_robots_address_is_not_the_subject_at_all():
    """``action@github.com`` signs GitHub Actions' automated commits.

    Following it walks the investigation into GitHub's own infrastructure -
    the email analogue of pivoting into a cloud netblock, which
    ``infra.judge_host`` already refuses.
    """
    assert judge_address("action@github.com").kind == "automated"
    assert judge_address("dependabot[bot]@users.noreply.github.com").kind == "automated"
    assert judge_address("renovate[bot]@users.noreply.github.com").kind == "automated"


# ---------------------------------------------------------------------------
# and the two that had to keep working
# ---------------------------------------------------------------------------


def test_a_personal_address_is_still_followed():
    v = judge_address("improvised30@gmail.com")
    assert v.kind == "personal" and v.expandable and v.identifies_a_person


def test_a_role_address_is_demoted_and_not_suppressed():
    """For a one-person business the role address genuinely is the owner.

    So this is a judgement with three outcomes, not a blocklist with two: the
    lead is still worth following, it just must never be read as evidence
    about a *person*.
    """
    v = judge_address("sales@designsbyracquel.com")
    assert v.kind == "role"
    assert v.expandable, "a shared mailbox still reaches the organisation"
    assert not v.identifies_a_person


def test_a_shared_mailbox_is_not_evidence_about_a_person():
    """``sales@`` on two sites says they share a mailbox, not an owner.

    An investigation that cannot tell those apart will merge a shop and its
    web designer.
    """
    assert not judge_address("info@a.test").identifies_a_person
    assert not judge_address("admin@b.test").identifies_a_person
    assert judge_address("racquel@designsbyracquel.com").identifies_a_person


# ---------------------------------------------------------------------------
# the shapes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("address,kind", [
    ("noreply@example.com", "automated"),
    ("no-reply@example.com", "automated"),
    ("donotreply@example.com", "automated"),
    ("mailer-daemon@example.com", "automated"),
    ("bounces@example.com", "automated"),
    ("x@noreply.example.com", "automated"),
    ("support@example.com", "role"),
    ("careers@example.com", "role"),
    ("postmaster@example.com", "role"),
    ("alice.smith@example.com", "personal"),
    ("a.n.other@corp.example", "personal"),
])
def test_the_classification(address, kind):
    assert judge_address(address).kind == kind


def test_plus_addressing_does_not_smuggle_a_robot_past_the_gate():
    """A machine is as likely to use plus-addressing as anyone."""
    assert judge_address("noreply+abc123@example.com").kind == "automated"
    assert judge_address("sales+web@example.com").kind == "role"


def test_an_unparseable_value_defaults_to_personal():
    """The two mistakes are not symmetrical.

    Expanding a robot costs a wasted minute. Declining to expand a real
    person's address costs the investigation its subject.
    """
    for odd in ("", "   ", "not-an-address", "@", "a@", "@b"):
        assert judge_address(odd).kind == "personal"


def test_case_and_angle_brackets_do_not_defeat_it():
    assert judge_address("<NoReply@Example.COM>").kind == "automated"


def test_a_domain_merely_containing_noreply_is_not_automated():
    """``noreply.example.com`` sends machine mail; ``noreplyshop.com`` sells things."""
    assert judge_address("alice@noreplyshop.com").kind == "personal"


# ---------------------------------------------------------------------------
# both expansion paths, because a rule enforced in one of two is not a rule
# ---------------------------------------------------------------------------


def test_the_gate_refuses_a_robot_and_names_why():
    reason = pivot_refusal("action@github.com", TargetType.EMAIL)
    assert reason and "platform" in reason


def test_the_gate_lets_people_and_role_addresses_through():
    assert pivot_refusal("improvised30@gmail.com", TargetType.EMAIL) == ""
    assert pivot_refusal("sales@designsbyracquel.com", TargetType.EMAIL) == ""


def test_the_gate_does_not_touch_other_target_types():
    """Only addresses are judged here; a host has ``infra.judge_host``."""
    assert pivot_refusal("noreply.example.com", TargetType.DOMAIN) == ""
    assert pivot_refusal("1.2.3.4", TargetType.IP) == ""
    assert pivot_refusal("noreply", TargetType.USERNAME) == ""


def test_follow_pivots_filters_before_it_limits():
    """Otherwise two robots at the front consume two of the five slots.

    Which is what happened: the run had four email pivots and the two useless
    ones were not at the back of the queue.
    """
    import inspect

    from nova_osint.core.engine import Engine

    src = inspect.getsource(Engine.follow_pivots)
    gate = src.index("pivot_refusal")
    limit = src.index("[:limit]")
    assert gate < limit, "the filter must run before the limit"


def test_a_refused_lead_is_reported_rather_than_dropped():
    from nova_osint.core.models import Investigation

    inv = Investigation(target="x", target_type=TargetType.USERNAME)
    inv.not_followed.append(("action@github.com", "a platform generates this"))
    assert inv.to_dict()["not_followed"] == [
        {"lead": "action@github.com", "reason": "a platform generates this"}]


def test_a_clean_investigation_carries_no_empty_section():
    from nova_osint.core.models import Investigation

    inv = Investigation(target="x", target_type=TargetType.USERNAME)
    assert "not_followed" not in inv.to_dict()


def test_the_module_and_the_gate_cannot_disagree():
    """One list. The old copy in ``modules.email`` drifted by construction."""
    from nova_osint.core.addresses import ROLE_LOCALPARTS
    from nova_osint.modules.email import ROLE_ACCOUNTS

    assert ROLE_ACCOUNTS is ROLE_LOCALPARTS


def test_a_verdict_is_truthy_exactly_when_it_is_worth_following():
    assert AddressVerdict("personal")
    assert AddressVerdict("role")
    assert not AddressVerdict("automated")
