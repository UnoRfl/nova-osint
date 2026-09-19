"""Telling a person's address apart from a machine's, before pivoting to it.

The email counterpart to :mod:`~nova_osint.core.infra`, and it exists for the
same reason: the most expensive mistake an expansion makes is spending a
budget on something that was never going to identify anybody.

A real scan, from the live log of a username run:

    60.4s   pivot:improvised30@gmail.com
    121.2s  pivot:unorfl@users.noreply.github.com
    172.0s  pivot:action@github.com
    243.2s  pivot:sales@designsbyracquel.com

Four email pivots, seven modules each, roughly sixty seconds apiece - about
250 of that scan's 313 seconds. Two of the four could not have worked:

``unorfl@users.noreply.github.com`` is an address GitHub **invents** so a
commit need not carry a real one. It is the subject's, and it is known to
exactly one system on earth, so asking breach corpora, DNS, WebFinger and a
search engine about it is a guaranteed nothing.

``action@github.com`` is not the subject at all. It is the address GitHub
Actions signs automated commits with. Following it walks the investigation
into GitHub's own infrastructure - the email analogue of pivoting into a cloud
netblock, which ``infra.judge_host`` already refuses to do.

Meanwhile ``sales@designsbyracquel.com`` is a role address, and for a one-person
business the role address genuinely *is* the owner. So this is not a blocklist
with two outcomes. It is a judgement with three:

``personal``
    Probably an individual's mailbox. Pivot normally.
``role``
    A shared mailbox belonging to an *organisation*: ``sales@``, ``info@``,
    ``admin@``. Worth keeping and worth following - it is how you reach the
    org - but it does not identify a person, so it must never be treated as
    evidence about one. Demoted, not suppressed.
``automated``
    A machine's address: noreply, mailer-daemon, a CI bot, a platform's
    synthetic commit alias. There is no one behind it. The finding is kept,
    with the reason named, and the pivot is suppressed.

What this module does **not** do is hide anything. An automated address stays
in the report - "the commits were signed by GitHub Actions" is a true and
occasionally useful fact - it just stops generating work.

Pure: no clock, no socket, no config. Takes an address, returns a judgement.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["AddressVerdict", "judge_address", "ROLE_LOCALPARTS",
           "AUTOMATED_LOCALPARTS"]

#: Local parts that belong to an organisation rather than a person. RFC 2142
#: names a few of these; the rest are what small businesses actually use.
#: Shared with :mod:`nova_osint.modules.email`, which reports the same fact
#: *after* a lookup - this is the copy consulted before one.
ROLE_LOCALPARTS = frozenset({
    "abuse", "admin", "administrator", "accounts", "billing", "careers",
    "contact", "enquiries", "enquiry", "finance", "help", "hello", "hi",
    "hostmaster", "hr", "info", "inquiries", "invoices", "jobs", "legal",
    "mail", "marketing", "office", "orders", "postmaster", "press", "privacy",
    "recruitment", "root", "sales", "security", "shop", "support", "team",
    "webmaster", "welcome",
})

#: Local parts with nobody behind them at all.
AUTOMATED_LOCALPARTS = frozenset({
    "noreply", "no-reply", "no_reply", "donotreply", "do-not-reply",
    "do_not_reply", "bounce", "bounces", "mailer-daemon", "mailerdaemon",
    "postmaster-noreply", "notification", "notifications", "automated",
    "autoreply", "auto-reply", "robot", "bot", "daemon", "cron", "system",
    "nobody", "devnull", "null", "noreply-dmarc", "dmarc", "dmarcreports",
})

#: Addresses a platform generates on a user's behalf, or signs its own
#: automation with. The first is the subject's and known only to that platform;
#: the second is not the subject. Neither is worth a request.
_PLATFORM_AUTOMATED = (
    # GitHub's commit privacy alias, in both the old and numbered forms.
    re.compile(r"@users\.noreply\.github\.com$", re.I),
    re.compile(r"^action@github\.com$", re.I),
    re.compile(r"^actions?(-user)?@github\.com$", re.I),
    re.compile(r"^\d+\+[^@]+@users\.noreply\.github(?:usercontent)?\.com$", re.I),
    re.compile(r"@users\.noreply\.gitlab\.com$", re.I),
    re.compile(r"@noreply\.codeberg\.org$", re.I),
    re.compile(r"^(?:gitlab|github|bitbucket)-(?:bot|ci|actions)@", re.I),
    re.compile(r"^dependabot(?:\[bot\])?@", re.I),
    re.compile(r"^renovate(?:\[bot\])?@", re.I),
    re.compile(r"^[^@]*\[bot\]@", re.I),
    re.compile(r"^(?:jenkins|travis|circleci|drone|buildkite)@", re.I),
    re.compile(r"@(?:sentry|bugsnag|pagerduty)\.io$", re.I),
)

#: Hosts that exist only to receive machine mail.
_AUTOMATED_HOSTS = re.compile(
    r"(?:^|\.)(?:noreply|no-reply|donotreply|bounces?|mailer)\.", re.I)


@dataclass(frozen=True)
class AddressVerdict:
    """What kind of mailbox this is, and whether it is worth expanding."""

    #: "personal" | "role" | "automated"
    kind: str
    reason: str = ""

    @property
    def personal(self) -> bool:
        return self.kind == "personal"

    @property
    def expandable(self) -> bool:
        """Is it worth spending a lookup on?

        A role address is: it reaches the organisation, and for a one-person
        business it reaches the person too. An automated one is not - there is
        nobody on the other end and no corpus has heard of it.
        """
        return self.kind != "automated"

    @property
    def identifies_a_person(self) -> bool:
        """May a link through this address be read as evidence about someone?

        ``sales@`` appearing on two sites says those sites share a mailbox, not
        that they share an owner, and an investigation that cannot tell those
        apart will cheerfully merge a shop and its web designer.
        """
        return self.kind == "personal"

    def __bool__(self) -> bool:
        return self.expandable


def judge_address(address: str) -> AddressVerdict:
    """Classify one address. Never raises; an unparseable value is personal.

    Defaulting an oddity to ``personal`` is deliberate. The cost of expanding
    something that turns out to be a robot is a wasted minute; the cost of
    declining to expand a real person's address is the investigation missing
    its subject, and those are not the same mistake.
    """
    text = str(address or "").strip().strip("<>").casefold()
    if "@" not in text:
        return AddressVerdict("personal")
    local, _, host = text.rpartition("@")
    if not local or not host:
        return AddressVerdict("personal")

    for pattern in _PLATFORM_AUTOMATED:
        if pattern.search(text):
            return AddressVerdict(
                "automated",
                "a platform generates this address; no mail corpus, DNS record "
                "or search engine knows it")
    if _AUTOMATED_HOSTS.search(host):
        return AddressVerdict("automated", f"{host} only sends machine mail")

    # Plus-addressing and dot-folding hide the real local part, and a robot is
    # as likely to use them as anyone: noreply+abc123@ is still noreply.
    base = local.split("+")[0]
    if base in AUTOMATED_LOCALPARTS:
        return AddressVerdict("automated", f"'{base}@' is an unattended mailbox")
    if base in ROLE_LOCALPARTS:
        return AddressVerdict(
            "role", f"'{base}@' is a shared mailbox: it reaches the "
                    f"organisation, not a named person")
    return AddressVerdict("personal")
