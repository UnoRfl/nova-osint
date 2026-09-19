"""Module registry and target-type detection.

A module is a class with a ``name``, the ``accepts`` set of target types it can
handle, and a ``run`` method. Registering is a decorator, so adding a source is
one file plus one import - no central switchboard to edit.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

from .config import Config
from .http import Fetcher
from .models import ScanResult, TargetType

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_PHONE_RE = re.compile(r"^\+?[0-9][0-9\s().-]{6,20}$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{2,64}$")


def detect_type(target: str) -> TargetType:
    """Guess what kind of thing the user typed.

    Order matters: an IP is also a valid-looking string for other checks, and
    a phone number with dots looks like a username.
    """
    t = target.strip()
    if not t:
        return TargetType.UNKNOWN
    if t.startswith(("http://", "https://")):
        return TargetType.URL
    try:
        ipaddress.ip_address(t)
        return TargetType.IP
    except ValueError:
        pass
    if _EMAIL_RE.match(t):
        return TargetType.EMAIL
    # A leading + or a long run of digits is a phone, not a handle.
    digits = re.sub(r"\D", "", t)
    if _PHONE_RE.match(t) and (t.startswith("+") or len(digits) >= 10) and len(digits) >= 7:
        return TargetType.PHONE
    if _DOMAIN_RE.match(t):
        return TargetType.DOMAIN
    if _USERNAME_RE.match(t):
        return TargetType.USERNAME
    if _looks_like_a_name(t):
        return TargetType.PERSON
    return TargetType.UNKNOWN


#: One name token: letters, plus the punctuation real names contain. Digits are
#: excluded deliberately - "user 123" is not a name, and admitting it would turn
#: every stray two-word string into a person search.
_NAME_TOKEN = re.compile(r"^[^\W\d_]([^\W\d_]|['’.‐-―-])*\.?$", re.UNICODE)


def _looks_like_a_name(text: str) -> bool:
    """Is this a human name rather than a handle or a typo?

    Conservative on purpose, and it can only ever fire on input that used to be
    ``UNKNOWN``: the username pattern rejects spaces, so nothing that previously
    resolved to a handle can be stolen by this. The cost of a false positive
    here is a wasted person search; the cost of being too eager is that
    ``--type`` stops meaning anything.

    Accepts ``Ada Lovelace``, ``Jean-Luc Picard``, ``J. R. R. Tolkien``,
    ``Ursula K. Le Guin``, ``O'Brien Smith``. Rejects handles, anything with a
    digit, and anything over five tokens (that is a sentence, not a name).
    """
    tokens = text.split()
    if not 2 <= len(tokens) <= 5:
        return False
    return all(1 <= len(tok) <= 24 and _NAME_TOKEN.match(tok) for tok in tokens)


class Module:
    """Base class for every source.

    Subclasses set the class attributes and implement :meth:`run`. ``run``
    should never raise - it gets a fresh :class:`ScanResult` and fills it in.
    Anything that goes wrong belongs in ``result.error(...)``.
    """

    name: str = "module"
    title: str = "Module"
    description: str = ""
    accepts: frozenset[TargetType] = frozenset()
    #: True when the module sends traffic to infrastructure the target controls.
    active: bool = False
    #: Short name of an API key this module needs, or None if it is key-free.
    requires_key: str | None = None
    #: Rough cost hint used to order output and warn on long scans.
    slow: bool = False

    def __init__(self, fetcher: Fetcher, config: Config) -> None:
        self.http = fetcher
        self.config = config

    def run(self, target: str, result: ScanResult) -> None:  # pragma: no cover
        raise NotImplementedError

    # convenience ------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        # One source of truth: if there is a reason to skip, we skip, and the
        # CLI can print that same reason.
        return self.skip_reason() is None

    def skip_reason(self) -> str | None:
        if self.requires_key and not self.config.has(self.requires_key):
            from .config import KEY_ENV

            return f"needs ${KEY_ENV.get(self.requires_key, self.requires_key.upper())}"
        if self.active and self.config.passive_only:
            return "active module, passive-only mode"
        return None


_REGISTRY: dict[str, type[Module]] = {}


def register(cls: type[Module]) -> type[Module]:
    if cls.name in _REGISTRY:
        raise ValueError(f"duplicate module name: {cls.name}")
    _REGISTRY[cls.name] = cls
    return cls


def all_modules() -> list[type[Module]]:
    import_modules()
    return sorted(_REGISTRY.values(), key=lambda c: c.name)


def modules_for(target_type: TargetType) -> list[type[Module]]:
    return [c for c in all_modules() if target_type in c.accepts]


def get_module(name: str) -> type[Module] | None:
    import_modules()
    return _REGISTRY.get(name)


_imported = False


def import_modules() -> None:
    """Import every module package exactly once, populating the registry."""
    global _imported
    if _imported:
        return
    _imported = True
    from ..modules import (  # noqa: F401
        breach,
        correlators,
        declared,
        documents,
        domain,
        dorks,
        email,
        github,
        ip,
        people,
        phone,
        securitytrails,
        username,
        virustotal,
        web,
        websearch,
    )


#: Why a value cannot be the kind of thing it is about to be scanned as, per
#: type. ``detect_type`` only ever *guesses*; ``--type`` (and the desktop app's
#: type menu) overrides it, and nothing used to check the override made sense.
#:
#: Forcing ``--type username`` on a name with a space in it sent eight modules
#: at URLs containing that space. Every one raised ``InvalidURL`` before a byte
#: left the machine, and the report presented the wreckage as eight sources
#: failing and 405 sites being unreachable - a local mistake dressed up as the
#: internet's fault, which is the one thing this tool is built not to do.
_SHAPE_CHECKS: dict[TargetType, tuple[re.Pattern[str], str]] = {
    TargetType.USERNAME: (_USERNAME_RE,
                          "not a handle: usernames are letters, digits, dot, "
                          "dash and underscore, with no spaces"),
    TargetType.DOMAIN: (_DOMAIN_RE, "not a domain name"),
    TargetType.EMAIL: (_EMAIL_RE, "not an email address"),
}


def shape_problem(target: str, target_type: TargetType) -> str | None:
    """Why *target* cannot be scanned as *target_type*, or ``None`` if it can.

    Deliberately checks only the types whose values get interpolated into URLs
    and DNS names. A person's name and a phone number are messy by nature and
    the modules that take them cope; a handle is not, and pretending otherwise
    costs a whole scan.
    """
    check = _SHAPE_CHECKS.get(target_type)
    if check is None:
        return None
    pattern, reason = check
    if pattern.match(target.strip()):
        return None
    detected = detect_type(target)
    if detected not in (target_type, TargetType.UNKNOWN):
        reason += f" - it looks like a {detected.value}"
    return reason


def select(
    target_type: TargetType,
    only: Iterable[str] | None = None,
    exclude: Iterable[str] | None = None,
) -> list[type[Module]]:
    """Resolve the module list for a run, honouring --only / --exclude."""
    chosen = modules_for(target_type)
    if only:
        wanted = {n.strip().lower() for n in only}
        chosen = [c for c in all_modules() if c.name in wanted]
        unknown = wanted - {c.name for c in chosen}
        if unknown:
            raise ValueError(f"unknown module(s): {', '.join(sorted(unknown))}")
    if exclude:
        dropped = {n.strip().lower() for n in exclude}
        chosen = [c for c in chosen if c.name not in dropped]
    return chosen
