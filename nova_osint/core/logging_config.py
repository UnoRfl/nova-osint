"""Logging, with secrets scrubbed on the way out.

Everything that is *narration* - which module started, which source answered
429, how long a retry waited - belongs here and goes to **stderr**. The report
itself goes to stdout, so ``nova scan x -f json | jq`` keeps working no matter
how loud the log is.

The one rule this module exists to enforce: an API key must never reach a log
file. :class:`SecretRedactingFilter` sits on every handler and rewrites the
formatted message, so even a module that carelessly logs a full request URL
containing ``?apikey=...`` produces ``?apikey=***`` on disk.
"""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import Iterable
from pathlib import Path

#: Root logger for the whole application. Modules use :func:`get_logger`.
LOGGER_NAME = "nova"

#: ``-v`` once is INFO, twice is DEBUG, none is WARNING.
LEVELS = {0: logging.WARNING, 1: logging.INFO, 2: logging.DEBUG}

REDACTED = "***"


class SecretRedactingFilter(logging.Filter):
    """Removes known secret values and secret-looking parameters from records.

    Two layers, because either one alone leaks:

    * **exact values** - every API key the config loaded is matched literally,
      which catches a key logged in any position or format.
    * **patterns** - ``?token=abc`` and ``Authorization: Bearer abc`` are
      redacted even when the value is one this process never loaded (a key
      pasted into a ``--only`` argument, a URL echoed back by a remote error).

    The record's message is formatted here and the args are dropped, which
    costs the lazy-formatting optimisation. For a CLI that logs tens of lines
    per scan this is not a trade worth thinking about.
    """

    QUERY_PARAM = re.compile(
        r"(?i)([?&](?:key|apikey|api_key|access_key|token|access_token|auth|"
        r"password|passwd|secret|signature|sig)=)[^&\s\"']+"
    )
    HEADER_LIKE = re.compile(
        r"(?i)\b(authorization|hibp-api-key|x-api-key|x-auth-token|api-key)"
        r"(\s*[:=]\s*)(?:bearer\s+)?\S+"
    )

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        super().__init__()
        # Sorted longest-first so a key that contains another key as a prefix
        # is redacted whole rather than leaving a tail behind.
        self._secrets: list[str] = sorted({s for s in secrets if s and len(s) >= 6}, key=len,
                                          reverse=True)

    def add_secrets(self, secrets: Iterable[str]) -> None:
        """Register more literal values to scrub (called once keys are loaded)."""
        merged = set(self._secrets) | {s for s in secrets if s and len(s) >= 6}
        self._secrets = sorted(merged, key=len, reverse=True)

    def redact(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, REDACTED)
        text = self.QUERY_PARAM.sub(rf"\1{REDACTED}", text)
        text = self.HEADER_LIKE.sub(rf"\1\2{REDACTED}", text)
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except (TypeError, ValueError):
            # A bad format string is a bug in the caller, not a reason to lose
            # the line - keep the raw template and carry on.
            message = str(record.msg)
        record.msg = self.redact(message)
        record.args = ()
        if record.exc_text:
            record.exc_text = self.redact(record.exc_text)
        return True


#: One shared filter instance: :func:`register_secrets` can add values to it
#: after the handlers are already attached.
_REDACTOR = SecretRedactingFilter()


class _PlainFormatter(logging.Formatter):
    """``[INFO] message``, which is what the console wants."""

    def format(self, record: logging.LogRecord) -> str:
        base = f"[{record.levelname}] {record.getMessage()}"
        if record.exc_info:
            base += "\n" + self.formatException(record.exc_info)
        return base


def setup_logging(
    verbosity: int = 0,
    log_file: Path | None = None,
    *,
    secrets: Iterable[str] = (),
    stream: object | None = None,
) -> logging.Logger:
    """Configure the ``nova`` logger and return it.

    Safe to call twice (the GUI and the CLI both call it): existing handlers
    are removed first, so a second call reconfigures rather than duplicating
    every line.
    """
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG)  # handlers decide what actually gets emitted
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    _REDACTOR.add_secrets(secrets)

    console = logging.StreamHandler(stream or sys.stderr)
    console.setLevel(LEVELS.get(max(0, min(verbosity, 2)), logging.DEBUG))
    console.setFormatter(_PlainFormatter())
    console.addFilter(_REDACTOR)
    logger.addHandler(console)

    if log_file is not None:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            disk = logging.FileHandler(log_file, encoding="utf-8")
        except OSError as exc:
            # A log file we cannot open is a warning, never a dead scan.
            logger.warning("could not open log file %s: %s", log_file, exc)
        else:
            disk.setLevel(logging.DEBUG)
            disk.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
            )
            disk.addFilter(_REDACTOR)
            logger.addHandler(disk)

    return logger


def register_secrets(secrets: Iterable[str]) -> None:
    """Add values that must never appear in a log line."""
    _REDACTOR.add_secrets(secrets)


def redact(text: str) -> str:
    """Scrub a string with the same rules the log handlers use."""
    return _REDACTOR.redact(text)


def get_logger(name: str = "") -> logging.Logger:
    """``get_logger("dns")`` -> the ``nova.dns`` logger."""
    return logging.getLogger(f"{LOGGER_NAME}.{name}" if name else LOGGER_NAME)
