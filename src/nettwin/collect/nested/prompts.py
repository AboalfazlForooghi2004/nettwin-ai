"""IOS prompt classification for nested sessions (Phase 2.3).

IOS does not have one prompt format: the hostname varies, the privilege level
shows as ``>`` or ``#``, pagination may append ``--More--``, and interactive
sub-prompts (SSH password, host-key confirmation, ``username:``) appear mid
stream. This module turns a raw response buffer into one explicit
:class:`PromptKind` so the session layer never has to guess.

The rules are deliberately conservative: an unrecognised buffer is
``UNKNOWN``, never ``READY``. A caller that treats ``UNKNOWN`` as ready would
sail past a prompt it did not understand, which is exactly the failure mode
that corrupts a collected output.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class PromptKind(StrEnum):
    """What the device is currently waiting for."""

    READY = "ready"                    # user-exec ">"
    PRIVILEGED = "privileged"          # enable "#"
    PASSWORD = "password"              # SSH password prompt
    USERNAME = "username"              # SSH login prompt
    HOSTKEY = "hostkey"                # "[yes/no]:" confirmation
    CONFIRM = "confirm"                # generic "[confirm]" / "(y/n)"
    MORE = "more"                      # pagination "--More--"
    ERROR = "error"                    # "% ..." command failure
    CLOSED = "closed"                  # session ended / peer closed
    UNKNOWN = "unknown"                # nothing recognised — do NOT assume ready


_PROMPT_RE = re.compile(r"(?:^|\n)\s*(?P<host>[A-Za-z0-9_.\-]+)(?:\([^)]*\))?\s*(?P<sig>[>#])\s*$")

_PASSWORD_PATTERNS = (
    re.compile(r"(?:^|\n)\s*Password:\s*$", re.IGNORECASE),
    re.compile(r"(?:password|passcode):\s*$", re.IGNORECASE),
)
_USERNAME_PATTERNS = (
    re.compile(r"(?:^|\n)\s*(?:Username|login as):\s*$", re.IGNORECASE),
)
_HOSTKEY_PATTERNS = (
    re.compile(r"\(yes/no(?:/fingerprint)?\)\?:\s*$", re.IGNORECASE),
    re.compile(r"Are you sure you want to continue connecting", re.IGNORECASE),
)
_CONFIRM_PATTERNS = (
    re.compile(r"\[confirm\]", re.IGNORECASE),
    re.compile(r"\(y/n\)\s*\[?[a-z]?\]?:\s*$", re.IGNORECASE),
)
_MORE_PATTERNS = (
    re.compile(r"--\s*More\s*--"),
    re.compile(r"<\s*More\s*>"),
)

#: Messages IOS prints when the nested ssh itself fails. These are *device*
#: output, not transport errors, so they must be detected in the text.
_FAILURE_PATTERNS = (
    re.compile(r"Connection refused by remote host", re.IGNORECASE),
    re.compile(r"Connection timed out", re.IGNORECASE),
    re.compile(r"Connection closed by remote host", re.IGNORECASE),
    re.compile(r"Connection to \S+ closed", re.IGNORECASE),
    re.compile(r"% ?Connection (?:refused|timed out)", re.IGNORECASE),
    re.compile(r"% ?Authentication failed", re.IGNORECASE),
    re.compile(r"% ?Invalid input", re.IGNORECASE),
    re.compile(r"% ?Unknown command", re.IGNORECASE),
    re.compile(r"Host key verification failed", re.IGNORECASE),
    re.compile(r"Permission denied", re.IGNORECASE),
    re.compile(r"No route to host", re.IGNORECASE),
    re.compile(r"Network is unreachable", re.IGNORECASE),
    re.compile(r"Destination unreachable", re.IGNORECASE),
)


@dataclass(frozen=True)
class IosPrompt:
    """A classified prompt with the captured hostname (when it has one)."""

    kind: PromptKind
    hostname: str | None = None
    raw: str = ""

    @property
    def is_ready(self) -> bool:
        """True only for ``>`` / ``#`` — the two states commands may be sent in."""
        return self.kind in {PromptKind.READY, PromptKind.PRIVILEGED}

    @property
    def privilege(self) -> int:
        return 15 if self.kind is PromptKind.PRIVILEGED else 1


def classify_prompt(buffer: str) -> IosPrompt:
    """Classify the tail of a device response.

    Order matters: interactive sub-prompts are checked before the shell
    prompts because ``Password:`` may appear on the same line as a previous
    prompt fragment.
    """
    if not buffer:
        return IosPrompt(PromptKind.UNKNOWN, None, "")

    tail = buffer[-400:]
    stripped_tail = tail.rstrip()
    # The buffer may end without trailing whitespace; patterns anchor on $.

    if any(p.search(stripped_tail) for p in _MORE_PATTERNS):
        return IosPrompt(PromptKind.MORE, None, stripped_tail[-120:])
    if any(p.search(stripped_tail) for p in _HOSTKEY_PATTERNS):
        return IosPrompt(PromptKind.HOSTKEY, None, stripped_tail[-120:])
    if any(p.search(stripped_tail) for p in _PASSWORD_PATTERNS):
        return IosPrompt(PromptKind.PASSWORD, None, stripped_tail[-120:])
    if any(p.search(stripped_tail) for p in _USERNAME_PATTERNS):
        return IosPrompt(PromptKind.USERNAME, None, stripped_tail[-120:])
    if any(p.search(stripped_tail) for p in _CONFIRM_PATTERNS):
        return IosPrompt(PromptKind.CONFIRM, None, stripped_tail[-120:])

    match = _PROMPT_RE.search(stripped_tail)
    if match:
        hostname = match.group("host")
        # Reject obvious false positives such as "[confirm]" already handled
        # above, or output lines like "R2-1#" inside a transcript body: the
        # regex is anchored to the very end of the buffer.
        kind = PromptKind.PRIVILEGED if match.group("sig") == "#" else PromptKind.READY
        return IosPrompt(kind, hostname, stripped_tail[-120:])

    if looks_like_failure(stripped_tail):
        return IosPrompt(PromptKind.ERROR, None, stripped_tail[-200:])

    if any(marker in stripped_tail for marker in ("Connection closed", "closed by")):
        return IosPrompt(PromptKind.CLOSED, None, stripped_tail[-120:])

    return IosPrompt(PromptKind.UNKNOWN, None, stripped_tail[-120:])


def looks_like_failure(text: str) -> bool:
    """True when the device reported a connection/auth/command failure."""
    return any(pattern.search(text) for pattern in _FAILURE_PATTERNS)


def failure_reason(text: str) -> str | None:
    """Return the matched failure message, or ``None``."""
    for pattern in _FAILURE_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(0).strip()
    return None
