"""Recursive multi-hop discovery through nested IOS SSH sessions (Phase 2.3).

The lab access path is::

    Ubuntu ──SSH──> R2-1 ──SSH──> R2-2 ──SSH──> R2-4

R2-2 and R2-4 are not reachable from the workstation. The only tested path is
the IOS CLI's own ``ssh`` command, so NetTwin drives it exactly like an
operator would type it: open a session on R2-1, type ``ssh -l user <ip>``,
answer the prompts, run the read-only discovery commands, then ``exit`` to
return to the parent session.

Layers (each testable without a real device):

``prompts``
    Recognise IOS prompt fragments: user-exec ``>``, privileged ``#``, the
    SSH password prompt, the host-key confirmation, ``username:``, command
    errors, and the "connection refused/timed out" messages.

``session``
    One :class:`IosShellSession` per device. It wraps a byte-level transport
    (netmiko in production, a scripted fake in tests) and exposes
    ``run_command`` / ``open_nested`` / ``close``.

``transcript``
    Replays a recorded or scripted IOS conversation so the orchestration can
    be tested deterministically without any socket.

Nothing here writes configuration: the only commands ever sent are the
allowlisted ``show`` commands plus the navigation verbs ``ssh``, ``exit``,
``terminal length 0`` and ``enable`` (the last two are operator conveniences
that change no device state and are opt-in).
"""

from __future__ import annotations

from nettwin.collect.nested.prompts import (
    IosPrompt,
    PromptKind,
    classify_prompt,
    looks_like_failure,
)
from nettwin.collect.nested.session import (
    IosShellSession,
    NestedConnectError,
    SessionAuthError,
    SessionClosedError,
    SessionError,
    SessionLimits,
    SessionTimeoutError,
    Transport,
    TransportFactory,
)
from nettwin.collect.nested.transcript import (
    ReplayTransport,
    ScriptedTransport,
    ScriptStep,
)

__all__ = [
    "IosPrompt",
    "IosShellSession",
    "NestedConnectError",
    "PromptKind",
    "ReplayTransport",
    "ScriptStep",
    "ScriptedTransport",
    "SessionAuthError",
    "SessionClosedError",
    "SessionError",
    "SessionLimits",
    "SessionTimeoutError",
    "Transport",
    "TransportFactory",
    "classify_prompt",
    "looks_like_failure",
]
