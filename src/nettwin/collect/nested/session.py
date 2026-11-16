"""Nested IOS SSH session handling (Phase 2.3, Task 4).

:class:`IosShellSession` is one device in the discovery tree. It owns a
:class:`~nettwin.collect.nested.transcript.Transport` — a byte channel — and
implements the interaction an operator performs:

    open()            read until a ``>``/``#`` prompt
    run_command(cmd)  send, read until the next prompt, return the output
    open_nested(...)  type ``ssh -l user <ip>`` and hand back a child session
    close()           type ``exit`` and return to the parent

Everything that can go wrong has an explicit error class, and **no secret is
ever placed in an exception message or a log line** (same sanitization policy
as the Phase-2 collector).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from nettwin.collect.nested.prompts import (
    IosPrompt,
    PromptKind,
    classify_prompt,
    failure_reason,
)


class SessionError(Exception):
    """Base class for nested-session failures."""


class SessionAuthError(SessionError):
    """The device rejected the credentials."""


class SessionTimeoutError(SessionError):
    """The device did not answer within the configured timeout."""


class SessionClosedError(SessionError):
    """The session ended unexpectedly (peer closed, exit without context)."""


class NestedConnectError(SessionError):
    """A nested ``ssh`` to a neighbour failed (refused/unreachable/auth)."""

    def __init__(self, message: str, kind: str) -> None:
        super().__init__(message)
        self.kind = kind  # "auth" | "refused" | "unreachable" | "timeout" | "hostkey"


@dataclass
class SessionLimits:
    """Configurable bounds; every field has a safe default (Task 5)."""

    connect_timeout: float = 20.0
    command_timeout: float = 30.0
    max_devices: int = 32
    max_depth: int = 8
    max_attempts_per_device: int = 2
    read_chunk: int = 4096
    poll_interval: float = 0.05
    #: Send ``terminal length 0`` on connect (privileged level needed). Opt-in
    #: because it is a device-setting change of scope — off by default so the
    #: collector stays strictly read-only unless the operator asks.
    disable_paging: bool = False
    #: Send ``enable`` when the session lands in user-exec ``>``. The Phase-2
    #: read-only account is documented as privilege 1, so this stays off.
    escalate_privilege: bool = False

    def __post_init__(self) -> None:
        if self.max_devices < 1:
            raise ValueError("max_devices must be >= 1")
        if self.max_depth < 0:
            raise ValueError("max_depth must be >= 0")
        if self.max_attempts_per_device < 1:
            raise ValueError("max_attempts_per_device must be >= 1")
        if self.connect_timeout <= 0 or self.command_timeout <= 0:
            raise ValueError("timeouts must be positive")


class Transport(Protocol):
    """Byte channel to one device (netmiko-backed in production)."""

    def read(self, timeout: float) -> str:
        """Return whatever arrived within ``timeout`` (empty string on none)."""

    def write(self, data: str) -> None: ...

    def close(self) -> None: ...


#: Factory shape: host/port/credentials -> a connected Transport.
TransportFactory = Callable[..., Transport]

_HOST_PROMPT_RE = re.compile(r"^(?P<host>[A-Za-z0-9_.\-]+)\s*[>#]\s*$")


def _sanitize(text: str, secret: str) -> str:
    """Replace every occurrence of ``secret`` in *untrusted* text.

    Substring replacement is deliberately aggressive: a partial redaction is a
    leak. The cost is that a short password eats common letters
    (``secret="p"`` turns "prompt" into "***rom***t"), so this must only ever
    be applied to text that came from the device or from a library exception —
    never to the diagnostic sentence we build around it. Our own wording is
    composed after sanitising, in :func:`_session_error`.
    """
    return text.replace(secret, "***") if secret else text


def _session_error(prefix: str, detail: str, secret: str, *, label: str | None = None) -> str:
    """Join our own ``prefix`` to untrusted ``detail``, sanitising the detail.

    ``label`` names the detail in the rendered message (for example
    ``"last output"``). Only ``detail`` passes through :func:`_sanitize`, so a
    short password can never mangle the operator-facing sentence.
    """
    safe_detail = _sanitize(detail, secret).strip()
    if not safe_detail:
        return prefix
    if label:
        return f"{prefix} ({label}: {safe_detail})"
    return f"{prefix}: {safe_detail}"


class IosShellSession:
    """One interactive IOS session, possibly nested inside another."""

    def __init__(
        self,
        *,
        host: str,
        transport: Transport,
        limits: SessionLimits,
        password: str | None = None,
        username: str | None = None,
        depth: int = 0,
        path: Sequence[str] = (),
    ) -> None:
        self.host = host
        self.depth = depth
        self.path = tuple(path) or (host,)
        self._transport = transport
        self._limits = limits
        self._password = password or ""
        self._username = username or ""
        self._closed = False
        self.hostname: str | None = None
        self.privilege: int = 0
        #: Full text of the most recent wait — lets callers inspect *why* a
        #: prompt appeared (IOS prints the ssh failure then returns to the
        #: parent prompt, so the prompt alone says "ready" while the truth is
        #: "the nested connection failed").
        self.last_buffer: str = ""
        #: True when the session was created by ``open_nested`` and has already
        #: reached a prompt during the handshake.
        self._already_open: bool = False

    # -- lifecycle ---------------------------------------------------------- #

    def open(self) -> IosPrompt:
        """Read until the device is ready at a ``>`` or ``#`` prompt."""
        if self._already_open:
            self._already_open = False
            return IosPrompt(
                PromptKind.PRIVILEGED if self.privilege >= 15 else PromptKind.READY,
                self.hostname,
                "",
            )
        prompt = self._await_prompt(self._limits.connect_timeout, context="initial prompt")
        if prompt.kind is PromptKind.USERNAME:
            if not self._username:
                raise SessionAuthError(
                    f"{self.host}: device asked for a username but none is configured"
                )
            self._transport.write(self._username + "\n")
            prompt = self._await_prompt(self._limits.connect_timeout, context="after username")
        if prompt.kind is PromptKind.PASSWORD:
            self._transport.write(self._password + "\n")
            prompt = self._await_prompt(self._limits.connect_timeout, context="after password")
        if prompt.kind is PromptKind.HOSTKEY:
            self._transport.write("yes\n")
            prompt = self._await_prompt(self._limits.connect_timeout, context="after host key")
        if prompt.kind is PromptKind.PASSWORD:
            self._transport.write(self._password + "\n")
            prompt = self._await_prompt(self._limits.connect_timeout, context="after password")

        self._remember_identity(prompt)
        if self._limits.escalate_privilege and prompt.kind is PromptKind.READY:
            prompt = self.run_command("enable")
            prompt = classify_prompt(prompt)
            self._remember_identity(prompt)
        if self._limits.disable_paging and self.privilege >= 15:
            self.run_command("terminal length 0")
        return prompt

    def close(self) -> None:
        """Leave this session, returning to the parent shell."""
        if self._closed:
            return
        self._closed = True
        try:
            self._transport.write("exit\n")
        except Exception:  # noqa: BLE001 - closing must never raise
            pass
        try:
            self._transport.close()
        except Exception:  # noqa: BLE001
            pass

    # -- command execution -------------------------------------------------- #

    def run_command(self, command: str, timeout: float | None = None) -> str:
        """Send ``command`` and return its output (prompt line removed)."""
        if self._closed:
            raise SessionClosedError(f"{self.host}: session is closed")
        self._transport.write(command + "\n")
        prompt = self._await_prompt(
            timeout if timeout is not None else self._limits.command_timeout,
            context=f"output of {command!r}",
        )
        if prompt.kind is PromptKind.ERROR:
            reason = failure_reason(prompt.raw) or "device reported an error"
            raise SessionError(f"{self.host}: {reason} (while running {command!r})")
        return self._pending_output

    def send_line(self, line: str) -> None:
        """Write a raw line (used for prompt answers)."""
        self._transport.write(line + "\n")

    # -- nested sessions ---------------------------------------------------- #

    def open_nested(
        self,
        *,
        neighbour_ip: str,
        username: str,
        password: str,
        transport_factory: TransportFactory,
        host_key_confirmation: str = "yes",
    ) -> IosShellSession:
        """Open ``ssh -l <username> <neighbour_ip>`` from this device.

        The nested session uses an independent transport supplied by
        ``transport_factory``: in production it is the same TCP/SSH client the
        parent used, pointed at the *next hop* through the device's own
        forwarding — in tests it is a scripted transcript.
        """
        if self._closed:
            raise SessionClosedError(f"{self.host}: cannot nest from a closed session")

        self._transport.write(f"ssh -l {username} {neighbour_ip}\n")
        prompt = self._await_prompt(self._limits.connect_timeout, context="ssh handshake")

        # Host-key confirmation is answered once, then re-read.
        if prompt.kind in {PromptKind.HOSTKEY, PromptKind.CONFIRM}:
            self._transport.write(host_key_confirmation + "\n")
            prompt = self._await_prompt(self._limits.connect_timeout, context="after host key")
        # From the password prompt onward the conversation belongs to the
        # NEIGHBOUR, so the credentials are written to the child transport, not
        # to the parent. Mixing the two channels is the classic nested-SSH bug:
        # the password would be typed into the parent's console and lost.
        child_transport: Transport | None = None
        if prompt.kind is PromptKind.USERNAME:
            child_transport = transport_factory(
                host=neighbour_ip, username=username, password=password, parent=self
            )
            child_transport.write(username + "\n")
            prompt = self._await_on(child_transport, "after username")
        if prompt.kind is PromptKind.PASSWORD:
            if child_transport is None:
                child_transport = transport_factory(
                    host=neighbour_ip, username=username, password=password, parent=self
                )
            child_transport.write(password + "\n")
            prompt = self._await_on(child_transport, "after password")
        if prompt.kind is PromptKind.PASSWORD:
            # Some IOS releases re-prompt; one retry only, never a loop.
            child_transport.write(password + "\n")
            prompt = self._await_on(child_transport, "after retry")

        # A returned prompt is not proof of success: IOS prints the failure and
        # drops straight back to the parent prompt. Check the whole buffer.
        reported = failure_reason(self.last_buffer)
        if reported is not None:
            raise NestedConnectError(
                _session_error(f"{self.host} -> {neighbour_ip}", reported, password),
                _classify_nested_failure(reported),
            )
        if prompt.kind is PromptKind.ERROR or not prompt.is_ready:
            reason = failure_reason(prompt.raw) or prompt.raw or "unexpected prompt"
            raise NestedConnectError(
                _session_error(f"{self.host} -> {neighbour_ip}", reason, password),
                _classify_nested_failure(reason),
            )

        if child_transport is None:
            child_transport = transport_factory(
                host=neighbour_ip, username=username, password=password, parent=self
            )
        child = IosShellSession(
            host=neighbour_ip,
            transport=child_transport,
            limits=self._limits,
            password=password,
            username=username,
            depth=self.depth + 1,
            path=(*self.path, neighbour_ip),
        )
        child.hostname = prompt.hostname
        child.privilege = prompt.privilege
        # The handshake above already reached the neighbour's prompt, so the
        # child must not wait for it a second time.
        child._already_open = True
        # The child's own prompts come from the nested transport; the parent's
        # transport is untouched until the child is closed.
        return child

    # -- internals ---------------------------------------------------------- #

    _pending_output: str = ""

    def _remember_identity(self, prompt: IosPrompt) -> None:
        if prompt.hostname:
            self.hostname = prompt.hostname
        if prompt.privilege:
            self.privilege = prompt.privilege

    def _await_on(self, transport: Transport, context: str) -> IosPrompt:
        """Await a prompt on a specific transport (the child during a handshake)."""
        import time

        deadline = time.monotonic() + self._limits.connect_timeout
        buffer = ""
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SessionTimeoutError(
                    _session_error(
                        f"{self.host} -> nested: timeout waiting for {context} after "
                        f"{self._limits.connect_timeout}s",
                        f"{buffer[-120:]!r}",
                        self._password,
                        label="last output",
                    )
                )
            chunk = transport.read(min(remaining, 1.0))
            if chunk:
                buffer += chunk
                if any(marker in buffer for marker in ("--More--", "<More>")):
                    transport.write(" ")
                    buffer = buffer.replace("--More--", "").replace("<More>", "")
                    continue
                prompt = classify_prompt(buffer)
                if prompt.kind is not PromptKind.UNKNOWN:
                    self.last_buffer = buffer
                    return prompt
            else:
                time.sleep(self._limits.poll_interval)

    def _await_prompt(self, timeout: float, *, context: str) -> IosPrompt:
        """Accumulate device output until a recognised prompt (or failure)."""
        import time

        deadline = time.monotonic() + timeout
        buffer = ""
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SessionTimeoutError(
                    _session_error(
                        f"{self.host}: timeout waiting for {context} after {timeout}s",
                        f"{buffer[-120:]!r}",
                        self._password,
                        label="last output",
                    )
                )
            chunk = self._transport.read(min(remaining, 1.0))
            if chunk:
                buffer += chunk
                if any(marker in buffer for marker in ("--More--", "<More>")):
                    self._transport.write(" ")
                    buffer = buffer.replace("--More--", "").replace("<More>", "")
                    continue
                prompt = classify_prompt(buffer)
                if prompt.kind is not PromptKind.UNKNOWN:
                    self.last_buffer = buffer
                    self._pending_output = _strip_prompt(buffer, prompt)
                    self._remember_identity(prompt)
                    return prompt
            else:
                time.sleep(self._limits.poll_interval)

    def __enter__(self) -> IosShellSession:
        self.open()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def _strip_prompt(buffer: str, prompt: IosPrompt) -> str:
    """Remove the trailing prompt line from a response buffer."""
    lines = buffer.splitlines()
    while lines and not lines[-1].strip():
        lines.pop()
    if lines and _HOST_PROMPT_RE.match(lines[-1].strip()):
        lines.pop()
    return "\n".join(lines)


def _classify_nested_failure(reason: str) -> str:
    lowered = reason.lower()
    if "authentication" in lowered or "permission denied" in lowered:
        return "auth"
    if "refused" in lowered:
        return "refused"
    if "timed out" in lowered or "timeout" in lowered:
        return "timeout"
    if "host key" in lowered:
        return "hostkey"
    return "unreachable"
