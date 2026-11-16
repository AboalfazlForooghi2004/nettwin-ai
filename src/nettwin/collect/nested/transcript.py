"""Scripted and recorded IOS transcripts for deterministic tests (Phase 2.3).

A :class:`ScriptedTransport` plays a fixed list of ``(expect, respond)`` steps.
Each step fires when the bytes written by the session *contain* the expected
fragment, so a test reads exactly like the console transcript an operator would
see:

    ScriptStep(expect="show version", respond="Cisco IOS Software ...\\nR2-1#")

:class:`ReplayTransport` replays a captured session file (a plain text
recording with ``>>> <command>`` markers), which lets a real PNETLab session be
frozen into a fixture later without changing any test.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


class TransportTimeout(Exception):
    """Raised by a transport when nothing arrives in time."""


@dataclass
class ScriptStep:
    """``respond`` is emitted once the written data contains ``expect``."""

    expect: str
    respond: str
    repeat: bool = False
    """When False the step is consumed; when True it may fire again."""


class ScriptedTransport:
    """Deterministic :class:`~nettwin.collect.nested.session.Transport` fake."""

    def __init__(self, steps: Sequence[ScriptStep], *, name: str = "scripted") -> None:
        self.name = name
        self._steps = list(steps)
        self._steps.reverse()  # pop() from the end preserves authored order
        self._pending = ""
        self._written: list[str] = []
        self.closed = False
        self.write_count = 0

    # -- Transport protocol ------------------------------------------------- #

    def read(self, timeout: float) -> str:  # noqa: ARG002 - deterministic fake
        if self._pending:
            chunk, self._pending = self._pending, ""
            return chunk
        if self.closed:
            return ""
        # Emit any step that is satisfied by everything written so far.
        written = "".join(self._written)
        for index in range(len(self._steps) - 1, -1, -1):
            step = self._steps[index]
            if step.expect in written:
                if not step.repeat:
                    self._steps.pop(index)
                return step.respond
        return ""

    def write(self, data: str) -> None:
        if self.closed:
            raise RuntimeError(f"{self.name}: write after close")
        self.write_count += 1
        self._written.append(data)

    def close(self) -> None:
        self.closed = True

    # -- assertions helpers ------------------------------------------------- #

    @property
    def written(self) -> str:
        """Everything the session has typed, in order."""
        return "".join(self._written)

    @property
    def remaining_steps(self) -> int:
        return len(self._steps)


class ReplayTransport:
    """Replay a recorded session file.

    File format (one command per section)::

        >>> show version
        Cisco IOS Software ...
        R2-1#

    A ``! timeout`` marker on its own line makes the next read return nothing,
    which is how timeout behaviour is captured.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._sections = _parse_replay(self.path.read_text(encoding="utf-8"))
        self.closed = False
        self._pending = ""
        self._command: str | None = None
        self._written: list[str] = []
        self._started = False
        self._initial = next((payload for fragment, payload in self._sections if fragment == ""), "")

    def read(self, timeout: float) -> str:  # noqa: ARG002
        if self._pending:
            chunk, self._pending = self._pending, ""
            return chunk
        if self.closed:
            return ""
        # The very first read yields the recorded initial prompt section.
        if not self._started:
            self._started = True
            return self._initial
        return ""

    def write(self, data: str) -> None:
        if self.closed:
            raise RuntimeError("replay: write after close")
        self._written.append(data)
        self._command = data.strip()
        for fragment, payload in self._sections:
            if fragment is not None and fragment == self._command:
                self._pending = payload
                return

    def close(self) -> None:
        self.closed = True


def _parse_replay(text: str) -> list[tuple[str | None, str]]:
    sections: list[tuple[str | None, str]] = []
    command: str | None = None
    buffer: list[str] = []
    for line in text.splitlines():
        if line.startswith(">>> "):
            if command is not None:
                sections.append((command, "\n".join(buffer).rstrip() + "\n"))
            command = line[4:].strip()
            buffer = []
        else:
            buffer.append(line)
    if command is not None:
        sections.append((command, "\n".join(buffer).rstrip() + "\n"))
    return sections
