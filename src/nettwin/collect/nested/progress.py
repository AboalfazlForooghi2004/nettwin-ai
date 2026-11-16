"""Live terminal progress for recursive discovery (Phase 2.4).

Why a separate module
---------------------
``RecursiveDiscovery`` must stay a pure algorithm: it takes session factories,
walks CDP, and returns a result. Nothing here is imported by the discovery
package, so the walk can never become dependent on a terminal, on ``rich`` or
on wall-clock output. The CLI wires the two together through the small
:class:`DiscoveryObserver` protocol that discovery already exposes.

Design notes
------------
* **No fake percentages.** The total number of devices is not knowable up
  front — that is the whole point of recursive discovery. Instead the display
  shows what *is* known: how many devices are queued, how many are collected,
  and how many failed, plus real elapsed time.
* **Never lies about progress.** If a nested handshake takes 40 seconds, the
  spinner keeps turning and the elapsed clock keeps counting; the status line
  says what is actually being attempted.
* **CI-safe.** The renderer writes to stderr (so stdout stays the machine
  readable report), and :class:`NullProgress` is a no-op used whenever the
  output is not a TTY or ``--no-progress`` was passed.
* **No secrets.** Device identity, depth, path and command names only. The
  password never reaches this module.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Protocol, TextIO

#: A single sample of what the walk is doing right now.
STATUS_CONNECTING = "connecting to seed"
STATUS_NESTED_SSH = "nested ssh"
STATUS_REOPENING = "re-opening parent chain"
STATUS_COMMAND = "running command"
STATUS_PARSING = "parsing output"
STATUS_RETURNING = "returning to parent"


class DiscoveryObserver(Protocol):
    """The hooks ``RecursiveDiscovery`` calls. All are optional no-ops."""

    def discovery_started(self, seed: str, max_depth: int, max_devices: int) -> None: ...

    def device_discovered(self, identity: str, depth: int, path: list[str]) -> None: ...

    def device_started(self, identity: str, depth: int, path: list[str], via: str) -> None: ...

    def device_status(self, identity: str, status: str) -> None: ...

    def command_started(self, identity: str, command: str) -> None: ...

    def device_finished(self, identity: str, collected: bool, reason: str = "") -> None: ...

    def discovery_finished(self) -> None: ...


class NullProgress:
    """A silent observer: the default for CI, pipes and ``--no-progress``."""

    def discovery_started(self, seed: str, max_depth: int, max_devices: int) -> None:
        return None

    def device_discovered(self, identity: str, depth: int, path: list[str]) -> None:
        return None

    def device_started(self, identity: str, depth: int, path: list[str], via: str) -> None:
        return None

    def device_status(self, identity: str, status: str) -> None:
        return None

    def command_started(self, identity: str, command: str) -> None:
        return None

    def device_finished(self, identity: str, collected: bool, reason: str = "") -> None:
        return None

    def discovery_finished(self) -> None:
        return None


def _shorten(path: list[str], limit: int = 4) -> str:
    """Render an access path compactly: ``seed -> hop -> hop``."""
    shown = path if len(path) <= limit else [path[0], "...", *path[-2:]]
    return " -> ".join(shown)


class RichProgress:
    """A live, spinner-based view of the walk.

    Uses ``rich`` when it is importable and falls back to a plain
    line-per-event writer otherwise, so the CLI never crashes because a
    presentation library is missing.
    """

    def __init__(
        self,
        *,
        stream: TextIO | None = None,
        refresh_per_second: float = 8.0,
        force_plain: bool = False,
    ) -> None:
        self._stream = stream or sys.stderr
        self._refresh = refresh_per_second
        self._force_plain = force_plain
        self._rich_live = None
        self._progress = None
        self._task_id = None
        self._started_at = time.monotonic()
        self._finished_at: float | None = None
        self._max_depth = 0
        self._max_devices = 0
        self._seed = ""
        self._collected = 0
        self._failed = 0
        self._discovered = 0
        self._status = "starting"
        self._current = ""
        self._current_depth = 0
        self._current_path: list[str] = []
        self._command = ""

    # -- lifecycle ---------------------------------------------------------- #

    def __enter__(self) -> RichProgress:
        self._begin()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.discovery_finished()

    def _rich(self):
        """Import ``rich`` lazily so the core install stays dependency-free."""
        try:
            from rich.console import Console
            from rich.live import Live
            from rich.progress import (
                BarColumn,
                Progress,
                SpinnerColumn,
                TextColumn,
                TimeElapsedColumn,
            )
            from rich.table import Table
        except ImportError:  # pragma: no cover - exercised only without rich
            return None
        console = Console(file=self._stream, force_terminal=False, width=100)
        progress = Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[bold]{task.description}"),
            BarColumn(bar_width=18),
            TextColumn("{task.completed}/{task.total} devices"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )
        return Console, Live, progress, Table, console

    def _begin(self) -> None:
        self._started_at = time.monotonic()
        if self._force_plain or not self._stream.isatty():
            self._rich_live = None
            return
        rich = self._rich()
        if rich is None:
            self._rich_live = None
            return
        _Console, Live, progress, _Table, console = rich
        self._progress = progress
        # The bar tracks *devices seen*, not an imagined total: it grows as
        # discovery discovers. `total` is updated live and shown as "n seen".
        self._task_id = progress.add_task("starting", total=None)
        self._rich_live = Live(
            self._render(),
            console=console,
            refresh_per_second=self._refresh,
            transient=False,
        )
        self._rich_live.start()

    def _refresh_view(self) -> None:
        if self._rich_live is not None:
            self._rich_live.update(self._render())
        elif self._force_plain is False and self._stream.isatty():
            return
        else:
            # Plain, non-interactive mode: one line per meaningful event, written
            # only when something actually changed.
            self._emit_plain()

    def _render(self):
        """Build the live renderable (a table of counters + current activity)."""
        rich = self._rich()
        if rich is None:  # pragma: no cover
            return ""
        _Console, _Live, _progress, Table, _console = rich
        elapsed = (self._finished_at or time.monotonic()) - self._started_at
        table = Table.grid(padding=(0, 1))
        table.add_column(justify="right", style="dim", width=12)
        table.add_column()
        table.add_row("elapsed", f"{elapsed:6.1f}s")
        table.add_row(
            "devices",
            f"[green]{self._collected}[/green] collected / "
            f"{self._discovered} discovered"
            + (f"  [red]{self._failed} failed[/red]" if self._failed else ""),
        )
        if self._current:
            table.add_row(
                "current",
                f"[bold]{self._current}[/bold] "
                f"depth={self._current_depth} path={_shorten(self._current_path)}",
            )
        table.add_row("status", self._status)
        if self._command:
            table.add_row("command", f"[cyan]{self._command}[/cyan]")
        depth_note = f"depth<={self._max_depth}, devices<={self._max_devices}"
        table.add_row("limits", depth_note)
        return table

    def _emit_plain(self) -> None:
        elapsed = (self._finished_at or time.monotonic()) - self._started_at
        parts = [f"[{elapsed:6.1f}s]", self._status]
        if self._current:
            parts.append(
                f"{self._current} depth={self._current_depth} "
                f"path={_shorten(self._current_path)}"
            )
        if self._command:
            parts.append(f"cmd={self._command}")
        parts.append(f"{self._collected} collected / {self._discovered} discovered")
        if self._failed:
            parts.append(f"{self._failed} failed")
        self._stream.write("  ".join(parts) + "\n")
        self._stream.flush()

    # -- DiscoveryObserver -------------------------------------------------- #

    def discovery_started(self, seed: str, max_depth: int, max_devices: int) -> None:
        self._seed = seed
        self._max_depth = max_depth
        self._max_devices = max_devices
        self._started_at = time.monotonic()
        self._status = f"seeding from {seed}"
        self._refresh_view()

    def device_discovered(self, identity: str, depth: int, path: list[str]) -> None:
        self._discovered += 1
        if self._progress is not None and self._task_id is not None:
            self._progress.update(self._task_id, total=self._discovered)
        self._refresh_view()

    def device_started(self, identity: str, depth: int, path: list[str], via: str) -> None:
        self._current = identity
        self._current_depth = depth
        self._current_path = list(path)
        self._status = via
        self._command = ""
        self._refresh_view()

    def device_status(self, identity: str, status: str) -> None:
        self._status = status
        self._refresh_view()

    def command_started(self, identity: str, command: str) -> None:
        self._current = identity
        self._command = command
        self._status = STATUS_COMMAND
        self._refresh_view()

    def device_finished(self, identity: str, collected: bool, reason: str = "") -> None:
        if collected:
            self._collected += 1
        else:
            self._failed += 1
        self._status = "collected" if collected else (reason or "failed")
        self._command = ""
        self._refresh_view()

    def discovery_finished(self) -> None:
        self._finished_at = time.monotonic()
        self._status = "finished"
        if self._rich_live is not None:
            self._rich_live.update(self._render())
            self._rich_live.stop()
            self._rich_live = None

    # -- reporting ---------------------------------------------------------- #

    @property
    def elapsed(self) -> float:
        return (self._finished_at or time.monotonic()) - self._started_at


class SummaryTable:
    """Final, always-printed summary (independent of the live view)."""

    @staticmethod
    def render(
        *,
        devices: int,
        interfaces: int,
        routes: int,
        warnings: int,
        elapsed: float,
        collected: int,
        discovered: int,
    ) -> str:
        lines = [
            "",
            "================ SUMMARY ================",
            f"  devices     : {devices}",
            f"  interfaces  : {interfaces}",
            f"  routes      : {routes}",
            f"  warnings    : {warnings}",
            f"  collected   : {collected}/{discovered} discovered",
            f"  elapsed     : {elapsed:.1f}s",
            "=========================================",
        ]
        return "\n".join(lines)


@contextmanager
def progress_for(
    *,
    enabled: bool,
    stream: TextIO | None = None,
) -> Iterator[DiscoveryObserver]:
    """Yield the right observer and guarantee teardown.

    ``enabled`` is False for ``--no-progress``, for non-TTY output, and for
    CI. In that case a :class:`NullProgress` is returned and nothing is ever
    written to the terminal.
    """
    out = stream or sys.stderr
    if not enabled or not out.isatty():
        yield NullProgress()
        return
    ui = RichProgress(stream=out)
    ui._begin()
    try:
        yield ui
    finally:
        ui.discovery_finished()
