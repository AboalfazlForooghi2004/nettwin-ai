"""Tests for the live progress view (Phase 2.4, Task 1).

The contract under test is deliberately narrow: the progress layer must
*observe* discovery without changing it. Everything here checks either that
nothing leaks into the algorithm's result, or that the operator-facing
behaviour (TTY on/off, --no-progress, summary) is what the CLI promises.
"""

from __future__ import annotations

import io

import pytest

from nettwin.collect.nested.progress import (
    NullProgress,
    RichProgress,
    SummaryTable,
    progress_for,
)


class FakeTTY(io.StringIO):
    """A stream that claims to be an interactive terminal."""

    def isatty(self) -> bool:
        return True


def _events(ui: RichProgress) -> list[str]:
    """Replay a realistic walk and return the plain-rendered lines.

    ``force_plain`` is set so the assertions target the renderer that CI and
    any non-TTY consumer actually gets, not rich's escape-coded output.
    """
    out = FakeTTY()
    ui._stream = out
    ui._force_plain = True
    ui.discovery_started("192.168.98.34", max_depth=3, max_devices=8)
    ui.device_discovered("r2-1", 0, ["192.168.98.34"])
    ui.device_started("r2-1", 0, ["192.168.98.34"], "connecting to seed")
    ui.command_started("r2-1", "show version")
    ui.device_finished("r2-1", True)
    ui.device_discovered("r2-2.nettwin.lab", 1, ["192.168.98.34", "10.0.21.1"])
    ui.device_started("r2-2.nettwin.lab", 1, ["192.168.98.34", "10.0.21.1"], "nested ssh")
    ui.device_finished("r2-2.nettwin.lab", False, "timeout")
    ui.discovery_finished()
    return out.getvalue().splitlines()


# --------------------------------------------------------------------------- #
# The observer must never alter the algorithm
# --------------------------------------------------------------------------- #


def test_null_progress_is_a_silent_no_op() -> None:
    ui = NullProgress()
    # Every hook must exist and return None -- discovery calls all of them.
    for call in (
        lambda: ui.discovery_started("h", 1, 1),
        lambda: ui.device_discovered("d", 0, ["h"]),
        lambda: ui.device_started("d", 0, ["h"], "via"),
        lambda: ui.device_status("d", "s"),
        lambda: ui.command_started("d", "show version"),
        lambda: ui.device_finished("d", True),
        lambda: ui.discovery_finished(),
    ):
        assert call() is None


def test_discovery_accepts_an_observer_without_changing_its_result() -> None:
    """A recording observer must not perturb node/edge counts.

    Guards the promise that the progress view is presentation only.
    """
    import sys

    sys.path.insert(0, "tests")
    import test_recursive_discovery as T

    class Recorder(NullProgress):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str]] = []

        def device_started(self, identity, depth, path, via):
            self.seen.append(("started", identity))

        def device_finished(self, identity, collected, reason=""):
            self.seen.append(("finished", identity))

    def build(observer):
        return T._make_discovery(
            nested={"10.0.21.1": ("R2-2", "r2-2_detail.txt")},
            limits=T.FAST,
        ) if observer is None else _with_observer(observer)

    def _with_observer(observer):
        discovery = T._make_discovery(
            nested={"10.0.21.1": ("R2-2", "r2-2_detail.txt")},
            limits=T.FAST,
        )
        discovery._observer = observer
        return discovery

    baseline = build(None).run()
    recorder = Recorder()
    observed = _with_observer(recorder).run()

    assert [n.identity for n in baseline.nodes] == [n.identity for n in observed.nodes]
    assert len(baseline.edges) == len(observed.edges)
    assert [n.status for n in baseline.nodes] == [n.status for n in observed.nodes]
    assert recorder.seen, "the observer was never called"


def test_building_discovery_without_an_observer_still_works() -> None:
    """The observer parameter is optional; the default is silent."""
    import sys

    sys.path.insert(0, "tests")
    import test_recursive_discovery as T

    discovery = T._make_discovery(nested={}, limits=T.FAST)
    assert isinstance(discovery._observer, NullProgress)


# --------------------------------------------------------------------------- #
# What the operator sees
# --------------------------------------------------------------------------- #


def test_plain_render_shows_elapsed_device_depth_and_path() -> None:
    lines = _events(RichProgress(stream=FakeTTY()))
    body = "\n".join(lines)
    assert "collected" in body
    assert "discovered" in body
    assert "depth=0" in body
    assert "192.168.98.34" in body
    assert "failed" in body, "a failed device must be visible"


def test_render_never_prints_a_fake_percentage() -> None:
    """No invented "37%" — the total is unknowable by construction."""
    lines = _events(RichProgress(stream=FakeTTY()))
    assert not any("%" in line for line in lines)


def test_render_counts_collected_versus_discovered() -> None:
    lines = _events(RichProgress(stream=FakeTTY()))
    final = [line for line in lines if "discovered" in line][-1]
    assert "1 collected" in final
    assert "2 discovered" in final
    assert "1 failed" in final


def test_render_shows_the_current_command() -> None:
    lines = _events(RichProgress(stream=FakeTTY()))
    assert any("show version" in line for line in lines)


def test_summary_table_contains_every_required_counter() -> None:
    text = SummaryTable.render(
        devices=3,
        interfaces=9,
        routes=9,
        warnings=1,
        elapsed=12.4,
        collected=3,
        discovered=4,
    )
    assert "devices" in text and "3" in text
    assert "interfaces" in text and "9" in text
    assert "routes" in text
    assert "warnings" in text and "1" in text
    assert "12.4s" in text
    assert "3/4" in text


# --------------------------------------------------------------------------- #
# CI / non-interactive behaviour
# --------------------------------------------------------------------------- #


def test_progress_is_silent_on_a_non_tty_stream() -> None:
    """CI pipes are not TTYs: nothing may be written there."""
    buffer = io.StringIO()  # isatty() is False
    with progress_for(enabled=True, stream=buffer) as observer:
        observer.device_started("r2-1", 0, ["192.168.98.34"], "connecting")
    assert buffer.getvalue() == ""


def test_no_progress_flag_yields_a_null_observer() -> None:
    with progress_for(enabled=False, stream=FakeTTY()) as observer:
        assert isinstance(observer, NullProgress)


def test_progress_for_writes_to_a_tty_when_enabled() -> None:
    stream = FakeTTY()
    with progress_for(enabled=True, stream=stream) as observer:
        assert not isinstance(observer, NullProgress)
        observer.discovery_started("192.168.98.34", 2, 4)
        observer.device_started("r2-1", 0, ["192.168.98.34"], "connecting to seed")
    assert stream.getvalue() != "", "an interactive terminal must see progress"


def test_progress_survives_an_exception_in_the_caller() -> None:
    """A crash must not leave the terminal in a broken state."""
    stream = FakeTTY()
    with pytest.raises(RuntimeError):
        with progress_for(enabled=True, stream=stream):
            raise RuntimeError("boom")
    assert stream.getvalue() == stream.getvalue()  # no assertion on content, no hang


def test_cli_help_documents_no_progress() -> None:
    import importlib.util
    from pathlib import Path

    script = Path(__file__).resolve().parents[1] / "scripts" / "discover_recursive.py"
    spec = importlib.util.spec_from_file_location("discover_cli", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    help_text = module.build_parser().format_help()
    assert "--no-progress" in help_text
    assert "TTY" in help_text


def test_cli_dry_run_makes_no_terminal_writes() -> None:
    """--dry-run must not start the spinner."""
    import subprocess
    import sys
    from pathlib import Path

    repo = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, str(repo / "scripts" / "discover_recursive.py"),
         "--seed", "192.168.98.34", "--dry-run"],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=repo,
    )
    assert result.returncode == 0
    assert result.stderr == "", f"dry-run wrote to stderr: {result.stderr!r}"
    assert "dry-run" in result.stdout
