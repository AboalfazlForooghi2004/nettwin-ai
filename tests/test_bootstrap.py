"""Basic bootstrap tests for TASK-001."""

from __future__ import annotations

import nettwin
from nettwin.main import main


def test_package_imports() -> None:
    assert nettwin.__version__ == "0.1.0"


def test_entry_point_runs(capsys) -> None:
    exit_code = main()
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "startup OK" in captured.out
