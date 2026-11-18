"""Phase 2.5 — the discovery run directory contract. **OFFLINE ONLY.**

A successful run must leave four files in one directory, and the two visual
ones must be pure functions of ``topology.yaml``:

    collected/<run>/
        discovery.yaml     what happened during the walk
        topology.yaml      the normalized topology
        topology.html      interactive, self-contained
        topology.svg       standalone vector
        raw_evidence.yaml  raw OSPF CLI text, for diagnosing a parse defect

These tests drive the real recursive engine with scripted IOS transcripts and
then assert the artifacts, so a regression in wiring (rather than in rendering)
is caught too.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

from nettwin.domain.models import Topology
from nettwin.render import render_html, render_svg
from test_recursive_links import _make_discovery


def _write_run_dir(result, out: Path) -> Path:  # noqa: ANN001 - result object
    """Mirror exactly what ``scripts/discover_recursive.py`` writes."""
    out.mkdir(parents=True, exist_ok=True)
    (out / "topology.yaml").write_text(
        yaml.safe_dump(result.topology.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )
    (out / "topology.svg").write_text(render_svg(result.topology, title="t"), encoding="utf-8")
    (out / "topology.html").write_text(
        render_html(result.topology, title="t", run_id=out.name), encoding="utf-8"
    )
    (out / "discovery.yaml").write_text(
        yaml.safe_dump({"seed": "192.168.98.34", "warnings": result.warnings}),
        encoding="utf-8",
    )
    # Raw OSPF CLI evidence. Written unconditionally by the real writer, so the
    # mirror must write it too — a mirror that drifts from the writer is how the
    # raw_commands field came to be retained but never persisted.
    (out / "raw_evidence.yaml").write_text(
        yaml.safe_dump(
            {
                "note": "raw OSPF CLI evidence",
                "commands_retained": [],
                "device_count": 0,
                "block_count": 0,
                "devices": [],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return out


def test_run_directory_has_all_four_artifacts(tmp_path: Path) -> None:
    result = _make_discovery(
        nested={
            "10.0.21.1": ("R2-2", "recip_r2-2_detail.txt"),
            "10.0.41.1": ("R2-4", "recip_r2-4_detail.txt"),
        }
    ).run()
    out = _write_run_dir(result, tmp_path / "run1")
    names = {p.name for p in out.iterdir()}
    assert names == {
        "discovery.yaml",
        "topology.yaml",
        "topology.html",
        "topology.svg",
        "raw_evidence.yaml",
    }


def test_topology_yaml_contains_the_confirmed_links(tmp_path: Path) -> None:
    result = _make_discovery(
        nested={
            "10.0.21.1": ("R2-2", "recip_r2-2_detail.txt"),
            "10.0.41.1": ("R2-4", "recip_r2-4_detail.txt"),
        }
    ).run()
    out = _write_run_dir(result, tmp_path / "run1")
    data = yaml.safe_load((out / "topology.yaml").read_text(encoding="utf-8"))
    assert len(data["links"]) == 3
    assert len(data["devices"]) == 3
    # links survive the round-trip back into the validated model
    reloaded = Topology.model_validate(data)
    assert len(reloaded.links) == 3


def test_html_and_svg_are_rendered_from_the_yaml_that_was_written(tmp_path: Path) -> None:
    """The visualisations are a function of the normalized data, not of the CLI."""
    result = _make_discovery(
        nested={
            "10.0.21.1": ("R2-2", "recip_r2-2_detail.txt"),
            "10.0.41.1": ("R2-4", "recip_r2-4_detail.txt"),
        }
    ).run()
    out = _write_run_dir(result, tmp_path / "run1")

    reloaded = Topology.model_validate(
        yaml.safe_load((out / "topology.yaml").read_text(encoding="utf-8"))
    )
    assert render_svg(reloaded, title="t") == (out / "topology.svg").read_text(encoding="utf-8")

    html = (out / "topology.html").read_text(encoding="utf-8")
    match = re.search(
        r'<script id="topology-data" type="application/json">(.*?)</script>',
        html, re.DOTALL,
    )
    assert match is not None
    payload = json.loads(match.group(1))
    assert payload["counts"]["links"] == len(reloaded.links)
    assert len(payload["devices"]) == len(reloaded.devices)


def test_svg_from_a_run_is_valid_xml(tmp_path: Path) -> None:
    result = _make_discovery(
        nested={"10.0.21.1": ("R2-2", "recip_r2-2_detail.txt")}
    ).run()
    out = _write_run_dir(result, tmp_path / "run1")
    ET.fromstring((out / "topology.svg").read_text(encoding="utf-8"))


def test_empty_run_still_writes_a_viewable_html(tmp_path: Path) -> None:
    """A run where nothing was collected must not crash the visualiser."""
    out = tmp_path / "empty"
    out.mkdir()
    (out / "topology.html").write_text(render_html(Topology(), title="t"), encoding="utf-8")
    (out / "topology.svg").write_text(render_svg(Topology(), title="t"), encoding="utf-8")
    assert (out / "topology.html").exists()
    ET.fromstring((out / "topology.svg").read_text(encoding="utf-8"))


def test_discovery_result_exposes_the_link_audit_trail() -> None:
    """``discovery.yaml`` reports why each non-link candidate was rejected."""
    result = _make_discovery(nested={}).run()
    assert result.link_result is not None
    for candidate in result.link_result.candidates:
        assert str(candidate.rule)
        assert candidate.detail
    # A one-sided row keeps its explanation.
    if result.link_result.candidates:
        assert any(
            "one-sided" in c.detail.lower() or "does not match" in c.detail.lower()
            for c in result.link_result.candidates
        )
