"""YAML topology loading and validation.

All input data is validated before it is used: structural validation happens
in the Pydantic domain models, and this layer converts failures into explicit
``TopologyValidationError`` messages that explain what failed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from nettwin.domain.models import Topology
from nettwin.errors import TopologyValidationError

SUPPORTED_SUFFIXES = {".yaml", ".yml"}


def _format_validation_error(exc: ValidationError) -> str:
    """Turn a Pydantic ValidationError into a readable, per-field message."""
    lines: list[str] = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"]) or "<root>"
        lines.append(f"{location}: {error['msg']}")
    return "topology validation failed — " + "; ".join(lines)


def load_topology_dict(data: Any) -> Topology:
    """Validate an already-parsed topology mapping into a ``Topology``.

    Args:
        data: Parsed YAML content; must be a mapping.

    Returns:
        A validated ``Topology``.

    Raises:
        TopologyValidationError: If the data is not a mapping or fails
            validation (duplicate ids, invalid references, bad values).
    """
    if not isinstance(data, dict):
        raise TopologyValidationError(
            f"topology root must be a mapping of collections, "
            f"got {type(data).__name__}"
        )
    try:
        return Topology.model_validate(data)
    except ValidationError as exc:
        raise TopologyValidationError(_format_validation_error(exc)) from exc


def load_topology(path: str | Path) -> Topology:
    """Load and validate a topology from a YAML file.

    Args:
        path: Path to a ``.yaml`` / ``.yml`` file.

    Returns:
        A validated ``Topology``.

    Raises:
        TopologyValidationError: If the file is missing, is not YAML, contains
            invalid YAML, or fails topology validation.
    """
    topology_path = Path(path)
    if not topology_path.exists():
        raise TopologyValidationError(f"topology file not found: {topology_path}")
    if topology_path.suffix.lower() not in SUPPORTED_SUFFIXES:
        raise TopologyValidationError(
            f"unsupported topology file type {topology_path.suffix!r} "
            f"(expected one of: {', '.join(sorted(SUPPORTED_SUFFIXES))}) "
            f"for {topology_path}"
        )
    try:
        raw = yaml.safe_load(topology_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise TopologyValidationError(f"invalid YAML in {topology_path}: {exc}") from exc
    except OSError as exc:
        raise TopologyValidationError(f"could not read {topology_path}: {exc}") from exc
    try:
        return load_topology_dict(raw)
    except TopologyValidationError as exc:
        raise TopologyValidationError(f"{topology_path}: {exc}") from exc
