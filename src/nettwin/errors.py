"""Explicit exception types for NetTwin AI.

Engineering rule: use explicit exceptions whose messages explain what failed.
"""

from __future__ import annotations


class NetTwinError(Exception):
    """Base class for all NetTwin AI errors."""


class TopologyValidationError(NetTwinError):
    """Raised when topology data (YAML or dict) fails validation.

    The message lists every problem found so callers can fix input in one pass.
    """


class EndpointNotFoundError(NetTwinError):
    """Raised when a referenced endpoint id does not exist in the topology."""


class ObjectNotFoundError(NetTwinError):
    """Raised when a referenced object id does not exist in the topology."""

    def __init__(self, kind: str, object_id: str) -> None:
        super().__init__(f"{kind} not found: {object_id!r}")
        self.kind = kind
        self.object_id = object_id
