"""Topology rendering (Phase 2.5): standalone SVG and offline HTML.

Both renderers take a normalized :class:`~nettwin.domain.models.Topology` and
nothing else — never CLI output, never raw observations — so a drawing can only
show relationships the collected evidence actually supports.
"""

from nettwin.render.topology_html import build_payload, render_html
from nettwin.render.topology_svg import render_svg

__all__ = ["build_payload", "render_html", "render_svg"]
