"""Topology rendering (Phase 2.5): standalone SVG and offline HTML.

Both renderers take a normalized :class:`~nettwin.domain.models.Topology` and
nothing else — never CLI output, never raw observations — so a drawing can only
show relationships the collected evidence actually supports.

Phase 2.6 adds a second pair for the *logical* OSPF view. They take an
:class:`~nettwin.domain.ospf_models.OspfTopology` and never merge it with the
physical one: an OSPF adjacency, and above all a transit network, is never
drawn as a cable. See :mod:`nettwin.render.ospf_svg` for the rule.
"""

from nettwin.render.ospf_html import build_ospf_payload, render_ospf_html
from nettwin.render.ospf_svg import render_ospf_svg
from nettwin.render.topology_html import build_payload, render_html
from nettwin.render.topology_svg import render_svg

__all__ = [
    "build_ospf_payload",
    "build_payload",
    "render_html",
    "render_ospf_html",
    "render_ospf_svg",
    "render_svg",
]
