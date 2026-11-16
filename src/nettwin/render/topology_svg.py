"""Standalone SVG rendering of a normalized topology (Phase 2.5).

Consumes the domain models only — never CLI output, never observations. Every
label printed comes from a field that actually exists on the model, so the
drawing cannot claim more than the collected evidence supports.

Layout is deterministic: a breadth-first sweep from the node with the most
links (ties broken by id) so the same topology always produces the same file.
No Newtonian relaxation, no randomness — two runs of the same discovery are
byte-identical.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from html import escape
from xml.sax.saxutils import quoteattr

from nettwin.domain.models import AdminState, LinkState, OperState, Topology

# Geometry ------------------------------------------------------------------
COLUMN_WIDTH = 420
ROW_HEIGHT = 170
MARGIN = 60
NODE_W = 190
NODE_H = 84
FONT = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"

# Colours -------------------------------------------------------------------
BG = "#ffffff"
INK = "#1f2933"
MUTED = "#6b7785"
EDGE = "#4a5568"
NODE_FILL = "#f7f9fc"
NODE_STROKE = "#2b6cb0"
LINK_UP = "#2f855a"
LINK_DOWN = "#c53030"
UNKNOWN = "#a0aec0"

#: Narrowest canvas that still fits the legend row comfortably.
LEGEND_MIN_WIDTH = 700


@dataclass(frozen=True)
class _Node:
    device_id: str
    label: str
    sublabel: str
    management: str
    x: int
    y: int


def _device_sublabel(vendor: str, platform: str) -> str:
    """Vendor + platform, or only what is evidenced."""
    parts = []
    if vendor and vendor != "unknown":
        parts.append(vendor)
    if platform and platform != "unknown":
        parts.append(platform)
    return " / ".join(parts) if parts else "vendor not evidenced"


def _interface_label(topology: Topology, interface_id: str) -> str:
    """``name ip/len`` for an interface, or an explicit placeholder."""
    for iface in topology.interfaces:
        if iface.id == interface_id:
            if iface.ipv4_addresses:
                return f"{iface.name} {iface.ipv4_addresses[0]}"
            return iface.name
    return "interface unresolved"


def _state_word(iface) -> str:  # noqa: ANN001 - Interface, kept local
    """Only report a state the model actually carries."""
    if iface.admin_state is AdminState.DOWN:
        return "admin down"
    if iface.admin_state is AdminState.UP and iface.oper_state is OperState.DOWN:
        return "oper down"
    if iface.is_up:
        return "up"
    return "state unknown"


def _bezier(x0: float, y0: float, p1: tuple[float, float],
            p2: tuple[float, float], x3: float, y3: float,
            t: float) -> tuple[float, float]:
    """Point at ``t`` on a cubic Bezier from (x0,y0) to (x3,y3)."""
    u = 1 - t
    x = (u ** 3) * x0 + 3 * (u ** 2) * t * p1[0] + 3 * u * (t ** 2) * p2[0] + (t ** 3) * x3
    y = (u ** 3) * y0 + 3 * (u ** 2) * t * p1[1] + 3 * u * (t ** 2) * p2[1] + (t ** 3) * y3
    return x, y


def _edge_label(
    x: float,
    y: float,
    text: str,
    side: str,
    box: tuple[float, float, float, float],
    above: bool = True,
) -> list[str]:
    """An interface label anchored just outside its own node's box edge.

    ``side`` is ``"right"`` or ``"left"``: the label is placed beyond that edge
    so it can never sit on top of a node rectangle.
    """
    width = len(text) * 5.6 + 12
    height = 14
    bx, by, bw, bh = box
    if side == "right":
        lx = bx + bw + 8
    else:
        lx = bx - 8 - width
    # Keep the label inside the horizontal band of its node so it reads as
    # belonging to that endpoint, but nudge it clear of the cable: the two
    # labels of one cable alternate above/below so they never collide.
    if above:
        ly = min(max(y - height / 2, by), by + bh) - 15
    else:
        ly = min(max(y + 4, by), by + bh) + 4
    return [
        f'<rect x="{lx:.0f}" y="{ly:.0f}" width="{width:.0f}" height="{height}" '
        f'rx="3" fill="{BG}" stroke="#dfe6ee" stroke-width="0.6" opacity="0.97"/>',
        f'<text x="{lx + 6:.0f}" y="{ly + 10:.0f}" font-size="9" fill="{EDGE}">'
        f'{escape(text)}</text>',
    ]


def _layout(topology: Topology) -> dict[str, _Node]:
    """Deterministic breadth-first placement: depth = column, index = row."""
    adjacency: dict[str, set[str]] = {d.id: set() for d in topology.devices}
    iface_to_device = {i.id: i.device_id for i in topology.interfaces}
    for link in topology.links:
        a = iface_to_device.get(link.source_interface_id)
        b = iface_to_device.get(link.destination_interface_id)
        if a and b and a != b:
            adjacency.setdefault(a, set()).add(b)
            adjacency.setdefault(b, set()).add(a)

    # Root: most links, ties by id — deterministic.
    order = sorted(adjacency, key=lambda d: (-len(adjacency[d]), d))
    nodes: dict[str, _Node] = {}
    placed: set[str] = set()
    column_counts: dict[int, int] = {}

    for root in order:
        if root in placed:
            continue
        if not adjacency.get(root):
            # An isolated device: no cable to place it by. Grid-pack the
            # isolated ones so a run with no confirmed links still produces a
            # readable sheet instead of one very tall column.
            row = column_counts.get(("isolated", 0), 0)
            column_counts[("isolated", 0)] = row + 1
            device = next(d for d in topology.devices if d.id == root)
            nodes[root] = _Node(
                device_id=root,
                label=device.name,
                sublabel=_device_sublabel(device.vendor, device.platform),
                management=(
                    str(device.management_address)
                    if device.management_address is not None
                    else "management address not evidenced"
                ),
                x=MARGIN + (row % 3) * COLUMN_WIDTH,
                y=MARGIN + 60 + (row // 3) * ROW_HEIGHT,
            )
            placed.add(root)
            continue
        queue: deque[tuple[str, int]] = deque([(root, 0)])
        while queue:
            device_id, depth = queue.popleft()
            if device_id in placed:
                continue
            placed.add(device_id)
            row = column_counts.get(depth, 0)
            column_counts[depth] = row + 1
            device = next(d for d in topology.devices if d.id == device_id)
            nodes[device_id] = _Node(
                device_id=device_id,
                label=device.name,
                sublabel=_device_sublabel(device.vendor, device.platform),
                management=(
                    str(device.management_address)
                    if device.management_address is not None
                    else "management address not evidenced"
                ),
                x=MARGIN + depth * COLUMN_WIDTH,
                y=MARGIN + row * ROW_HEIGHT,
            )
            for neighbour in sorted(adjacency.get(device_id, ())):
                if neighbour not in placed:
                    queue.append((neighbour, depth + 1))
    return nodes


def render_svg(topology: Topology, *, title: str = "Network topology") -> str:
    """Render ``topology`` as a standalone, documentation-ready SVG document."""
    nodes = _layout(topology)
    iface_to_device = {i.id: i.device_id for i in topology.interfaces}

    width = MARGIN * 2 + max((n.x for n in nodes.values()), default=0) + NODE_W + 120
    height = MARGIN * 2 + max((n.y for n in nodes.values()), default=0) + NODE_H

    # The legend is a single row of fixed-width items; the canvas must be at
    # least wide enough to hold it or the items collide.
    width = max(width, LEGEND_MIN_WIDTH)
    height += 60

    out: list[str] = []
    out.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family={quoteattr(FONT)} '
        f'role="img" aria-label={quoteattr(title)}>'
    )
    out.append(f"<title>{escape(title)}</title>")
    out.append(
        "<desc>Generated from normalized topology data by NetTwin. "
        "Only relationships confirmed by collected evidence are drawn.</desc>"
    )
    out.append(f'<rect width="100%" height="100%" fill="{BG}"/>')
    out.append(
        f'<text x="{MARGIN}" y="34" font-size="18" fill="{INK}" '
        f'font-weight="600">{escape(title)}</text>'
    )
    out.append(
        f'<text x="{MARGIN}" y="52" font-size="11" fill="{MUTED}">'
        f"{len(topology.devices)} device(s), {len(topology.links)} confirmed link(s), "
        f"{len(topology.interfaces)} interface(s)</text>"
    )

    # ---- edges (drawn first, so nodes sit on top) -------------------------
    for link in topology.links:
        a = iface_to_device.get(link.source_interface_id)
        b = iface_to_device.get(link.destination_interface_id)
        if not a or not b or a not in nodes or b not in nodes:
            continue
        na, nb = nodes[a], nodes[b]
        x1, y1 = na.x + NODE_W / 2, na.y + NODE_H / 2
        x2, y2 = nb.x + NODE_W / 2, nb.y + NODE_H / 2
        colour = LINK_UP if link.state is LinkState.UP else LINK_DOWN
        dash = "" if link.state is LinkState.UP else ' stroke-dasharray="6 4"'

        if abs(na.x - nb.x) < 1:
            # Two stacked nodes: bow the cable sideways so it never runs
            # through a node box, and label it near each end.
            bow = max(110.0, abs(y2 - y1) * 0.55)
            mid_x = max(x1, x2) + bow
            p1 = (mid_x, y1)
            p2 = (mid_x, y2)
            out.append(
                f'<path d="M {x1:.0f} {y1:.0f} C {p1[0]:.0f} {p1[1]:.0f}, '
                f'{p2[0]:.0f} {p2[1]:.0f}, {x2:.0f} {y2:.0f}" fill="none" '
                f'stroke="{colour}" stroke-width="2"{dash}/>'
            )
            point_a = _bezier(x1, y1, p1, p2, x2, y2, 0.22)
            point_b = _bezier(x1, y1, p1, p2, x2, y2, 0.78)
        else:
            out.append(
                f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" '
                f'stroke="{colour}" stroke-width="2"{dash}/>'
            )
            point_a = (x1 + (x2 - x1) * 0.26, y1 + (y2 - y1) * 0.26)
            point_b = (x1 + (x2 - x1) * 0.74, y1 + (y2 - y1) * 0.74)

        # One label per endpoint, floated clear of the cable. Long interface
        # names get the address on a second line rather than a wider box.
        for point, text, node, above in (
            (point_a, _interface_label(topology, link.source_interface_id), na, True),
            (point_b, _interface_label(topology, link.destination_interface_id), nb, False),
        ):
            # Label on the outer side of each node: right for the left-hand
            # node, left for the right-hand one. When both nodes share a
            # column the labels go right, where the cable is bowed.
            side = "right" if node.x <= min(na.x, nb.x) else "left"
            if abs(na.x - nb.x) < 1:
                side = "right"
            out.extend(
                _edge_label(
                    point[0], point[1], text, side,
                    (node.x, node.y, NODE_W, NODE_H), above,
                )
            )

    # ---- nodes ------------------------------------------------------------
    for node in nodes.values():
        out.append(
            f'<rect x="{node.x}" y="{node.y}" width="{NODE_W}" height="{NODE_H}" '
            f'rx="7" fill="{NODE_FILL}" stroke="{NODE_STROKE}" stroke-width="1.6"/>'
        )
        out.append(
            f'<text x="{node.x + 12}" y="{node.y + 22}" font-size="13" '
            f'fill="{INK}" font-weight="600">{escape(node.label)}</text>'
        )
        out.append(
            f'<text x="{node.x + 12}" y="{node.y + 40}" font-size="10" '
            f'fill="{MUTED}">{escape(node.sublabel)}</text>'
        )
        out.append(
            f'<text x="{node.x + 12}" y="{node.y + 56}" font-size="10" '
            f'fill="{EDGE}">{escape(node.management)}</text>'
        )
        # Interface states, only where the model evidences them.
        device_ifaces = [i for i in topology.interfaces if i.device_id == node.device_id]
        if device_ifaces:
            up = sum(1 for i in device_ifaces if i.is_up)
            out.append(
                f'<text x="{node.x + 12}" y="{node.y + 72}" font-size="9.5" '
                f'fill="{MUTED}">{up}/{len(device_ifaces)} interface(s) up</text>'
            )

    if not topology.devices:
        out.append(
            f'<text x="{MARGIN}" y="{MARGIN + 30}" font-size="13" fill="{MUTED}">'
            "No devices were collected — nothing to draw.</text>"
        )

    # ---- legend -----------------------------------------------------------
    legend_y = height - 28
    out.append(
        f'<line x1="{MARGIN}" y1="{legend_y}" x2="{MARGIN + 26}" y2="{legend_y}" '
        f'stroke="{LINK_UP}" stroke-width="2"/>'
    )
    out.append(
        f'<text x="{MARGIN + 34}" y="{legend_y + 4}" font-size="10" fill="{MUTED}">'
        "link up (both endpoints up)</text>"
    )
    out.append(
        f'<line x1="{MARGIN + 210}" y1="{legend_y}" x2="{MARGIN + 236}" '
        f'y2="{legend_y}" stroke="{LINK_DOWN}" stroke-width="2" '
        f'stroke-dasharray="6 4"/>'
    )
    out.append(
        f'<text x="{MARGIN + 244}" y="{legend_y + 4}" font-size="10" fill="{MUTED}">'
        "link down</text>"
    )
    out.append(
        f'<text x="{width - MARGIN}" y="{legend_y + 4}" font-size="10" '
        f'fill="{UNKNOWN}" text-anchor="end">'
        "drawn from confirmed two-sided evidence only</text>"
    )
    out.append("</svg>")
    return "\n".join(out)
