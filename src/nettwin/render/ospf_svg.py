"""Standalone SVG rendering of an OSPF logical topology (Phase 2.6).

Consumes :class:`~nettwin.domain.ospf_models.OspfTopology` only — never CLI
output — so the drawing cannot claim more than the LSDB supports.

**The one rule this module exists to enforce.** An OSPF adjacency, and above
all a *shared transit network*, is not a cable. Multi-access segments are drawn
as their own hexagonal nodes in a dedicated lane, with membership lines running
from each router into the network — never as a router-to-router wire. Stub
prefixes are drawn as detached pills with no line at all, because an advertised
prefix is not a link. A real cable appears in this drawing only when the caller
passes ``physical=``, and then it is labelled CDP and drawn separately.

Layout is deterministic (no randomness, no force simulation): routers on a
single row ordered by router ID, transit networks in a lane beneath ordered by
``(area, prefix, id)``, stub pills flowing left-to-right. The same OSPF state
always produces byte-identical output.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from html import escape
from xml.sax.saxutils import quoteattr

from nettwin.domain.models import Topology
from nettwin.domain.ospf_models import (
    OspfEvidenceState,
    OspfTopology,
    OspfTransitNetwork,
)

# Geometry ------------------------------------------------------------------
MARGIN = 60
HEADER_H = 176

ROUTER_W = 200
ROUTER_H = 96
ROUTER_PITCH = 268

TRANSIT_W = 214
TRANSIT_H = 84
TRANSIT_LANE_GAP = 132
TRANSIT_GAP = 18

STUB_H = 30
STUB_GAP = 14
STUB_ROW_GAP = 12
STUB_LANE_GAP = 118

ARC_LIFT = 62
LEGEND_ITEM_W = 236

FONT = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
FONT_SIZE = 10

# Colours -------------------------------------------------------------------
BG = "#ffffff"
INK = "#1f2933"
MUTED = "#6b7785"

ROUTER_FILL = "#f7f9fc"
ROUTER_STROKE = "#2b6cb0"
ROUTER_ID_INK = "#1a365d"

TRANSIT_FILL = "#fff8ed"
TRANSIT_STROKE = "#c05621"
TRANSIT_INK = "#7b341e"

STUB_FILL = "#f4f6f8"
STUB_STROKE = "#8d99ae"
STUB_INK = "#3d4852"

ADJ = "#2f855a"          # OSPF neighbor adjacency (logical, dashed)
P2P = "#6b46c1"          # point-to-point link with reciprocal Type-1
MEMBER = "#c05621"       # router -> transit network membership
PHYSICAL = "#a0aec0"     # CDP cable underlay

STATE_ALPHA = {
    OspfEvidenceState.CONFIRMED: "1",
    OspfEvidenceState.PARTIAL: "0.85",
    OspfEvidenceState.UNRESOLVED: "0.6",
    OspfEvidenceState.INCONSISTENT: "0.6",
}


@dataclass(frozen=True)
class _Box:
    x: float
    y: float
    w: float
    h: float

    @property
    def cx(self) -> float:
        return self.x + self.w / 2

    @property
    def bottom(self) -> float:
        return self.y + self.h


@dataclass(frozen=True)
class _RouterSlot:
    router_id: str
    label: str
    sublabel: str
    detail: str
    box: _Box


@dataclass(frozen=True)
class _TransitSlot:
    node: OspfTransitNetwork
    title: str
    subtitle: str
    footer: str
    box: _Box


def _text_width(text: str, size: float) -> float:
    """Conservative monospace width estimate — no font metrics available."""
    return len(text) * size * 0.62


def _cubic_point(
    x0: float, y0: float, x1: float, y1: float,
    x2: float, y2: float, x3: float, y3: float, t: float,
) -> tuple[float, float]:
    """Point on a cubic Bézier at parameter ``t``."""
    u = 1 - t
    return (
        u**3 * x0 + 3 * u**2 * t * x1 + 3 * u * t**2 * x2 + t**3 * x3,
        u**3 * y0 + 3 * u**2 * t * y1 + 3 * u * t**2 * y2 + t**3 * y3,
    )


def _arc_peak(endpoint_y: float, lift: float) -> float:
    """Lowest y reached by the symmetric cubic used for logical arcs.

    Both control points sit ``lift`` above their endpoints, so the curve peaks
    at ``t = 0.5`` exactly: ``(y + 3(y-lift) + 3(y-lift) + y) / 8``.
    """
    return (endpoint_y + 6 * (endpoint_y - lift)) / 8


def _dash_for(state: OspfEvidenceState) -> str:
    """Evidence state is legible without colour: solid / dashed / dotted."""
    if state is OspfEvidenceState.CONFIRMED:
        return ""
    if state is OspfEvidenceState.PARTIAL:
        return ' stroke-dasharray="7 4"'
    if state is OspfEvidenceState.INCONSISTENT:
        return ' stroke-dasharray="2 3"'
    return ' stroke-dasharray="3 6"'          # unresolved


def _halo_text(
    x: float,
    y: float,
    text: str,
    *,
    fill: str,
    size: float = 9,
    anchor: str = "middle",
    weight: str = "",
) -> list[str]:
    """Text with a background halo, drawn as two elements.

    The halo is a separate, fattened white copy of the string underneath the
    coloured one rather than ``paint-order`` on a single element: every SVG
    renderer understands two elements in order, while ``paint-order`` is
    ignored by several of them (cairosvg, rsvg), which would leave the white
    stroke painted over the fill and the label unreadable.
    """
    weight_attr = f' font-weight="{weight}"' if weight else ""
    common = (
        f'font-size="{size}" text-anchor="{anchor}"{weight_attr}'
    )
    return [
        f'<text x="{x:.1f}" y="{y:.1f}" {common} fill="{BG}" stroke="{BG}" '
        f'stroke-width="3.2" stroke-linejoin="round">{escape(text)}</text>',
        f'<text x="{x:.1f}" y="{y:.1f}" {common} fill="{fill}">{escape(text)}</text>',
    ]


def _router_label(router_id: str, device_id: str, names: dict[str, str]) -> str:
    name = names.get(device_id) or device_id
    return name if name else router_id


def _area_word(areas: list[str]) -> str:
    if not areas:
        return "area unknown"
    if len(areas) == 1:
        return f"area {areas[0]}"
    return "areas " + ",".join(areas)


# --------------------------------------------------------------------------- #
# Layout
# --------------------------------------------------------------------------- #


def _router_order(ospf: OspfTopology, router_ids: list[str]) -> list[str]:
    """Order routers so transit members sit near each other.

    Breadth-first over the transit-membership graph, seeded from the lowest
    router ID and breaking every tie by router ID. Deterministic, and far
    kinder to the eye than alphabetical order: in the reference lab it puts
    the two ends of each /30 segment beside each other instead of pairing
    routers that happen to share a digit.
    """
    adjacency: dict[str, set[str]] = {rid: set() for rid in router_ids}
    for network in ospf.transit_networks:
        members = [m for m in network.member_router_ids if m in adjacency]
        for a in members:
            adjacency[a].update(m for m in members if m != a)

    ordered: list[str] = []
    seen: set[str] = set()
    for seed in sorted(router_ids):
        if seed in seen:
            continue
        queue = deque([seed])
        seen.add(seed)
        while queue:
            current = queue.popleft()
            ordered.append(current)
            for peer in sorted(adjacency.get(current, ())):
                if peer not in seen:
                    seen.add(peer)
                    queue.append(peer)
    return ordered


def _layout_routers(
    ospf: OspfTopology, names: dict[str, str]
) -> tuple[dict[str, _RouterSlot], int]:
    by_id = {r.router_id: r for r in ospf.routers}
    order = _router_order(ospf, sorted(by_id))

    memberships: dict[str, int] = {}
    for network in ospf.transit_networks:
        for rid in network.member_router_ids:
            memberships[rid] = memberships.get(rid, 0) + 1
    stubs: dict[str, int] = {}
    for stub in ospf.stub_networks:
        stubs[stub.advertising_router] = stubs.get(stub.advertising_router, 0) + 1

    slots: dict[str, _RouterSlot] = {}
    for index, rid in enumerate(order):
        router = by_id[rid]
        box = _Box(x=MARGIN + index * ROUTER_PITCH, y=HEADER_H, w=ROUTER_W, h=ROUTER_H)
        device_name = names.get(router.device_id, "") if router.device_id else ""
        if device_name and device_name != router.router_id:
            label = device_name
            sublabel = f"{router.router_id}  ·  {_pid_word(router)}"
        else:
            # No hostname evidence: the ID is the name, so the second line
            # carries process/area instead of repeating it.
            label = router.router_id
            sublabel = _pid_word(router)
        detail = (
            f"{_area_word(router.areas)}  ·  "
            f"{memberships.get(rid, 0)} transit  ·  {stubs.get(rid, 0)} stub"
        )
        slots[rid] = _RouterSlot(
            router_id=rid, label=label, sublabel=sublabel, detail=detail, box=box
        )

    # Router IDs that appear in neighbour/LSA data but were never collected
    # still get a place: an adjacency pointing into empty space would be a
    # worse lie than an explicitly unknown router.
    unknown = sorted(
        rid
        for rid in {
            *(n.neighbor_router_id for n in ospf.neighbors),
            *(m for t in ospf.transit_networks for m in t.member_router_ids),
        }
        if rid and rid not in by_id
    )
    for offset, rid in enumerate(unknown):
        box = _Box(
            x=MARGIN + (len(order) + offset) * ROUTER_PITCH,
            y=HEADER_H,
            w=ROUTER_W,
            h=ROUTER_H,
        )
        slots[rid] = _RouterSlot(
            router_id=rid,
            label=f"RID {rid}",
            sublabel="not collected",
            detail="seen in the LSDB / neighbour table only",
            box=box,
        )
    return slots, len(order) + len(unknown)


def _pid_word(router) -> str:  # noqa: ANN001 - OspfRouter, kept local
    return "pid " + "/".join(router.process_ids) if router.process_ids else "pid unknown"


def _layout_transits(
    ospf: OspfTopology, routers: dict[str, _RouterSlot]
) -> list[_TransitSlot]:
    """Place each transit network under the midpoint of its members.

    Sits the hexagon directly beneath the routers that attach to it, so a
    membership spoke is a short diagonal instead of a long sweep across other
    nodes. Conflicts are resolved by nudging right and re-checking, which
    keeps the whole layout deterministic.
    """
    networks = sorted(
        ospf.transit_networks, key=lambda n: (n.area, n.prefix or "", n.id)
    )
    placed: list[tuple[float, float]] = []      # (left, right)
    pending: list[tuple[float, OspfTransitNetwork]] = []
    for network in networks:
        centres = [
            routers[rid].box.cx
            for rid in network.member_router_ids
            if rid in routers
        ]
        ideal = (
            (min(centres) + max(centres)) / 2 - TRANSIT_W / 2
            if centres
            else MARGIN
        )
        pending.append((max(ideal, MARGIN), network))

    slots: list[_TransitSlot] = []
    for ideal, network in sorted(pending, key=lambda item: item[0]):
        # Keep the ideal position unless it would collide with something
        # already placed; then slide right just far enough to clear it.
        x = ideal
        moved = True
        while moved:
            moved = False
            for left, right in placed:
                if x < right + TRANSIT_GAP and x + TRANSIT_W > left - TRANSIT_GAP:
                    x = right + TRANSIT_GAP
                    moved = True
        placed.append((x, x + TRANSIT_W))
        attached = len(network.member_router_ids)
        slots.append(
            _TransitSlot(
                node=network,
                title=network.prefix or f"{network.dr_address} (mask unknown)",
                subtitle=f"DR {network.dr_address}  ·  {attached} attached",
                footer=f"area {network.area}  ·  {network.state}",
                box=_Box(x=x, y=0, w=TRANSIT_W, h=TRANSIT_H),   # y set by caller
            )
        )
    # Draw order follows the LSDB, not the packing order, so the same input
    # always yields the same file.
    slots.sort(key=lambda t: (t.node.area, t.node.prefix or "", t.node.id))
    return slots


def _hexagon(box: _Box) -> str:
    """A hexagonal node — deliberately unlike a router box and unlike a switch."""
    inset = box.w * 0.16
    points = [
        (box.x, box.y + box.h / 2),
        (box.x + inset, box.y),
        (box.x + box.w - inset, box.y),
        (box.x + box.w, box.y + box.h / 2),
        (box.x + box.w - inset, box.y + box.h),
        (box.x + inset, box.y + box.h),
    ]
    return " ".join(f"{x:.1f},{y:.1f}" for x, y in points)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def render_ospf_svg(
    ospf: OspfTopology,
    *,
    title: str = "OSPF logical topology",
    physical: Topology | None = None,
) -> str:
    """Render ``ospf`` as a standalone SVG document.

    ``physical`` is optional and only ever used as an *underlay*: confirmed CDP
    links are drawn in grey and labelled CDs, so a reader can see where the
    logical view and the cable view agree. Passing it never turns an OSPF
    relationship into a physical one.
    """
    names: dict[str, str] = {}
    if physical is not None:
        names = {d.id: d.name for d in physical.devices}

    routers, router_count = _layout_routers(ospf, names)
    transits = _layout_transits(ospf, routers)

    # ---- vertical bands ---------------------------------------------------
    router_bottom = HEADER_H + ROUTER_H
    transit_y = router_bottom + TRANSIT_LANE_GAP
    transits = [
        _TransitSlot(
            node=t.node,
            title=t.title,
            subtitle=t.subtitle,
            footer=t.footer,
            box=_Box(x=t.box.x, y=transit_y, w=t.box.w, h=t.box.h),
        )
        for t in transits
    ]
    stub_y = transit_y + (TRANSIT_H if transits else 0) + STUB_LANE_GAP

    routers_width = router_count * ROUTER_PITCH
    transit_right = max((t.box.x + t.box.w for t in transits), default=MARGIN)
    canvas_left = MARGIN
    content_width = max(routers_width, transit_right - MARGIN, 1)
    width = content_width + MARGIN * 2

    # ---- stub pills -------------------------------------------------------
    stubs = sorted(ospf.stub_networks, key=lambda s: (s.area, s.prefix, s.advertising_router))
    stub_pills: list[tuple[float, float, str, float, str]] = []
    cursor_x = canvas_left
    cursor_y = stub_y
    pill_cap = max(width - MARGIN * 2, 320)
    for stub in stubs:
        metric = f"m{stub.metric}" if stub.metric is not None else "m?"
        text = f"{stub.prefix}   {metric}   adv {stub.advertising_router}   a{stub.area}"
        pill_w = min(_text_width(text, FONT_SIZE) + 24, pill_cap)
        if stub_pills and cursor_x + pill_w > canvas_left + pill_cap:
            cursor_x = canvas_left
            cursor_y += STUB_H + STUB_ROW_GAP
        stub_pills.append((cursor_x, cursor_y, text, pill_w, stub.area))
        cursor_x += pill_w + STUB_GAP
    stub_bottom = (cursor_y + STUB_H) if stub_pills else stub_y - STUB_ROW_GAP

    # ---- canvas height ----------------------------------------------------
    legend_rows = _legend_rows(physical is not None)
    legend_h = len(legend_rows) * 20 + 24
    height = max(stub_bottom + 46, transit_y) + legend_h + 34
    width = max(width, 760)

    out: list[str] = []
    out.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" '
        f'height="{height:.0f}" viewBox="0 0 {width:.0f} {height:.0f}" '
        f'font-family={quoteattr(FONT)} role="img" aria-label={quoteattr(title)}>'
    )
    out.append(f"<title>{escape(title)}</title>")
    out.append(
        "<desc>OSPF logical topology reconstructed from Router LSAs (Type 1) and "
        "Network LSAs (Type 2). Transit networks are drawn as their own nodes; "
        "an OSPF adjacency is never drawn as a cable.</desc>"
    )
    out.append(f'<rect width="100%" height="100%" fill="{BG}"/>')

    # ---- header -----------------------------------------------------------
    out.append(
        f'<text x="{MARGIN}" y="38" font-size="18" fill="{INK}" '
        f'font-weight="600">{escape(title)}</text>'
    )
    counts = ospf.state_counts()
    state_word = ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "no relationships"
    out.append(
        f'<text x="{MARGIN}" y="58" font-size="11" fill="{MUTED}">'
        f"{len(ospf.routers)} OSPF router(s), "
        f"{len(ospf.transit_networks)} transit network(s), "
        f"{len(ospf.stub_networks)} stub prefix(es), "
        f"{len(ospf.neighbors)} adjacency record(s) — {escape(state_word)}</text>"
    )
    out.append(
        f'<text x="{MARGIN}" y="76" font-size="10.5" fill="{MUTED}">'
        "transit networks are logical broadcast segments, not switches and not cables"
        "</text>"
    )

    # ---- physical underlay (grey, behind everything) ----------------------
    if physical is not None:
        device_of = {r.router_id: r.device_id for r in ospf.routers if r.device_id}
        out.extend(_physical_layer(physical, routers, device_of))

    # ---- membership spokes: router -> transit network ---------------------
    for slot in transits:
        for member in slot.node.member_router_ids:
            router = routers.get(member)
            if router is None:
                continue
            x1 = router.box.cx
            y1 = router.box.bottom
            x2 = slot.box.cx
            y2 = slot.box.y
            mid_y = (y1 + y2) / 2
            out.append(
                f'<path d="M {x1:.1f} {y1:.1f} C {x1:.1f} {mid_y:.1f}, '
                f'{x2:.1f} {mid_y:.1f}, {x2:.1f} {y2:.1f}" fill="none" '
                f'stroke="{MEMBER}" stroke-width="1.5" opacity="0.9"/>'
            )
            address = slot.node.member_interface_addresses.get(member)
            if address:
                # Sample the curve a third of the way down. Every spoke through
                # one hexagon converges at the bottom and diverges at the top,
                # so labelling near the router is what keeps two members'
                # addresses from being printed on top of each other.
                lx, ly = _cubic_point(
                    x1, y1, x1, mid_y, x2, mid_y, x2, y2, 0.34
                )
                out.extend(_halo_text(lx, ly - 4, address, fill=MUTED))

    # ---- point-to-point logical edges (reciprocal Type-1) -----------------
    for edge in ospf.logical_edges:
        a = routers.get(edge.source_router_id)
        b = routers.get(edge.destination_router_id)
        if a is None or b is None:
            continue
        lift = ARC_LIFT + 18
        out.append(
            f'<path d="M {a.box.cx:.1f} {a.box.y:.1f} C {a.box.cx:.1f} '
            f'{a.box.y - lift:.1f}, {b.box.cx:.1f} {b.box.y - lift:.1f}, '
            f'{b.box.cx:.1f} {b.box.y:.1f}" fill="none" stroke="{P2P}" '
            f'stroke-width="1.6"{_dash_for(edge.state)}/>'
        )
        out.extend(
            _halo_text(
                (a.box.cx + b.box.cx) / 2,
                _arc_peak(a.box.y, lift) - 6,
                f"{edge.prefix or 'p2p'} · {edge.state}",
                fill=P2P,
            )
        )

    # ---- OSPF adjacencies (neighbor table) --------------------------------
    router_id_by_device = {r.device_id: r.router_id for r in ospf.routers if r.device_id}
    for neighbor in ospf.neighbors:
        local = router_id_by_device.get(neighbor.device_id, "")
        a = routers.get(local)
        b = routers.get(neighbor.neighbor_router_id)
        if a is None or b is None or a.router_id == b.router_id:
            continue
        lift = ARC_LIFT - 22
        out.append(
            f'<path d="M {a.box.cx:.1f} {a.box.y:.1f} C {a.box.cx:.1f} '
            f'{a.box.y - lift:.1f}, {b.box.cx:.1f} {b.box.y - lift:.1f}, '
            f'{b.box.cx:.1f} {b.box.y:.1f}" fill="none" stroke="{ADJ}" '
            f'stroke-width="1.6" stroke-dasharray="5 4" opacity="0.95"/>'
        )
        out.extend(
            _halo_text(
                (a.box.cx + b.box.cx) / 2,
                _arc_peak(a.box.y, lift) - 6,
                f"{neighbor.state} · {neighbor.local_interface}",
                fill=ADJ,
            )
        )

    # ---- router nodes -----------------------------------------------------
    for slot in sorted(routers.values(), key=lambda s: (s.box.x, s.router_id)):
        box = slot.box
        out.append(
            f'<rect x="{box.x:.1f}" y="{box.y:.1f}" width="{box.w}" height="{box.h}" '
            f'rx="8" fill="{ROUTER_FILL}" stroke="{ROUTER_STROKE}" stroke-width="1.6"/>'
        )
        out.append(
            f'<text x="{box.x + 12:.1f}" y="{box.y + 24:.1f}" font-size="13" '
            f'fill="{ROUTER_ID_INK}" font-weight="600">{escape(slot.label)}</text>'
        )
        out.append(
            f'<text x="{box.x + 12:.1f}" y="{box.y + 43:.1f}" font-size="10" '
            f'fill="{INK}">{escape(slot.sublabel)}</text>'
        )
        out.append(
            f'<text x="{box.x + 12:.1f}" y="{box.y + 60:.1f}" font-size="9.5" '
            f'fill="{MUTED}">{escape(slot.detail)}</text>'
        )
        out.append(
            f'<text x="{box.x + 12:.1f}" y="{box.y + 77:.1f}" font-size="9" '
            f'fill="{MUTED}" opacity="0.9">OSPF router</text>'
        )

    # ---- transit network nodes -------------------------------------------
    for slot in transits:
        box = slot.box
        opacity = STATE_ALPHA.get(slot.node.state, "0.85")
        out.append(
            f'<polygon points="{_hexagon(box)}" fill="{TRANSIT_FILL}" '
            f'stroke="{TRANSIT_STROKE}" stroke-width="1.8" '
            f'opacity="{opacity}"{_dash_for(slot.node.state)}/>'
        )
        out.append(
            f'<text x="{box.cx:.1f}" y="{box.y + 26:.1f}" font-size="11" '
            f'fill="{TRANSIT_INK}" font-weight="600" text-anchor="middle">'
            f"{escape(slot.title)}</text>"
        )
        out.append(
            f'<text x="{box.cx:.1f}" y="{box.y + 44:.1f}" font-size="9.5" '
            f'fill="{INK}" text-anchor="middle">{escape(slot.subtitle)}</text>'
        )
        out.append(
            f'<text x="{box.cx:.1f}" y="{box.y + 60:.1f}" font-size="9" '
            f'fill="{MUTED}" text-anchor="middle">{escape(slot.footer)}</text>'
        )
        out.append(
            f'<text x="{box.cx:.1f}" y="{box.y + 74:.1f}" font-size="8.5" '
            f'fill="{MUTED}" text-anchor="middle" opacity="0.9">'
            "transit network (Type 2)</text>"
        )

    # ---- stub prefix pills (no lines at all) ------------------------------
    if stub_pills:
        out.append(
            f'<text x="{MARGIN}" y="{stub_y - 16:.1f}" font-size="10" fill="{MUTED}" '
            f'font-weight="600">Stub prefixes — advertised, not links</text>'
        )
    for x, y, text, pill_w, _area in stub_pills:
        out.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{pill_w:.1f}" height="{STUB_H}" '
            f'rx="{STUB_H / 2}" fill="{STUB_FILL}" stroke="{STUB_STROKE}" '
            f'stroke-width="1" stroke-dasharray="4 3"/>'
        )
        out.append(
            f'<text x="{x + pill_w / 2:.1f}" y="{y + 19.5:.1f}" font-size="{FONT_SIZE}" '
            f'fill="{STUB_INK}" text-anchor="middle">{escape(text)}</text>'
        )

    if not ospf.routers and not ospf.transit_networks:
        out.append(
            f'<text x="{MARGIN}" y="{HEADER_H + 40}" font-size="13" fill="{MUTED}">'
            "No OSPF evidence was collected — nothing to draw.</text>"
        )

    # ---- legend -----------------------------------------------------------
    legend_y = height - legend_h - 6
    for index, (kind, text) in enumerate(legend_rows):
        row_y = legend_y + index * 20
        out.append(_legend_geometry(kind, row_y))
        out.append(
            f'<text x="{MARGIN + 44:.1f}" y="{row_y + 4:.1f}" font-size="10" '
            f'fill="{MUTED}">{escape(text)}</text>'
        )
    out.append(
        f'<text x="{width - MARGIN:.1f}" y="{height - 12:.1f}" font-size="10" '
        f'fill="{MUTED}" text-anchor="end">'
        "reconstructed from the LSDB — a transit network is never a cable</text>"
    )
    out.append("</svg>")
    return "\n".join(out)


def _physical_layer(
    physical: Topology, routers: dict[str, _RouterSlot], device_of: dict[str, str]
) -> list[str]:
    """Grey underlay of the *physical* view, drawn behind the logical one.

    Only an explicit, already-confirmed :class:`Topology` is drawn here, and it
    is drawn in a different lane colour and labelled CDP in the legend. Nothing
    from the OSPF side feeds into it — the two evidence sources stay separate
    even when they happen to describe the same cable.
    """
    interface_device = {i.id: i.device_id for i in physical.interfaces}
    router_of_device = {dev: rid for rid, dev in device_of.items() if dev}
    out: list[str] = []
    seen: set[tuple[str, str]] = set()
    for link in physical.links:
        a_dev = interface_device.get(link.source_interface_id, "")
        b_dev = interface_device.get(link.destination_interface_id, "")
        if not a_dev or not b_dev:
            continue
        key = tuple(sorted((a_dev, b_dev)))
        if key in seen:
            continue
        seen.add(key)
        a = routers.get(router_of_device.get(a_dev, ""))
        b = routers.get(router_of_device.get(b_dev, ""))
        if a is None or b is None:
            continue
        out.append(
            f'<line x1="{a.box.cx:.1f}" y1="{a.box.y + a.box.h / 2:.1f}" '
            f'x2="{b.box.cx:.1f}" y2="{b.box.y + b.box.h / 2:.1f}" '
            f'stroke="{PHYSICAL}" stroke-width="1.2" opacity="0.55"/>'
        )
    return out


_LEGEND: list[tuple[str, str]] = [
    ("router", "OSPF router — router ID, process, area"),
    ("transit", "transit network (Type 2) — a segment, not a switch and not a cable"),
    ("member", "router attached to a transit network (Type 1 ⇄ Type 2)"),
    ("adj", "OSPF adjacency from the neighbour table — logical, not a cable"),
    ("p2p", "point-to-point link, reciprocal Type 1 in both directions"),
    ("stub", "stub prefix — advertised, no link is drawn"),
    ("physical", "CDP cable (physical view) — kept separate from OSPF evidence"),
    ("state", "dashes = evidence state: solid confirmed, dash partial, "
              "dot inconsistent, sparse dot unresolved"),
]


def _legend_geometry(kind: str, y: float) -> str:
    """One legend swatch, drawn at its own row."""
    x = MARGIN
    if kind == "router":
        return (
            f'<rect x="{x}" y="{y}" width="24" height="12" rx="3" '
            f'fill="{ROUTER_FILL}" stroke="{ROUTER_STROKE}" stroke-width="1.4"/>'
        )
    if kind == "transit":
        return (
            f'<polygon points="{x},{y} {x + 6},{y} {x + 12},{y + 6} '
            f'{x + 6},{y + 12} {x},{y + 12} {x - 6},{y + 6}" '
            f'fill="{TRANSIT_FILL}" stroke="{TRANSIT_STROKE}" stroke-width="1.4"/>'
        )
    if kind == "member":
        return (
            f'<line x1="{x}" y1="{y}" x2="{x + 28}" y2="{y}" '
            f'stroke="{MEMBER}" stroke-width="1.5"/>'
        )
    if kind == "adj":
        return (
            f'<line x1="{x}" y1="{y}" x2="{x + 28}" y2="{y}" '
            f'stroke="{ADJ}" stroke-width="1.6" stroke-dasharray="5 4"/>'
        )
    if kind == "p2p":
        return (
            f'<line x1="{x}" y1="{y}" x2="{x + 28}" y2="{y}" '
            f'stroke="{P2P}" stroke-width="1.6" stroke-dasharray="7 4"/>'
        )
    if kind == "stub":
        return (
            f'<rect x="{x}" y="{y}" width="28" height="12" rx="6" '
            f'fill="{STUB_FILL}" stroke="{STUB_STROKE}" stroke-width="1" '
            f'stroke-dasharray="4 3"/>'
        )
    if kind == "physical":
        return (
            f'<line x1="{x}" y1="{y}" x2="{x + 28}" y2="{y}" '
            f'stroke="{PHYSICAL}" stroke-width="1.6" opacity="0.8"/>'
        )
    return (
        f'<line x1="{x}" y1="{y}" x2="{x + 28}" y2="{y}" '
        f'stroke="{MUTED}" stroke-width="1.4" stroke-dasharray="3 6"/>'
    )


def _legend_rows(with_physical: bool) -> list[tuple[str, str]]:
    return [
        (kind, caption)
        for kind, caption in _LEGEND
        if kind != "physical" or with_physical
    ]
