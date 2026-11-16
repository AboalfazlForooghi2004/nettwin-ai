"""Interactive, dependency-free HTML viewer for an OSPF logical topology (2.6).

Same delivery contract as the Phase 2.5 viewer: one ``.html`` file with the CSS,
the JavaScript and the data all inline — no CDN, no ``fetch()``, no build step.
Opening it from disk is enough. The SVG beside it is a static drawing; this page
is the inspector.

What it must never do, and how that is enforced:

* **imply that a transit network is a switch or a cable** — a transit network is
  rendered as a hexagonal node in its own lane, and the panel for it is titled
  "Transit network", never "device";
* **merge evidence sources** — a router panel lists CDP view, OSPF adjacency and
  LSDB view as three separate sections, and the CDP correlation is reported as
  its own row, never folded into the OSPF claim;
* **hide a conflict** — ``inconsistent`` and ``unresolved`` objects are shown
  with their warnings and their source LSA references, in their own colour,
  and they are counted in the banner.
"""

from __future__ import annotations

import json
from html import escape
from typing import Any

from nettwin.domain.models import Topology
from nettwin.domain.ospf_models import (
    OspfCorrelation,
    OspfTopology,
    OspfTransitNetwork,
)


def _lsa_payload(ref) -> dict[str, Any]:  # noqa: ANN001 - OspfLsaRef
    return {
        "device_id": ref.device_id,
        "area": ref.area,
        "lsa_type": ref.lsa_type,
        "link_state_id": ref.link_state_id,
        "advertising_router": ref.advertising_router,
        "sequence": ref.sequence,
        "checksum": ref.checksum,
        "age": ref.age,
        "command": ref.command,
    }


def _transit_payload(network: OspfTransitNetwork) -> dict[str, Any]:
    return {
        "id": network.id,
        "area": network.area,
        "prefix": network.prefix,
        "dr_address": network.dr_address,
        "advertising_router": network.advertising_router,
        "member_router_ids": list(network.member_router_ids),
        "member_interface_addresses": dict(network.member_interface_addresses),
        "state": str(network.state),
        "evidence": list(network.evidence),
        "notes": list(network.notes),
        "source_lsas": [_lsa_payload(r) for r in network.source_lsas],
    }


def _embed_json(payload: object) -> str:
    """Serialize for embedding inside a ``<script type="application/json">``.

    ``json.dumps`` alone is not safe here. Escaping ``</`` only stops the parser
    from seeing a literal end tag; a payload such as ``<script>alert(1)</script>``
    still arrives intact and any consumer doing ``innerHTML`` or naive DOM
    building executes it. (An IOS *hostname* is attacker-controlled input in the
    general case, so this is not hypothetical.)

    The HTML spec lets a JSON text be escaped with ``\u003c``/``\u003e``/
    ``\u0026``: these are valid JSON string escapes, ``json.loads`` and
    ``JSON.parse`` both restore the original characters, and no ``<`` survives
    to be mistaken for markup.
    """
    text = json.dumps(payload, indent=2, sort_keys=False)
    return (
        text.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def build_ospf_payload(
    ospf: OspfTopology,
    *,
    title: str,
    run_id: str = "",
    physical: Topology | None = None,
) -> dict[str, Any]:
    """Serialize the OSPF topology for the page.

    A pure function of the models, so the inspector cannot display anything the
    models do not carry.
    """
    correlations: list[OspfCorrelation] = list(ospf.correlations)
    routers = [
        {
            "router_id": r.router_id,
            "device_id": r.device_id,
            "process_ids": list(r.process_ids),
            "areas": list(r.areas),
            "collected": r.collected,
            "transit_memberships": [
                t.id for t in ospf.transit_networks if r.router_id in t.member_router_ids
            ],
            "stub_prefixes": [
                s.prefix for s in ospf.stub_networks if s.advertising_router == r.router_id
            ],
            "neighbors": [
                {
                    "neighbor_router_id": n.neighbor_router_id,
                    "neighbor_address": n.neighbor_address,
                    "state": n.state,
                    "local_interface": n.local_interface,
                    "area": n.area,
                    "process_id": n.process_id,
                    "device_id": n.device_id,
                    "evidence": n.evidence,
                }
                for n in ospf.neighbors
                if n.device_id == r.device_id and r.device_id
            ],
            "interfaces": [
                {
                    "name": i.name,
                    "process_id": i.process_id,
                    "area": i.area,
                    "ip_address": i.ip_address,
                    "mask": i.mask,
                    "prefix": i.prefix,
                    "cost": i.cost,
                    "state": i.state,
                    "neighbors_full": i.neighbors_full,
                    "neighbors_total": i.neighbors_total,
                }
                for i in ospf.interfaces
                if i.device_id == r.device_id and r.device_id
            ],
            "routes": [
                {
                    "prefix": rt.prefix,
                    "route_type": str(rt.route_type),
                    "cost": rt.cost,
                    "next_hop": rt.next_hop,
                    "outgoing_interface": rt.outgoing_interface,
                    "area": rt.area,
                    "learned": rt.learned,
                }
                for rt in ospf.routes
                if rt.device_id == r.device_id and r.device_id
            ],
        }
        for r in ospf.routers
    ]
    instances = [
        {
            "device_id": i.device_id,
            "process_id": i.process_id,
            "router_id": i.router_id,
            "vrf": i.vrf,
            "protocol_version": i.protocol_version,
            "areas": [
                {"area": a.area, "interfaces": list(a.interfaces)} for a in i.areas
            ],
        }
        for i in ospf.instances
    ]
    payload: dict[str, Any] = {
        "title": title,
        "run_id": run_id,
        "capability": "ospf-logical",
        "routers": routers,
        "instances": instances,
        "transit_networks": [_transit_payload(t) for t in ospf.transit_networks],
        "stub_networks": [
            {
                "prefix": s.prefix,
                "area": s.area,
                "advertising_router": s.advertising_router,
                "metric": s.metric,
                "device_id": s.device_id,
                "source_lsa": _lsa_payload(s.source_lsa) if s.source_lsa else None,
            }
            for s in ospf.stub_networks
        ],
        "logical_edges": [
            {
                "source_router_id": e.source_router_id,
                "destination_router_id": e.destination_router_id,
                "prefix": e.prefix,
                "area": e.area,
                "source_interface": e.source_interface,
                "destination_interface": e.destination_interface,
                "state": str(e.state),
                "notes": list(e.notes),
                "source_lsas": [_lsa_payload(r) for r in e.source_lsas],
            }
            for e in ospf.logical_edges
        ],
        "neighbors": [
            {
                "device_id": n.device_id,
                "local_interface": n.local_interface,
                "neighbor_router_id": n.neighbor_router_id,
                "neighbor_address": n.neighbor_address,
                "state": n.state,
                "adjacency_state": n.adjacency_state,
                "role": n.role,
                "area": n.area,
                "process_id": n.process_id,
            }
            for n in ospf.neighbors
        ],
        "routes": [
            {
                "device_id": rt.device_id,
                "prefix": rt.prefix,
                "route_type": str(rt.route_type),
                "cost": rt.cost,
                "next_hop": rt.next_hop,
                "outgoing_interface": rt.outgoing_interface,
                "area": rt.area,
                "learned": rt.learned,
            }
            for rt in ospf.routes
        ],
        "correlations": [
            {
                "relation_id": c.relation_id,
                "cdp_state": str(c.cdp_state),
                "detail": c.detail,
            }
            for c in correlations
        ],
        "router_lsas": [
            {
                "area": lsa.area,
                "link_state_id": lsa.link_state_id,
                "advertising_router": lsa.advertising_router,
                "sequence": lsa.sequence,
                "checksum": lsa.checksum,
                "age": lsa.age,
                "number_of_links": lsa.number_of_links,
                "device_id": lsa.device_id,
                # Provenance: every router whose LSDB held this LSA. One LSA,
                # several observers — never one LSA per observer.
                "observed_by": lsa.observed_by,
                "links": [
                    {
                        "link_type": str(link.link_type),
                        "link_id": link.link_id,
                        "link_data": link.link_data,
                        "network_mask": link.network_mask,
                        "metric": link.metric,
                        "prefix": link.prefix,
                    }
                    for link in lsa.links
                ],
            }
            for lsa in ospf.router_lsas
        ],
        "network_lsas": [
            {
                "area": lsa.area,
                "link_state_id": lsa.link_state_id,
                "advertising_router": lsa.advertising_router,
                "network_mask": lsa.network_mask,
                "prefix": lsa.prefix,
                "attached_routers": list(lsa.attached_routers),
                "sequence": lsa.sequence,
                "checksum": lsa.checksum,
                "age": lsa.age,
                "device_id": lsa.device_id,
                "observed_by": lsa.observed_by,
            }
            for lsa in ospf.network_lsas
        ],
        "warnings": list(ospf.warnings),
        "state_counts": ospf.state_counts(),
        "counts": {
            "routers": len(ospf.routers),
            "transit_networks": len(ospf.transit_networks),
            "stub_networks": len(ospf.stub_networks),
            "logical_edges": len(ospf.logical_edges),
            "neighbors": len(ospf.neighbors),
            "routes": len(ospf.routes),
            "learned_routes": len(ospf.learned_routes()),
            "connected_routes": len(ospf.connected_routes()),
            "router_lsas": len(ospf.router_lsas),
            "network_lsas": len(ospf.network_lsas),
            # Separate the LSDB identities from the observations of them, so a
            # reader is never told "25 transit networks" when there are 5.
            "router_lsa_observations": sum(
                len(lsa.observed_by) for lsa in ospf.router_lsas
            ),
            "network_lsa_observations": sum(
                len(lsa.observed_by) for lsa in ospf.network_lsas
            ),
            "observers": len(
                {
                    observer
                    for lsa in [*ospf.router_lsas, *ospf.network_lsas]
                    for observer in lsa.observed_by
                }
            ),
        },
        "has_physical": physical is not None,
    }
    return payload


_CSS = """
:root{
  --bg:#0f1419; --panel:#161d26; --panel2:#1d2733; --ink:#e6edf3; --muted:#8b98a5;
  --line:#2b3846; --accent:#4aa3ff; --up:#3fb950; --warn:#d29922; --bad:#f85149;
  --transit:#e08c3c; --p2p:#a78bfa;
}
*{box-sizing:border-box}
html,body{margin:0;height:100%;background:var(--bg);color:var(--ink);
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
#app{display:flex;height:100vh}
#stage{flex:1;position:relative;overflow:hidden;display:flex;flex-direction:column}
#hud{position:absolute;top:10px;left:10px;right:340px;z-index:5;display:flex;
  gap:6px;flex-wrap:wrap;align-items:center}
#hud .title{font-size:13px;font-weight:600;margin-right:8px}
#hud .stat{font-size:10.5px;color:var(--muted);border:1px solid var(--line);
  border-radius:99px;padding:2px 8px}
button{background:var(--panel2);color:var(--ink);border:1px solid var(--line);
  border-radius:6px;padding:5px 10px;font:inherit;font-size:11px;cursor:pointer}
button:hover{border-color:var(--accent)}
button.on{border-color:var(--accent);color:var(--accent)}
#lanes{flex:1;overflow:auto;padding:64px 16px 16px}
.lane{margin-bottom:26px}
.lane>h3{font-size:10.5px;text-transform:uppercase;letter-spacing:.09em;
  color:var(--muted);margin:0 0 8px;font-weight:600}
.row{display:flex;gap:10px;flex-wrap:wrap}
.card{border:1px solid var(--line);border-radius:8px;background:var(--panel);
  padding:9px 11px;cursor:pointer;transition:border-color .12s,transform .12s;
  min-width:190px}
.card:hover{border-color:var(--accent);transform:translateY(-1px)}
.card.sel{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent) inset}
.card .nm{font-size:12.5px;font-weight:600}
.card .sub{font-size:10.5px;color:var(--muted);margin-top:3px;line-height:1.5}
.card .foot{font-size:10px;margin-top:5px}
.hex{border-color:var(--transit)}
.hex .nm{color:var(--transit)}
.pill{font-size:9.5px;padding:1px 6px;border-radius:99px;border:1px solid var(--line);
  display:inline-block;margin-right:4px}
.pill.confirmed{color:var(--up);border-color:var(--up)}
.pill.partial{color:var(--warn);border-color:var(--warn)}
.pill.inconsistent{color:var(--bad);border-color:var(--bad)}
.pill.unresolved{color:var(--muted);border-style:dashed}
.pill.cdp_confirmed{color:var(--up);border-color:var(--up)}
.pill.cdp_missing,.pill.cdp_disagrees{color:var(--warn);border-color:var(--warn)}
.pill.cdp_nodata{color:var(--muted)}
.stub{font-size:10.5px;color:var(--muted);border:1px dashed var(--line);
  border-radius:99px;padding:4px 11px;background:#141b23}
.stub b{color:var(--ink);font-weight:600}
#side{width:330px;border-left:1px solid var(--line);background:var(--panel);
  overflow-y:auto;padding:14px;font-size:12px}
#side h2{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);
  margin:0 0 10px;font-weight:600}
#side h4{font-size:10px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);
  margin:16px 0 6px;font-weight:600}
#side .empty{color:var(--muted);line-height:1.7}
.kv{display:grid;grid-template-columns:88px 1fr;gap:4px 8px;margin-bottom:10px}
.kv dt{color:var(--muted)}
.kv dd{margin:0;word-break:break-word}
.item{border:1px solid var(--line);border-radius:6px;padding:6px 8px;margin-bottom:5px;
  background:var(--panel2)}
.item .nm{font-weight:600;display:flex;justify-content:space-between;gap:8px}
.item .meta{color:var(--muted);font-size:10.5px;margin-top:3px;line-height:1.5}
.addr{color:var(--accent);font-size:11px}
.note{color:var(--warn);font-size:10.5px;margin-top:4px;line-height:1.5}
/* `.item .meta` above is scoped to items; a bare .meta outside a card still
   needs a size or it inherits the page's default body text. */
.meta{color:var(--muted);font-size:10.5px;line-height:1.6;margin-top:6px}
.lsa{font-size:10px;color:var(--muted);border-left:2px solid var(--line);
  padding-left:7px;margin-top:5px;line-height:1.6}
.warnbox{border:1px solid var(--warn);border-radius:6px;padding:7px 9px;
  color:var(--warn);font-size:10.5px;line-height:1.6;margin-bottom:8px}
table{width:100%;border-collapse:collapse;font-size:10.5px}
th,td{text-align:left;padding:3px 5px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:600;font-size:9.5px;text-transform:uppercase}
td.num{text-align:right}
tr.learned td{color:var(--ink)}
tr.connected td{color:var(--muted)}
.banner{position:absolute;top:10px;right:356px;font-size:10px;color:var(--muted);z-index:5}
"""

_JS = r"""
(function(){
"use strict";
var DATA = JSON.parse(document.getElementById("ospf-data").textContent);
var side = document.getElementById("side");
var lanes = document.getElementById("lanes");

function el(tag, cls, text){
  var n = document.createElement(tag);
  if(cls){ n.className = cls; }
  if(text !== undefined && text !== null){ n.textContent = String(text); }
  return n;
}
function kv(pairs){
  var dl = el("dl","kv");
  pairs.forEach(function(p){
    if(p[1] === null || p[1] === undefined || p[1] === ""){ return; }
    dl.appendChild(el("dt",null,p[0]));
    dl.appendChild(el("dd",null,p[1]));
  });
  return dl;
}
function statePill(state){ return el("span","pill "+state, state); }
function addrPill(text){ return el("span","pill", text); }

function clear(node){ while(node.firstChild){ node.removeChild(node.firstChild); } }

/* ---------------------------------------------------------------- lanes */
function card(opts, onclick){
  var c = el("div", "card" + (opts.extraClass ? " " + opts.extraClass : ""));
  c.appendChild(el("div","nm",opts.name));
  if(opts.sub){ c.appendChild(el("div","sub",opts.sub)); }
  var foot = el("div","foot");
  (opts.pills||[]).forEach(function(p){ foot.appendChild(p); });
  if(foot.firstChild){ c.appendChild(foot); }
  c.addEventListener("click", function(){
    var cards = document.querySelectorAll(".card");
    for(var i=0;i<cards.length;i++){ cards[i].classList.remove("sel"); }
    c.classList.add("sel");
    onclick();
  });
  return c;
}

function renderRouterPanel(r){
  clear(side);
  side.appendChild(el("h2","","OSPF router"));
  side.appendChild(kv([
    ["router ID", r.router_id],
    ["device", r.device_id || "not collected"],
    ["process", r.process_ids.length ? r.process_ids.join(", ") : "unknown"],
    ["area(s)", r.areas.length ? r.areas.join(", ") : "unknown"],
    ["collected", r.collected ? "yes — this walk" : "no — LSDB reference only"]
  ]));

  side.appendChild(el("h4",null,"Transit networks"));
  if(!r.transit_memberships.length){
    side.appendChild(el("div","empty","None of this router's Type 1 links is a transit link."));
  } else {
    r.transit_memberships.forEach(function(id){
      var t = DATA.transit_networks.filter(function(x){ return x.id === id; })[0];
      var it = el("div","item");
      it.appendChild(el("div","nm", t.prefix || t.dr_address));
      var meta = el("div","meta");
      meta.appendChild(statePill(t.state));
      meta.appendChild(document.createTextNode("DR "+t.dr_address));
      it.appendChild(meta);
      var mine = t.member_interface_addresses[r.router_id];
      if(mine){ it.appendChild(el("div","addr", "local address " + mine)); }
      side.appendChild(it);
    });
  }

  side.appendChild(el("h4",null,"Advertised stub prefixes"));
  if(!r.stub_prefixes.length){
    side.appendChild(el("div","empty","No stub links advertised."));
  } else {
    r.stub_prefixes.forEach(function(p){
      side.appendChild(el("div","item")).appendChild(el("div","nm",p));
    });
  }

  side.appendChild(el("h4",null,"OSPF adjacencies (neighbour table)"));
  if(!r.neighbors.length){
    side.appendChild(el("div","empty","No neighbours recorded for this device."));
  } else {
    r.neighbors.forEach(function(n){
      var it = el("div","item");
      var nm = el("div","nm");
      nm.appendChild(el("span",null,"RID "+n.neighbor_router_id));
      nm.appendChild(el("span",null,n.state));
      it.appendChild(nm);
      it.appendChild(el("div","meta",
        n.local_interface + " · " + n.neighbor_address +
        (n.role ? " · role " + n.role : "")));
      it.appendChild(el("div","meta","evidence: "+n.evidence));
      side.appendChild(it);
    });
  }

  side.appendChild(el("h4",null,"OSPF interfaces"));
  if(!r.interfaces.length){
    side.appendChild(el("div","empty","No `show ip ospf interface brief` rows."));
  } else {
    r.interfaces.forEach(function(i){
      var it = el("div","item");
      var nm = el("div","nm");
      nm.appendChild(el("span",null,i.name));
      nm.appendChild(el("span",null,i.state));
      it.appendChild(nm);
      it.appendChild(el("div","meta",
        "pid "+i.process_id+" · area "+i.area+" · cost "+i.cost));
      if(i.prefix){ it.appendChild(el("div","addr", i.prefix)); }
      if(i.neighbors_total !== null && i.neighbors_total !== undefined){
        it.appendChild(el("div","meta",
          i.neighbors_full+" of "+i.neighbors_total+" neighbours FULL/UP"));
      }
      side.appendChild(it);
    });
  }

  side.appendChild(el("h4",null,"Routes (routing evidence, not topology)"));
  if(!r.routes.length){
    side.appendChild(el("div","empty","No `show ip ospf route` rows."));
  } else {
    var t = el("table");
    var head = el("tr");
    ["prefix","type","cost","next hop"].forEach(function(h){ head.appendChild(el("th",null,h)); });
    t.appendChild(head);
    r.routes.forEach(function(rt){
      var tr = el("tr", rt.learned ? "learned" : "connected");
      tr.appendChild(el("td",null,rt.prefix));
      tr.appendChild(el("td",null,rt.route_type));
      tr.appendChild(el("td","num",rt.cost === null ? "?" : rt.cost));
      tr.appendChild(el("td",null,rt.next_hop || (rt.learned ? "?" : "connected")));
      t.appendChild(tr);
    });
    side.appendChild(t);
    side.appendChild(el("div","meta",
      "Connected rows are interface networks, not OSPF learning evidence."));
  }
}

function renderTransitPanel(t){
  clear(side);
  side.appendChild(el("h2","","Transit network — not a switch, not a cable"));
  side.appendChild(kv([
    ["prefix", t.prefix || "unknown (no Network Mask)"],
    ["area", t.area],
    ["DR address", t.dr_address],
    ["advertised by", t.advertising_router],
    ["attached", t.member_router_ids.length + " router(s)"],
    ["state", null]
  ]));
  var p = el("div","foot");
  p.appendChild(statePill(t.state));
  (t.evidence||[]).forEach(function(e){ p.appendChild(el("span","pill",e)); });
  side.insertBefore(p, side.firstChild.nextSibling);

  side.appendChild(el("h4",null,"Attached routers"));
  t.member_router_ids.forEach(function(rid){
    var it = el("div","item");
    it.appendChild(el("div","nm", rid));
    var a = t.member_interface_addresses[rid];
    it.appendChild(el("div", a ? "addr" : "meta", a || "interface address not resolved"));
    side.appendChild(it);
  });

  side.appendChild(el("h4",null,"Source LSAs"));
  if(!t.source_lsas.length){
    side.appendChild(el("div","empty","No LSA reference recorded — this should not happen."));
  } else {
    t.source_lsas.forEach(function(l){
      side.appendChild(el("div","lsa",
        "Type "+l.lsa_type+" · area "+l.area+" · LSID "+l.link_state_id+
        " · adv "+l.advertising_router+
        (l.sequence ? " · seq "+l.sequence : "")+
        (l.checksum ? " · cksum "+l.checksum : "")+
        (l.age !== null && l.age !== undefined ? " · age "+l.age : "")));
    });
  }
  if(t.notes && t.notes.length){
    t.notes.forEach(function(n){ side.appendChild(el("div","note",n)); });
  }
}

function renderStubPanel(s){
  clear(side);
  side.appendChild(el("h2","","Stub prefix — advertised, not a link"));
  side.appendChild(kv([
    ["prefix", s.prefix],
    ["area", s.area],
    ["advertised by", s.advertising_router],
    ["metric", s.metric === null || s.metric === undefined ? "unknown" : s.metric],
    ["collected from", s.device_id || "unknown"]
  ]));
  side.appendChild(el("div","empty",
    "A stub link is a prefix an OSPF router advertises for one of its own "+
    "networks. It creates no router and no connection, so no line is drawn "+
    "for it anywhere in this view."));
  if(s.source_lsa){
    side.appendChild(el("h4",null,"Source LSA"));
    var l = s.source_lsa;
    side.appendChild(el("div","lsa",
      "Type "+l.lsa_type+" · area "+l.area+" · LSID "+l.link_state_id+
      " · adv "+l.advertising_router));
  }
}

function renderCorrelations(corr){
  if(!corr.length){ return; }
  side.appendChild(el("h4",null,"CDP correlation (kept separate)"));
  corr.forEach(function(c){
    var it = el("div","item");
    var nm = el("div","nm");
    nm.appendChild(el("span",null,c.relation_id));
    nm.appendChild(el("span","pill "+c.cdp_state, c.cdp_state.replace("_"," ")));
    it.appendChild(nm);
    if(c.detail){ it.appendChild(el("div","meta",c.detail)); }
    side.appendChild(it);
  });
}

function renderEmptyPanel(){
  clear(side);
  side.appendChild(el("h2","","OSPF evidence"));
  if(DATA.warnings.length){
    DATA.warnings.forEach(function(w){ side.appendChild(el("div","warnbox",w)); });
  }
  side.appendChild(el("div","empty",
    "Click a router, a transit network or a stub prefix.\n\n"+
    "This page shows the logical OSPF view rebuilt from Router LSAs (Type 1) "+
    "and Network LSAs (Type 2). A transit network is a broadcast segment "+
    "shared by its attached routers — it is drawn as a node of its own, and "+
    "it is never a switch and never a cable. CDP evidence stays in the "+
    "physical topology and is only ever reported here as a separate correlation."));
  var learned = DATA.routes.filter(function(r){ return r.learned; }).length;
  side.appendChild(el("h4",null,"Totals"));
  side.appendChild(kv([
    ["routers", DATA.counts.routers],
    ["transit networks", DATA.counts.transit_networks],
    ["stub prefixes", DATA.counts.stub_networks],
    ["adjacencies", DATA.counts.neighbors],
    ["routes", DATA.counts.routes + " (" + learned + " learned)"],
    ["Type 1 / Type 2", DATA.counts.router_lsas + " / " + DATA.counts.network_lsas],
    ["observers", DATA.counts.observers + (
      DATA.counts.observers > 1
        ? " (each LSA seen by up to " + DATA.counts.observers + ", counted once)"
        : ""
    )]
  ]));
}

/* ------------------------------------------------------------- assembly */
function build(){
  clear(lanes);

  var routerLane = el("div","lane");
  routerLane.appendChild(el("h3",null,"OSPF routers — from Router LSAs and the neighbour table"));
  var row = el("div","row");
  DATA.routers.forEach(function(r){
    var pills = [];
    if(r.process_ids.length){ pills.push(addrPill("pid "+r.process_ids.join("/"))); }
    r.areas.forEach(function(a){ pills.push(addrPill("area "+a)); });
    if(!r.collected){ pills.push(el("span","pill unresolved","not collected")); }
    row.appendChild(card({
      name: r.router_id,
      sub: (r.collected ? r.device_id : "seen in the LSDB only") +
           " · " + r.transit_memberships.length + " transit · " +
           r.stub_prefixes.length + " stub",
      pills: pills
    }, function(){ renderRouterPanel(r); }));
  });
  if(!DATA.routers.length){
    row.appendChild(el("div","empty","No OSPF routers were reconstructed."));
  }
  routerLane.appendChild(row);
  lanes.appendChild(routerLane);

  var transitLane = el("div","lane");
  transitLane.appendChild(el("h3",null,
    "Transit networks — shared segments, drawn as nodes, never as cables"));
  var trow = el("div","row");
  DATA.transit_networks.forEach(function(t){
    trow.appendChild(card({
      extraClass: "hex",
      name: t.prefix || t.dr_address,
      sub: "DR "+t.dr_address+" · "+t.member_router_ids.length+" attached"+
           " · adv "+t.advertising_router,
      pills: [statePill(t.state)]
    }, function(){ renderTransitPanel(t); }));
  });
  if(!DATA.transit_networks.length){
    trow.appendChild(el("div","empty","No transit networks reconstructed."));
  }
  transitLane.appendChild(trow);
  lanes.appendChild(transitLane);

  var edgeLane = el("div","lane");
  edgeLane.appendChild(el("h3",null,"Point-to-point logical links — reciprocal Type 1 both ways"));
  var erow = el("div","row");
  DATA.logical_edges.forEach(function(e){
    erow.appendChild(card({
      name: e.source_router_id + " ⇄ " + e.destination_router_id,
      sub: (e.prefix || "prefix unknown") + " · area " + e.area,
      pills: [statePill(e.state)]
    }, function(){
      clear(side);
      side.appendChild(el("h2","","Point-to-point logical link"));
      side.appendChild(kv([
        ["endpoint A", e.source_router_id],
        ["interface A", e.source_interface],
        ["endpoint B", e.destination_router_id],
        ["interface B", e.destination_interface],
        ["prefix", e.prefix],
        ["area", e.area]
      ]));
      side.appendChild(el("div","empty",
        "Both routers advertise this as a point-to-point link to each other, "+
        "so the relationship survives reciprocal validation. It is still a "+
        "logical claim, not physical evidence: an OSPF adjacency never becomes "+
        "a cable here, and only the CDP view can ever place one."));
      if(e.notes.length){ e.notes.forEach(function(n){ side.appendChild(el("div","note",n)); }); }
      if(e.source_lsas.length){
        if(r.observed_by && r.observed_by.length > 1){
        side.appendChild(el("div","note",
          "Held by " + r.observed_by.length + " observers: " + r.observed_by.join(", ") +
          " — one LSA, shown once."));
      }
      side.appendChild(el("h4",null,"Source LSAs"));
        e.source_lsas.forEach(function(l){
          side.appendChild(el("div","lsa",
            "Type "+l.lsa_type+" · area "+l.area+" · LSID "+l.link_state_id+
            " · adv "+l.advertising_router));
        });
      }
    }));
  });
  if(!DATA.logical_edges.length){
    erow.appendChild(el("div","empty",
      "No point-to-point links — every adjacency in this LSDB is via a transit network."));
  }
  edgeLane.appendChild(erow);
  lanes.appendChild(edgeLane);

  var stubLane = el("div","lane");
  stubLane.appendChild(el("h3",null,"Stub prefixes — advertised networks, not links"));
  var srow = el("div","row");
  DATA.stub_networks.forEach(function(s){
    var box = el("div","stub");
    box.appendChild(el("b",null,s.prefix));
    box.appendChild(document.createTextNode(
      "  m" + (s.metric === null ? "?" : s.metric) +
      " · adv " + s.advertising_router + " · a" + s.area));
    box.style.cursor = "pointer";
    box.addEventListener("click", function(){ renderStubPanel(s); });
    srow.appendChild(box);
  });
  if(!DATA.stub_networks.length){
    srow.appendChild(el("div","empty","No stub prefixes advertised."));
  }
  stubLane.appendChild(srow);
  lanes.appendChild(stubLane);

  var evLane = el("div","lane");
  evLane.appendChild(el("h3",null,"Honesty ledger — evidence state per reconstructed relationship"));
  var evRow = el("div","row");
  var kinds = ["confirmed","partial","inconsistent","unresolved"];
  kinds.forEach(function(k){
    var n = DATA.state_counts[k] || 0;
    var c = el("div","card");
    c.appendChild(el("div","nm",k));
    c.appendChild(el("div","sub",
      k === "confirmed" ? "Type 1 and Type 2 agree" :
      k === "partial" ? "only one evidence source" :
      k === "inconsistent" ? "evidence conflicts — reported, not resolved" :
      "association could not be determined"));
    c.appendChild(el("div","foot")).appendChild(el("span","pill "+k, n+" object(s)"));
    evRow.appendChild(c);
  });
  evLane.appendChild(evRow);
  if(DATA.warnings.length){
    var w = el("div","warnbox");
    DATA.warnings.forEach(function(x){ w.appendChild(el("div",null,x)); });
    evLane.appendChild(w);
  }
  evLane.appendChild(el("div","meta",
    "Routing-table evidence is listed per router and never used to create a "+
    "topology link: a route says where traffic goes, not what is plugged into what."));
  lanes.appendChild(evLane);
}

document.getElementById("all").addEventListener("click", function(){
  renderEmptyPanel();
  var cards = document.querySelectorAll(".card");
  for(var i=0;i<cards.length;i++){ cards[i].classList.remove("sel"); }
});
document.getElementById("raw").addEventListener("click", function(){
  var w = window.open("", "_blank");
  w.document.write("<pre>" + JSON.stringify(DATA, null, 2)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;") + "</pre>");
  w.document.close();
});

build();
renderEmptyPanel();
})();
"""


def render_ospf_html(
    ospf: OspfTopology,
    *,
    title: str = "OSPF logical topology",
    run_id: str = "",
    physical: Topology | None = None,
) -> str:
    """Render a single self-contained interactive HTML document."""
    payload = build_ospf_payload(ospf, title=title, run_id=run_id, physical=physical)
    data_json = _embed_json(payload)
    safe_title = escape(title)
    counts = payload["counts"]
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{safe_title}</title>
<style>{_CSS}</style>
</head>
<body>
<div id="app">
  <div id="stage">
    <div id="hud">
      <span class="title">{safe_title}</span>
      <span class="stat">{counts["routers"]} routers</span>
      <span class="stat">{counts["transit_networks"]} transit</span>
      <span class="stat">{counts["stub_networks"]} stub</span>
      <span class="stat">{counts["neighbors"]} adjacencies</span>
      <span class="stat">{counts["routes"]} routes</span>
      <button id="all" title="Overview panel">overview</button>
      <button id="raw" title="Open the raw payload">json</button>
    </div>
    <div id="lanes"></div>
  </div>
  <div id="side"></div>
</div>
<script id="ospf-data" type="application/json">{data_json}</script>
<script>{_JS}</script>
</body>
</html>
"""
