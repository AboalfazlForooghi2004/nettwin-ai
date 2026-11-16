"""Interactive, dependency-free HTML topology viewer (Phase 2.5).

Requirements this satisfies, and how:

* **works with no backend** — one ``.html`` file with the CSS, the JavaScript
  and the topology data all inline. No CDN, no fetch(), no build step. Opening
  the file from disk is enough.
* **generated from normalized topology data** — the payload is built by
  :func:`build_payload` from the domain models only.
* **zoom, pan, drag** — a from-scratch SVG viewport in plain ES2019, no d3.
* **device details on click** — name, vendor, platform, management address,
  per-interface addresses and the states the model evidences.
* **link details on click** — both endpoints and both interface names.
* **never claims unevidenced state** — an interface state is only rendered
  when the model carries it; otherwise the panel says "not evidenced".
"""

from __future__ import annotations

import json
from html import escape
from typing import Any

from nettwin.domain.models import Interface, Topology


def _interface_payload(iface: Interface) -> dict[str, Any]:
    """Serialize one interface, flagging what the evidence actually supports."""
    return {
        "id": iface.id,
        "name": iface.name,
        "device_id": iface.device_id,
        "addresses": [str(a) for a in iface.ipv4_addresses],
        "admin_state": str(iface.admin_state),
        "oper_state": str(iface.oper_state),
        # The model always carries both enums, so both are evidenced by
        # construction; the flag exists so the UI never has to guess.
        "state_evidenced": True,
        "is_up": iface.is_up,
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


def build_payload(topology: Topology, *, title: str, run_id: str = "") -> dict[str, Any]:
    """Build the JSON payload embedded in the page.

    Pure function of the normalized models — this is the single place the
    renderer reads from, which is what keeps the drawing honest.
    """
    interfaces = {i.id: i for i in topology.interfaces}
    devices = [
        {
            "id": d.id,
            "name": d.name,
            "vendor": d.vendor,
            "platform": d.platform,
            "management_address": (
                str(d.management_address) if d.management_address is not None else None
            ),
            "metadata": d.metadata,
        }
        for d in topology.devices
    ]
    links = []
    for link in topology.links:
        src = interfaces.get(link.source_interface_id)
        dst = interfaces.get(link.destination_interface_id)
        links.append(
            {
                "id": link.id,
                "state": str(link.state),
                "source": {
                    "device_id": src.device_id if src else "",
                    "interface_id": link.source_interface_id,
                    "interface_name": src.name if src else "",
                    "addresses": [str(a) for a in src.ipv4_addresses] if src else [],
                    "state_evidenced": src is not None,
                },
                "destination": {
                    "device_id": dst.device_id if dst else "",
                    "interface_id": link.destination_interface_id,
                    "interface_name": dst.name if dst else "",
                    "addresses": [str(a) for a in dst.ipv4_addresses] if dst else [],
                    "state_evidenced": dst is not None,
                },
            }
        )
    return {
        "title": title,
        "run_id": run_id,
        "devices": devices,
        "interfaces": [_interface_payload(i) for i in topology.interfaces],
        "links": links,
        "counts": {
            "devices": len(topology.devices),
            "interfaces": len(topology.interfaces),
            "links": len(topology.links),
            "routes": len(topology.routes),
        },
    }


_CSS = """
:root{
  --bg:#0f1419; --panel:#161d26; --panel2:#1d2733; --ink:#e6edf3; --muted:#8b98a5;
  --line:#2b3846; --accent:#4aa3ff; --up:#3fb950; --down:#f85149; --node:#1c2836;
}
*{box-sizing:border-box}
html,body{margin:0;height:100%;background:var(--bg);color:var(--ink);
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
#app{display:flex;height:100vh}
#stage{flex:1;position:relative;overflow:hidden;cursor:grab;touch-action:none}
#stage.grabbing{cursor:grabbing}
#hud{position:absolute;top:12px;left:12px;z-index:5;display:flex;gap:6px;flex-wrap:wrap;align-items:center}
#hud .title{font-size:13px;font-weight:600;margin-right:8px}
button{background:var(--panel2);color:var(--ink);border:1px solid var(--line);
  border-radius:6px;padding:5px 10px;font:inherit;font-size:11px;cursor:pointer}
button:hover{border-color:var(--accent)}
button.on{border-color:var(--accent);color:var(--accent)}
#legend{position:absolute;bottom:12px;left:12px;font-size:10.5px;color:var(--muted);
  display:flex;gap:14px;flex-wrap:wrap;z-index:5}
#legend i{display:inline-block;width:16px;height:2px;vertical-align:middle;margin-right:5px}
#side{width:330px;border-left:1px solid var(--line);background:var(--panel);
  overflow-y:auto;padding:14px;font-size:12px}
#side h2{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);
  margin:0 0 10px;font-weight:600}
#side .empty{color:var(--muted);line-height:1.6}
.kv{display:grid;grid-template-columns:96px 1fr;gap:4px 8px;margin-bottom:12px}
.kv dt{color:var(--muted)}
.kv dd{margin:0;word-break:break-word}
.iface{border:1px solid var(--line);border-radius:6px;padding:7px 9px;margin-bottom:6px;
  background:var(--panel2)}
.iface .nm{font-weight:600;display:flex;justify-content:space-between;gap:8px}
.pill{font-size:10px;padding:1px 6px;border-radius:99px;border:1px solid var(--line)}
.pill.up{color:var(--up);border-color:var(--up)}
.pill.down{color:var(--down);border-color:var(--down)}
.pill.unknown{color:var(--muted)}
.addr{color:var(--accent);font-size:11px;margin-top:2px}
.tag{display:inline-block;font-size:10px;color:var(--muted);border:1px solid var(--line);
  border-radius:4px;padding:1px 5px;margin-right:4px}
#tip{position:absolute;pointer-events:none;background:var(--panel2);border:1px solid var(--line);
  border-radius:6px;padding:5px 8px;font-size:11px;opacity:0;transition:opacity .1s;z-index:9;
  white-space:nowrap}
#tip.show{opacity:1}
"""

_JS = r"""
(function(){
"use strict";
var DATA = JSON.parse(document.getElementById("topology-data").textContent);

// ---- index ---------------------------------------------------------------
var devById = {}, ifaceById = {}, linksOfDevice = {};
DATA.devices.forEach(function(d){ devById[d.id]=d; linksOfDevice[d.id]=[]; });
DATA.interfaces.forEach(function(i){ ifaceById[i.id]=i; });
DATA.links.forEach(function(l){
  if(linksOfDevice[l.source.device_id]) linksOfDevice[l.source.device_id].push(l);
  if(linksOfDevice[l.destination.device_id]) linksOfDevice[l.destination.device_id].push(l);
});

// ---- layout: deterministic BFS, same rule as the SVG renderer -------------
var positions = {}, placed = {};
var adjacency = {};
DATA.devices.forEach(function(d){ adjacency[d.id]=[]; });
DATA.links.forEach(function(l){
  var a=l.source.device_id, b=l.destination.device_id;
  if(a&&b&&a!==b){ adjacency[a].push(b); adjacency[b].push(a); }
});
Object.keys(adjacency).forEach(function(k){
  adjacency[k]=adjacency[k].filter(function(v,i,s){return s.indexOf(v)===i;}).sort();
});
var order = Object.keys(adjacency).sort(function(a,b){
  var d = adjacency[b].length-adjacency[a].length;
  return d !== 0 ? d : (a<b?-1:a>b?1:0);
});
var COL=300, ROW=150;
order.forEach(function(root){
  if(placed[root]) return;
  var queue=[[root,0]], colCount={};
  while(queue.length){
    var item=queue.shift(), id=item[0], depth=item[1];
    if(placed[id]) continue;
    placed[id]=true;
    var row=colCount[depth]||0; colCount[depth]=row+1;
    positions[id]={x:60+depth*COL, y:60+row*ROW};
    adjacency[id].forEach(function(nb){ if(!placed[nb]) queue.push([nb,depth+1]); });
  }
});

// ---- svg scaffolding ------------------------------------------------------
var SVGNS="http://www.w3.org/2000/svg";
var stage=document.getElementById("stage");
var svg=document.createElementNS(SVGNS,"svg");
svg.setAttribute("width","100%"); svg.setAttribute("height","100%");
stage.appendChild(svg);
var viewport=document.createElementNS(SVGNS,"g");
svg.appendChild(viewport);
var edgeLayer=document.createElementNS(SVGNS,"g");
var nodeLayer=document.createElementNS(SVGNS,"g");
viewport.appendChild(edgeLayer); viewport.appendChild(nodeLayer);

var W=190, H=84;
function el(name,attrs,parent){
  var e=document.createElementNS(SVGNS,name);
  for(var k in attrs) if(attrs.hasOwnProperty(k)) e.setAttribute(k,attrs[k]);
  if(parent) parent.appendChild(e);
  return e;
}

// ---- viewport transform ---------------------------------------------------
var view={x:0,y:0,k:1};
function applyView(){
  viewport.setAttribute("transform","translate("+view.x+","+view.y+") scale("+view.k+")");
}
applyView();

function svgPoint(evt){
  var r=svg.getBoundingClientRect();
  return {x:evt.clientX-r.left, y:evt.clientY-r.top};
}
function toWorld(p){ return {x:(p.x-view.x)/view.k, y:(p.y-view.y)/view.k}; }

// zoom on wheel, centred on the pointer
svg.addEventListener("wheel",function(e){
  e.preventDefault();
  var p=svgPoint(e), before=toWorld(p);
  var factor = e.deltaY<0 ? 1.12 : 1/1.12;
  var k = Math.min(4, Math.max(0.15, view.k*factor));
  view.x = p.x - before.x*k;
  view.y = p.y - before.y*k;
  view.k = k;
  applyView();
},{passive:false});

// pan with background drag
var panning=null;
function isBackground(target){
  // Only the empty canvas pans. Nodes and link hit-areas handle themselves,
  // and pointer capture here would swallow their click events.
  return target===svg || target===stage;
}
svg.addEventListener("pointerdown",function(e){
  if(!isBackground(e.target)) return;
  panning={x:e.clientX,y:e.clientY,ox:view.x,oy:view.y};
  stage.classList.add("grabbing");
  try{ svg.setPointerCapture(e.pointerId); }catch(err){}
});
svg.addEventListener("pointermove",function(e){
  if(!panning) return;
  view.x=panning.ox+(e.clientX-panning.x);
  view.y=panning.oy+(e.clientY-panning.y);
  applyView();
});
function endPan(e){
  if(!panning) return;
  panning=null; stage.classList.remove("grabbing");
  try{ svg.releasePointerCapture(e.pointerId); }catch(err){}
}
svg.addEventListener("pointerup",endPan);
svg.addEventListener("pointercancel",endPan);

// ---- draw edges -----------------------------------------------------------
var linkEls={};
DATA.links.forEach(function(link){
  var a=positions[link.source.device_id], b=positions[link.destination.device_id];
  if(!a||!b) return;
  var up = link.state==="up";
  var line=el("line",{
    x1:a.x+W/2, y1:a.y+H/2, x2:b.x+W/2, y2:b.y+H/2,
    stroke: up?"#3fb950":"#f85149", "stroke-width":2,
    "stroke-dasharray": up?"":"6 4", "stroke-linecap":"round"
  },edgeLayer);
  // A wide invisible companion makes the thin line clickable.
  // The visible edge is 2px thin; this companion makes it easy to hit. It is
  // drawn with a hair of opacity rather than "transparent" so every browser
  // keeps it hit-testable.
  var hit=el("line",{
    x1:a.x+W/2, y1:a.y+H/2, x2:b.x+W/2, y2:b.y+H/2,
    stroke: up?"#3fb950":"#f85149", "stroke-opacity":"0.001",
    "stroke-width":14, "stroke-linecap":"round", style:"cursor:pointer"
  },edgeLayer);
  var label=[link.source.interface_name||"?",link.destination.interface_name||"?"].join(" \u2194 ");
  var mx=(a.x+b.x)/2+W/2, my=(a.y+b.y)/2+H/2-6;
  el("rect",{x:mx-3,y:my-11,width:Math.min(label.length*6+10,300),height:14,rx:3,
    fill:"#0f1419",opacity:0.85},edgeLayer);
  el("text",{x:mx,y:my,fill:"#8b98a5","font-size":9.5,"text-anchor":"start"},edgeLayer)
    .textContent=label;
  linkEls[link.id]={line:line,hit:hit};
  hit.addEventListener("click",function(e){ e.stopPropagation(); showLink(link); });
  hit.addEventListener("pointerenter",function(){ line.setAttribute("stroke-width",3.5); });
  hit.addEventListener("pointerleave",function(){ line.setAttribute("stroke-width",2); });
});

// ---- draw nodes -----------------------------------------------------------
var nodeEls={};
DATA.devices.forEach(function(d){
  var p=positions[d.id]; if(!p) return;
  var g=el("g",{transform:"translate("+p.x+","+p.y+")",class:"node",style:"cursor:pointer"},nodeLayer);
  el("rect",{width:W,height:H,rx:7,fill:"#1c2836",stroke:"#4aa3ff","stroke-width":1.6},g);
  el("text",{x:12,y:22,fill:"#e6edf3","font-size":13,"font-weight":600},g).textContent=d.name;
  var sub=[d.vendor,d.platform].filter(function(v){return v&&v!=="unknown";}).join(" / ")||"vendor not evidenced";
  el("text",{x:12,y:40,fill:"#8b98a5","font-size":10},g).textContent=sub;
  el("text",{x:12,y:56,fill:"#9fb0c0","font-size":10},g)
    .textContent=d.management_address||"management IP not evidenced";
  var mine=DATA.interfaces.filter(function(i){return i.device_id===d.id;});
  if(mine.length){
    var up=mine.filter(function(i){return i.is_up;}).length;
    el("text",{x:12,y:72,fill:"#8b98a5","font-size":9.5},g).textContent=up+"/"+mine.length+" interface(s) up";
  }
  nodeEls[d.id]=g;

  // drag to reposition, click to select
  var dragging=null;
  g.addEventListener("pointerdown",function(e){
    e.stopPropagation();
    var start=svgPoint(e);
    dragging={sx:start.x,sy:start.y,px:p.x,py:p.y,id:d.id,moved:false};
    g.setPointerCapture(e.pointerId);
  });
  g.addEventListener("pointermove",function(e){
    if(!dragging) return;
    var now=svgPoint(e), w=toWorld(now), w0=toWorld({x:dragging.sx,y:dragging.sy});
    var dx=w.x-w0.x, dy=w.y-w0.y;
    if(Math.abs(dx)+Math.abs(dy)>2) dragging.moved=true;
    positions[d.id]={x:dragging.px+dx, y:dragging.py+dy};
    g.setAttribute("transform","translate("+positions[d.id].x+","+positions[d.id].y+")");
    redrawEdgesFor(d.id);
  });
  g.addEventListener("pointerup",function(e){
    var wasClick = dragging && !dragging.moved;
    dragging=null;
    try{ g.releasePointerCapture(e.pointerId); }catch(err){}
    if(wasClick){
      e.stopPropagation();
      selectNode(d.id);
      showDevice(d);
    }
  });
  g.addEventListener("pointerenter",function(){ g.firstChild.setAttribute("stroke-width",2.6); });
  g.addEventListener("pointerleave",function(){ g.firstChild.setAttribute("stroke-width",1.6); });
});

function selectNode(deviceId){
  Object.keys(nodeEls).forEach(function(id){
    var stroke = (id===deviceId) ? "#7cc4ff" : "#4aa3ff";
    var width  = (id===deviceId) ? 3 : 1.6;
    nodeEls[id].firstChild.setAttribute("stroke",stroke);
    nodeEls[id].firstChild.setAttribute("stroke-width",width);
  });
}

function redrawEdgesFor(deviceId){
  DATA.links.forEach(function(link){
    if(link.source.device_id!==deviceId && link.destination.device_id!==deviceId) return;
    var a=positions[link.source.device_id], b=positions[link.destination.device_id];
    var els=linkEls[link.id]; if(!a||!b||!els) return;
    els.line.setAttribute("x1",a.x+W/2); els.line.setAttribute("y1",a.y+H/2);
    els.line.setAttribute("x2",b.x+W/2); els.line.setAttribute("y2",b.y+H/2);
    els.hit.setAttribute("x1",a.x+W/2); els.hit.setAttribute("y1",a.y+H/2);
    els.hit.setAttribute("x2",b.x+W/2); els.hit.setAttribute("y2",b.y+H/2);
  });
}

// ---- side panel -----------------------------------------------------------
var side=document.getElementById("side");
function esc(s){
  return String(s==null?"":s).replace(/[&<>"']/g,function(c){
    return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];
  });
}
function statePill(isUp, evidenced){
  if(!evidenced) return '<span class="pill unknown">state not evidenced</span>';
  return isUp ? '<span class="pill up">up</span>' : '<span class="pill down">down</span>';
}
function showDevice(d){
  var mine=DATA.interfaces.filter(function(i){return i.device_id===d.id;});
  var links=linksOfDevice[d.id]||[];
  var h='<h2>Device</h2>';
  h+='<dl class="kv">';
  h+='<dt>Name</dt><dd>'+esc(d.name)+'</dd>';
  h+='<dt>Vendor</dt><dd>'+esc(d.vendor||"unknown")+'</dd>';
  h+='<dt>Platform</dt><dd>'+esc(d.platform||"not evidenced")+'</dd>';
  h+='<dt>Mgmt IP</dt><dd>'+(d.management_address?esc(d.management_address):'<span class="pill unknown">not evidenced</span>')+'</dd>';
  var meta=d.metadata||{};
  var keys=["serial","fortios_version","fortios_build","ios_version","vdom","model"].filter(function(k){return meta[k];});
  if(keys.length){
    h+='<dt>Details</dt><dd>'+keys.map(function(k){
      return '<span class="tag">'+esc(k)+': '+esc(meta[k])+'</span>';
    }).join("")+'</dd>';
  }
  h+='</dl>';
  h+='<h2>Interfaces ('+mine.length+')</h2>';
  if(!mine.length) h+='<p class="empty">No interface evidence collected for this device.</p>';
  mine.forEach(function(i){
    h+='<div class="iface"><div class="nm"><span>'+esc(i.name)+'</span>'+statePill(i.is_up,i.state_evidenced)+'</div>';
    if(i.addresses.length) h+='<div class="addr">'+i.addresses.map(esc).join(", ")+'</div>';
    else h+='<div class="addr" style="color:#6b7785">no IPv4 address collected</div>';
    h+='</div>';
  });
  h+='<h2>Links ('+links.length+')</h2>';
  if(!links.length) h+='<p class="empty">No confirmed link touches this device.</p>';
  links.forEach(function(l){
    var fwd = l.source.device_id===d.id;
    var far = fwd?l.destination:l.source;
    var near = fwd?l.source:l.destination;
    var farDev=devById[far.device_id];
    h+='<div class="iface"><div class="nm"><span>'+esc(near.interface_name||"?")+'</span>'+
       '<span class="pill '+(l.state==="up"?"up":"down")+'">'+esc(l.state)+'</span></div>'+
       '<div style="color:#8b98a5;font-size:11px;margin-top:3px">\u2192 '+
       esc(farDev?farDev.name:far.device_id)+' ['+esc(far.interface_name||"?")+']</div></div>';
  });
  side.innerHTML=h;
}
function showLink(l){
  var a=devById[l.source.device_id], b=devById[l.destination.device_id];
  var h='<h2>Link</h2><dl class="kv">';
  h+='<dt>State</dt><dd><span class="pill '+(l.state==="up"?"up":"down")+'">'+esc(l.state)+'</span></dd>';
  h+='<dt>Endpoint A</dt><dd>'+esc(a?a.name:l.source.device_id)+'<br><span class="addr">'+esc(l.source.interface_name||"?")+'</span>'+
     (l.source.addresses.length?'<br>'+l.source.addresses.map(esc).join(", "):'')+'</dd>';
  h+='<dt>Endpoint B</dt><dd>'+esc(b?b.name:l.destination.device_id)+'<br><span class="addr">'+esc(l.destination.interface_name||"?")+'</span>'+
     (l.destination.addresses.length?'<br>'+l.destination.addresses.map(esc).join(", "):'')+'</dd>';
  h+='</dl><p class="empty">Confirmed by two-sided neighbour evidence; '
    +'not inferred from IP addressing.</p>';
  side.innerHTML=h;
}
stage.addEventListener("click",function(e){
  // Node and link clicks bubble up here; only a click on the empty background
  // should clear the panel, otherwise selecting anything is instantly undone.
  if(e.target===svg || e.target===stage) resetPanel();
});
function resetPanel(){
  side.innerHTML='<h2>Topology</h2><dl class="kv">'+
    '<dt>Devices</dt><dd>'+DATA.counts.devices+'</dd>'+
    '<dt>Interfaces</dt><dd>'+DATA.counts.interfaces+'</dd>'+
    '<dt>Links</dt><dd>'+DATA.counts.links+'</dd>'+
    '<dt>Routes</dt><dd>'+DATA.counts.routes+'</dd>'+
    '</dl><p class="empty">Click a device or a link to inspect it.<br><br>'+
    'Drag the background to pan, drag a device to move it, scroll to zoom.</p>';
}
resetPanel();

// ---- controls -------------------------------------------------------------
document.getElementById("zin").onclick=function(){ zoomBy(1.25); };
document.getElementById("zout").onclick=function(){ zoomBy(1/1.25); };
document.getElementById("zfit").onclick=function(){ fit(); };
document.getElementById("ztoggle").onclick=function(e){
  var on=this.classList.toggle("on");
  document.getElementById("legend").style.display=on?"none":"flex";
};
function zoomBy(f, cx, cy){
  var r=svg.getBoundingClientRect();
  var p = (cx==null)? {x:r.width/2,y:r.height/2} : {x:cx-r.left,y:cy-r.top};
  var before=toWorld(p);
  var k=Math.min(4,Math.max(0.15,view.k*f));
  view.x=p.x-before.x*k; view.y=p.y-before.y*k; view.k=k;
  applyView();
}
function fit(){
  var xs=[],ys=[];
  Object.keys(positions).forEach(function(id){ xs.push(positions[id].x); ys.push(positions[id].y); });
  if(!xs.length){ view={x:0,y:0,k:1}; applyView(); return; }
  var minX=Math.min.apply(null,xs)-40, maxX=Math.max.apply(null,xs)+W+40;
  var minY=Math.min.apply(null,ys)-40, maxY=Math.max.apply(null,ys)+H+40;
  var r=svg.getBoundingClientRect();
  var k=Math.min(r.width/(maxX-minX), r.height/(maxY-minY));
  view.k=Math.min(1.6,Math.max(0.15,k));
  view.x=(r.width-(maxX-minX)*view.k)/2-minX*view.k;
  view.y=(r.height-(maxY-minY)*view.k)/2-minY*view.k;
  applyView();
}
fit();
window.addEventListener("resize",fit) ;
})();
"""


def render_html(topology: Topology, *, title: str = "Network topology", run_id: str = "") -> str:
    """Render a single self-contained interactive HTML document."""
    payload = build_payload(topology, title=title, run_id=run_id)
    data_json = _embed_json(payload)
    safe_title = escape(title)
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
      <button id="zin" title="Zoom in">+</button>
      <button id="zout" title="Zoom out">&minus;</button>
      <button id="zfit" title="Fit to view">fit</button>
      <button id="ztoggle" title="Toggle legend">legend</button>
    </div>
    <div id="legend">
      <span><i style="background:#3fb950"></i>link up</span>
      <span><i style="background:#f85149"></i>link down</span>
      <span>drag background = pan &middot; scroll = zoom &middot; drag device = move</span>
    </div>
  </div>
  <div id="side"></div>
</div>
<script id="topology-data" type="application/json">{data_json}</script>
<script>{_JS}</script>
</body>
</html>
"""
