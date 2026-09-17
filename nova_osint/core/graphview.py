"""Renderers for the entity graph: an interactive page, GraphML, and redaction.

A two-hundred-finding report is a wall of text; the same investigation as a
graph is one picture where the shape of the answer is visible before a word is
read. This draws that picture, and exports the same structure for tools that do
link analysis properly (Gephi, yEd, Cytoscape - all read GraphML).

Three decisions worth keeping:

**No CDN, no dependency.** The HTML embeds a force-directed layout written in
plain JavaScript, about a hundred lines. Loading d3 or vis.js from a CDN would
be shorter, and would mean a report that stops working offline, leaks the fact
it was opened to a third party, and cannot be attached to a case file that has
to stay self-contained.

**Edge width is evidence, not traffic.** The thing an analyst must be able to
see at a glance is *how much a link is worth*, so stroke width comes from the
log-odds and the Admiralty grade rides on the tooltip. A picture that makes a
string-similarity guess look like a cryptographic proof is worse than no
picture.

**Redaction is a rendering concern.** The store always holds the real values -
an investigation that quietly loses its own data is useless - so ``--redact``
masks at the point of output. Consistently: the same value masks to the same
token everywhere in one report, which keeps the graph readable while removing
the personal data.
"""

from __future__ import annotations

import hashlib
import html as html_mod
import json
import re
from typing import Any

from .entities import EntityType
from .graph import EntityGraph, Observation, probability
from .models import Investigation

# ---------------------------------------------------------------------------
# redaction
# ---------------------------------------------------------------------------

#: Entity kinds that identify a person rather than infrastructure. These are
#: what ``--redact`` masks; a domain or an ASN is a public fact about a company
#: and masking it would make the report unreadable for no privacy gain.
PERSONAL = frozenset({EntityType.EMAIL, EntityType.USERNAME, EntityType.PERSON,
                      EntityType.PHONE, EntityType.ADDRESS})

_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_PHONE_RE = re.compile(r"(?<!\w)\+?\d[\d\s().-]{7,17}\d(?!\w)")


class Redactor:
    """Masks personal values consistently within one report.

    ``alice@example.com`` becomes ``email:7f3a2c`` everywhere it appears, so the
    graph still shows that two accounts share an address without disclosing
    which address. The token is a truncated hash of the value with a per-report
    salt - stable inside the document, useless for looking the value up, and not
    comparable between two reports unless the same salt is passed deliberately.
    """

    def __init__(self, enabled: bool = True, salt: str = "") -> None:
        self.enabled = enabled
        self.salt = salt
        self._seen: dict[str, str] = {}

    def token(self, kind: str, value: str) -> str:
        key = f"{kind}:{value}".casefold()
        if key not in self._seen:
            digest = hashlib.sha256((self.salt + key).encode()).hexdigest()[:6]
            self._seen[key] = f"{kind}:{digest}"
        return self._seen[key]

    def entity(self, etype: EntityType, value: str) -> str:
        if not self.enabled or etype not in PERSONAL:
            return value
        return self.token(etype.value, value)

    def text(self, value: Any) -> str:
        """Mask addresses and phone numbers inside free text.

        A finding's *value* is arbitrary - a page title, an SPF record, a commit
        message - so entity-type masking cannot reach it. This is a regex pass,
        which means it is best-effort by construction: it will not catch a name,
        and it is documented as reducing exposure rather than guaranteeing it.
        """
        text = str(value)
        if not self.enabled:
            return text
        text = _EMAIL_RE.sub(lambda m: self.token("email", m.group(0)), text)
        return _PHONE_RE.sub(lambda m: self.token("phone", m.group(0)), text)

    @property
    def count(self) -> int:
        return len(self._seen)


# ---------------------------------------------------------------------------
# GraphML
# ---------------------------------------------------------------------------


def coverage_lines(inv: Investigation) -> list[str]:
    """Every module that did not get a clean run, and why.

    Shared by both graph renderers because the project's one hard reporting
    rule applies to pictures as much as to prose: "could not look" must never
    render as "found nothing".
    """
    lines = [f"{r.module}: {r.status.value}"
             + (f" - {r.status_reason}" if r.status_reason else "")
             for r in inv.incomplete]
    lines += [f"{name}: skipped - {reason}" for name, reason in inv.skipped]
    return lines


def render_graphml(inv: Investigation, redactor: Redactor | None = None) -> str:
    """GraphML, for Gephi / yEd / Cytoscape.

    Attributes are flattened onto nodes and edges because GraphML consumers
    expect scalars; the evidence behind an edge is joined into one string rather
    than dropped, so the reason for a link survives the export.
    """
    graph: EntityGraph | None = inv.graph
    red = redactor or Redactor(False)
    e = html_mod.escape
    out = [
        "<?xml version='1.0' encoding='UTF-8'?>",
        "<graphml xmlns='http://graphml.graphdrawing.org/xmlns'>",
    ]
    for key, name, target, typ in (
        ("d0", "label", "node", "string"), ("d1", "type", "node", "string"),
        ("d2", "score", "node", "double"), ("d3", "depth", "node", "int"),
        ("d4", "sources", "node", "string"),
        ("e0", "relation", "edge", "string"), ("e1", "llr", "edge", "double"),
        ("e2", "probability", "edge", "double"), ("e3", "grade", "edge", "string"),
        ("e4", "evidence", "edge", "string"),
        ("g0", "coverage_gaps", "graph", "string"),
    ):
        out.append(f"<key id='{key}' for='{target}' attr.name='{name}' "
                   f"attr.type='{typ}'/>")
    out.append(f"<graph id='{e(inv.target)}' edgedefault='undirected'>")
    # The export carries the gaps too. A graph handed to Gephi without them
    # shows a sparse picture and no reason for it, which reads as "there is
    # little here" rather than "we were not allowed to look".
    out.append(f"<data key='g0'>{e('; '.join(coverage_lines(inv)) or 'none')}</data>")
    if graph is not None:
        for node in graph:
            label = red.entity(node.entity.etype, node.entity.value)
            out.append(
                f"<node id='{e(node.entity.eid)}'>"
                f"<data key='d0'>{e(label)}</data>"
                f"<data key='d1'>{e(node.entity.etype.value)}</data>"
                f"<data key='d2'>{node.score:.4f}</data>"
                f"<data key='d3'>{node.depth}</data>"
                f"<data key='d4'>{e(','.join(sorted(node.sources)))}</data>"
                "</node>")
        for i, edge in enumerate(graph.edges.values()):
            why = "; ".join(f"{o.kind} ({o.module})" for o in edge.observations)
            out.append(
                f"<edge id='e{i}' source='{e(edge.src)}' target='{e(edge.dst)}'>"
                f"<data key='e0'>{e(edge.label)}</data>"
                f"<data key='e1'>{edge.llr:.3f}</data>"
                f"<data key='e2'>{edge.probability:.3f}</data>"
                f"<data key='e3'>{edge.grade}</data>"
                f"<data key='e4'>{e(why)}</data>"
                "</edge>")
    out.append("</graph></graphml>")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# interactive page
# ---------------------------------------------------------------------------

#: Colour per entity kind. Chosen to stay distinguishable in greyscale print,
#: because a report that has to be filed is a report that gets printed.
TYPE_COLOR = {
    "domain": "#7c5cff", "host": "#9b86ff", "ip": "#00c2a8", "cidr": "#00a890",
    "asn": "#00806e", "email": "#ff6b6b", "username": "#ffa94d",
    "person": "#ff4d94", "org": "#c77dff", "phone": "#ffd43b", "url": "#4dabf7",
    "cert": "#868e96", "spki": "#6c757d", "key": "#495057", "tracker": "#f06595",
    "favicon": "#20c997", "filehash": "#adb5bd", "crypto": "#fab005",
}


def graph_payload(inv: Investigation, redactor: Redactor | None = None
                  ) -> dict[str, Any]:
    """The JSON the page draws from. Also useful on its own, so it is public."""
    graph: EntityGraph | None = inv.graph
    red = redactor or Redactor(False)
    if graph is None:
        return {"seed": None, "nodes": [], "edges": [], "target": red.text(inv.target),
                "summary": {"entities": 0, "edges": 0, "hubs": 0, "by_type": {}}}
    nodes = []
    for node in graph:
        ent = node.entity
        nodes.append({
            "id": ent.eid,
            "label": red.entity(ent.etype, ent.display),
            "type": ent.etype.value,
            "score": round(node.score, 4),
            "depth": node.depth,
            "degree": graph.degree(ent.eid),
            "expanded": node.expanded,
            "sources": sorted(node.sources),
            "seed": ent.eid == graph.seed,
        })
    edges = []
    for edge in graph.edges.values():
        edges.append({
            "source": edge.src, "target": edge.dst, "label": edge.label,
            "llr": round(edge.llr, 3),
            "probability": round(edge.probability, 3),
            "grade": edge.grade,
            "why": [{"kind": o.kind, "module": o.module, "detail": o.detail,
                     "url": o.url, "evidence": o.evidence}
                    for o in edge.observations],
        })
    return {
        "seed": graph.seed, "nodes": nodes, "edges": edges,
        "target": red.text(inv.target),
        "summary": graph.to_dict()["summary"],
    }


def _script_json(value: Any) -> str:
    r"""JSON safe to embed inside a ``<script>`` block.

    ``json.dumps`` escapes nothing HTML cares about, so a target containing
    ``</script>`` closes the block early and the rest of the payload lands in
    the document as markup. Escaping the sequences that can terminate a script
    element is the fix; escaping the whole thing as HTML would corrupt the JSON.

    `` `` and `` `` are here because they are valid in JSON strings
    and are line terminators in JavaScript, which breaks the literal.
    """
    return (json.dumps(value)
            .replace("</", "<\\/")
            .replace("<!--", "<\\u0021--")
            .replace(" ", "\\u2028")
            .replace(" ", "\\u2029"))


def render_graph_html(inv: Investigation, redactor: Redactor | None = None) -> str:
    """A self-contained page: force-directed graph, evidence panel, no network."""
    red = redactor or Redactor(False)
    payload = graph_payload(inv, red)
    e = html_mod.escape
    note = ""
    if red.enabled:
        note = (f"<div class='redacted'>redacted - {red.count} personal value(s) "
                f"masked. Tokens are consistent within this document only.</div>")
    exp = ""
    if inv.expansion is not None:
        d = inv.expansion.to_dict()
        unreached = "".join(
            f"<li>{e(u['entity'])} <span class='dim'>({u['score']:.3f})</span></li>"
            for u in d["unexplored"][:10])
        exp = (f"<div class='panel'><h2>Expansion</h2>"
               f"<p>{d['rounds']} round(s), {len(d['expanded'])} entit(ies) expanded, "
               f"{d['module_runs']} module run(s).<br>Stopped by "
               f"<b>{e(d['stopped_by'])}</b>.</p>"
               + (f"<p class='dim'>Leads not reached:</p><ul>{unreached}</ul>"
                  if unreached else "") + "</div>")
    gaps = coverage_lines(inv)
    coverage = ("<div class='panel'><h2>Coverage gaps</h2><ul>"
                + "".join(f"<li>{e(line)}</li>" for line in gaps)
                + "</ul><p class='dim'>These sources did not answer. Absence here "
                  "is not evidence of absence.</p></div>") if gaps else ""
    return _PAGE.replace("__TITLE__", e(payload["target"])) \
                .replace("__COVERAGE__", coverage) \
                .replace("__DATA__", _script_json(payload)) \
                .replace("__COLORS__", _script_json(TYPE_COLOR)) \
                .replace("__NOTE__", note) \
                .replace("__EXPANSION__", exp)


_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Entity graph - __TITLE__</title>
<style>
  :root{--bg:#0b0b12;--fg:#e8e6f0;--dim:#8a87a0;--line:#24223a;--accent:#7c5cff}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);
       font:14px/1.5 ui-sans-serif,system-ui,'Segoe UI',sans-serif}
  header{padding:14px 18px;border-bottom:1px solid var(--line);
         display:flex;gap:16px;align-items:baseline;flex-wrap:wrap}
  h1{font-size:16px;margin:0;font-weight:600}
  h1 code{color:var(--accent)}
  .dim{color:var(--dim)}
  .redacted{background:#3a1c2b;color:#ffb3c8;padding:6px 12px;font-size:12px}
  main{display:flex;height:calc(100vh - 52px);flex-wrap:wrap}
  #cv{flex:1 1 520px;min-width:320px;display:block;cursor:grab}
  #cv:active{cursor:grabbing}
  aside{width:340px;max-width:100%;border-left:1px solid var(--line);
        overflow:auto;padding:14px 16px}
  .panel{margin-bottom:18px}
  h2{font-size:12px;text-transform:uppercase;letter-spacing:.08em;
     color:var(--dim);margin:0 0 8px}
  ul{margin:0;padding-left:18px}
  li{margin-bottom:4px;word-break:break-all}
  .chip{display:inline-block;padding:1px 7px;border-radius:9px;font-size:11px;
        margin-right:5px;color:#0b0b12;font-weight:600}
  .ev{border-left:2px solid var(--line);padding-left:9px;margin:7px 0}
  .grade{font-family:ui-monospace,monospace;color:var(--accent)}
  a{color:#7dd3fc}
  footer{padding:8px 18px;border-top:1px solid var(--line);font-size:12px}
  @media (max-width:820px){main{height:auto}#cv{height:60vh}aside{width:100%;
    border-left:none;border-top:1px solid var(--line)}}
</style></head><body>
<header>
  <h1>Entity graph &middot; <code>__TITLE__</code></h1>
  <span class="dim" id="counts"></span>
  <span class="dim">drag to pan &middot; scroll to zoom &middot; click a node</span>
</header>
__NOTE__
<main>
  <canvas id="cv"></canvas>
  <aside>
    <div class="panel"><h2>Selection</h2><div id="sel" class="dim">
      Click a node or an edge.</div></div>
    __COVERAGE__
    __EXPANSION__
    <div class="panel"><h2>Legend</h2><div id="legend"></div></div>
  </aside>
</main>
<footer class="dim">Edge thickness is the strength of the evidence, not the
amount of traffic. Grades are Admiralty: letter = source reliability, digit =
corroboration.</footer>
<script>
const DATA = __DATA__, COLORS = __COLORS__;
const cv = document.getElementById('cv'), ctx = cv.getContext('2d');
const nodes = DATA.nodes.map(n => ({...n,
  x: (Math.random()-0.5)*400, y: (Math.random()-0.5)*400, vx:0, vy:0}));
const byId = Object.fromEntries(nodes.map(n => [n.id, n]));
const edges = DATA.edges.filter(e => byId[e.source] && byId[e.target])
  .map(e => ({...e, a: byId[e.source], b: byId[e.target]}));
document.getElementById('counts').textContent =
  nodes.length + ' entities, ' + edges.length + ' edges';

let view = {x:0, y:0, k:1}, selected = null, dragging = null, hover = null;
function resize(){
  const r = cv.getBoundingClientRect();
  cv.width = r.width * devicePixelRatio; cv.height = r.height * devicePixelRatio;
}
addEventListener('resize', resize); resize();

// Radius encodes relevance, not degree: the question a reader has is "how much
// does this matter to the target", and degree answers a different one.
const radius = n => 5 + 13 * Math.sqrt(Math.max(n.score, 0.01)) + (n.seed ? 4 : 0);
const width  = e => Math.max(0.6, Math.min(5, Math.abs(e.llr) / 1.6));

function step(){
  for (const n of nodes){
    n.vx *= 0.82; n.vy *= 0.82;
    // Pull to the centre, so a disconnected component cannot drift off-screen.
    n.vx -= n.x * 0.0016; n.vy -= n.y * 0.0016;
  }
  for (let i = 0; i < nodes.length; i++){
    for (let j = i + 1; j < nodes.length; j++){
      const a = nodes[i], b = nodes[j];
      let dx = b.x - a.x, dy = b.y - a.y, d2 = dx*dx + dy*dy || 0.01;
      if (d2 > 90000) continue;
      const f = 1400 / d2, d = Math.sqrt(d2);
      const ux = dx/d*f, uy = dy/d*f;
      a.vx -= ux; a.vy -= uy; b.vx += ux; b.vy += uy;
    }
  }
  for (const e of edges){
    // A better-evidenced edge is a shorter, stiffer spring, so the strongly
    // connected part of the graph clusters and the guesses float outward.
    const p = Math.max(0.05, e.probability);
    const rest = 190 - 110 * p, k = 0.006 + 0.02 * p;
    const dx = e.b.x - e.a.x, dy = e.b.y - e.a.y;
    const d = Math.hypot(dx, dy) || 0.01, f = (d - rest) * k;
    const ux = dx/d*f, uy = dy/d*f;
    e.a.vx += ux; e.a.vy += uy; e.b.vx -= ux; e.b.vy -= uy;
  }
  for (const n of nodes){
    if (n === dragging) continue;
    n.x += Math.max(-8, Math.min(8, n.vx));
    n.y += Math.max(-8, Math.min(8, n.vy));
  }
}

function draw(){
  const w = cv.width, h = cv.height;
  ctx.setTransform(1,0,0,1,0,0);
  ctx.clearRect(0,0,w,h);
  ctx.setTransform(view.k*devicePixelRatio, 0, 0, view.k*devicePixelRatio,
                   w/2 + view.x*devicePixelRatio, h/2 + view.y*devicePixelRatio);
  for (const e of edges){
    const on = selected && (selected.id === e.source || selected.id === e.target);
    ctx.strokeStyle = e.llr < 0 ? 'rgba(255,90,90,.55)'
                    : on ? 'rgba(124,92,255,.95)' : 'rgba(150,145,190,.30)';
    ctx.lineWidth = width(e);
    if (e.llr <= 0.05) ctx.setLineDash([4,4]); else ctx.setLineDash([]);
    ctx.beginPath(); ctx.moveTo(e.a.x, e.a.y); ctx.lineTo(e.b.x, e.b.y); ctx.stroke();
  }
  ctx.setLineDash([]);
  for (const n of nodes){
    const r = radius(n);
    ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, 6.2832);
    ctx.fillStyle = COLORS[n.type] || '#9aa';
    ctx.globalAlpha = n.expanded || n.seed ? 1 : 0.72;
    ctx.fill(); ctx.globalAlpha = 1;
    if (n === selected || n === hover){
      ctx.strokeStyle = '#fff'; ctx.lineWidth = 2; ctx.stroke();
    }
    if (n.seed){ ctx.strokeStyle = '#fff'; ctx.lineWidth = 1.5; ctx.stroke(); }
    if (view.k > 0.55 || n.seed || n.score > 0.3){
      ctx.fillStyle = '#e8e6f0';
      ctx.font = (n.seed ? '600 ' : '') + '11px ui-sans-serif,system-ui,sans-serif';
      ctx.fillText(n.label.length > 34 ? n.label.slice(0,33) + '\\u2026' : n.label,
                   n.x + r + 4, n.y + 4);
    }
  }
}

function frame(){ step(); draw(); requestAnimationFrame(frame); }
frame();

function toWorld(ev){
  const r = cv.getBoundingClientRect();
  return {x: (ev.clientX - r.left - r.width/2 - view.x) / view.k,
          y: (ev.clientY - r.top - r.height/2 - view.y) / view.k};
}
function pick(p){
  let best = null, bd = 1e9;
  for (const n of nodes){
    const d = Math.hypot(n.x - p.x, n.y - p.y);
    if (d < radius(n) + 5 && d < bd){ best = n; bd = d; }
  }
  return best;
}
let panning = false, last = null;
cv.addEventListener('mousedown', ev => {
  const n = pick(toWorld(ev));
  if (n){ dragging = n; select(n); } else { panning = true; last = ev; }
});
addEventListener('mousemove', ev => {
  if (dragging){ const p = toWorld(ev); dragging.x = p.x; dragging.y = p.y; }
  else if (panning && last){ view.x += ev.clientX - last.clientX;
                             view.y += ev.clientY - last.clientY; last = ev; }
  else hover = pick(toWorld(ev));
});
addEventListener('mouseup', () => { dragging = null; panning = false; last = null; });
cv.addEventListener('wheel', ev => {
  ev.preventDefault();
  view.k = Math.max(0.15, Math.min(4, view.k * (ev.deltaY < 0 ? 1.12 : 0.89)));
}, {passive:false});

const esc = s => String(s).replace(/[&<>"]/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

function select(n){
  selected = n;
  const mine = edges.filter(e => e.source === n.id || e.target === n.id)
                    .sort((a,b) => b.llr - a.llr);
  let html = '<div><span class="chip" style="background:' +
    (COLORS[n.type] || '#9aa') + '">' + esc(n.type) + '</span><b>' +
    esc(n.label) + '</b></div>' +
    '<p class="dim">relevance ' + n.score.toFixed(3) + ' &middot; depth ' +
    n.depth + ' &middot; ' + n.degree + ' neighbour(s)' +
    (n.expanded ? '' : ' &middot; not expanded') + '</p>';
  if (n.sources.length)
    html += '<p class="dim">found by ' + esc(n.sources.join(', ')) + '</p>';
  if (n.degree >= 12)
    html += '<p class="dim">High degree - this looks like shared infrastructure. ' +
            'Links through it are demoted automatically.</p>';
  html += '<h2 style="margin-top:14px">Why it is connected</h2>';
  for (const e of mine){
    const other = e.source === n.id ? e.target : e.source;
    html += '<div class="ev"><b>' + esc(e.label) + '</b> &rarr; ' +
      esc((byId[other] || {}).label || other) +
      '<br><span class="grade">' + esc(e.grade) + '</span> ' +
      '<span class="dim">llr ' + e.llr.toFixed(2) + ' &middot; p=' +
      e.probability.toFixed(2) + '</span>';
    for (const w of e.why){
      html += '<br><span class="dim">' + esc(w.kind) + ' via ' + esc(w.module) +
        (w.detail ? ' - ' + esc(w.detail) : '') +
        (w.url ? ' <a href="' + esc(w.url) + '" rel="noreferrer noopener">source</a>'
               : '') +
        (w.evidence ? ' <span title="sha256 of the stored response">[' +
           esc(w.evidence.slice(0,10)) + ']</span>' : '') + '</span>';
    }
    html += '</div>';
  }
  document.getElementById('sel').innerHTML = html;
}

document.getElementById('legend').innerHTML =
  [...new Set(nodes.map(n => n.type))].sort().map(t =>
    '<span class="chip" style="background:' + (COLORS[t] || '#9aa') + '">' +
    esc(t) + '</span>').join(' ');
if (DATA.seed && byId[DATA.seed]) select(byId[DATA.seed]);
</script></body></html>
"""


def render_graph_json(inv: Investigation, redactor: Redactor | None = None) -> str:
    return json.dumps(graph_payload(inv, redactor), indent=2)


def redact_investigation(inv: Investigation, redactor: Redactor) -> Investigation:
    """Mask personal values in a copy of the investigation, for rendering.

    A copy, not an edit in place: the case store must keep the real values, and
    a renderer that mutated the object would silently redact whatever ran after
    it - including the save.
    """
    import copy

    out = copy.deepcopy(inv)
    for result in out.results:
        for finding in result.findings:
            finding.label = redactor.text(finding.label)
            if isinstance(finding.value, list):
                finding.value = [redactor.text(v) for v in finding.value]
            else:
                finding.value = redactor.text(finding.value)
            if finding.url:
                finding.url = redactor.text(finding.url)
    out.target = redactor.text(inv.target)
    if out.graph is not None:
        out.graph = _redact_graph(out.graph, redactor)
    return out


def _redact_graph(graph: EntityGraph, redactor: Redactor) -> EntityGraph:
    """Rebuild the graph with masked entities.

    Masking ``entity.value`` in place is not enough, and the first version of
    this did exactly that. An edge stores endpoint *ids*, and an id is derived
    from the value, so every masked address was still spelled out in full on
    both ends of every edge it touched - the page looked redacted and was not.
    The graph has to be rebuilt so the ids are regenerated from masked values.
    """
    from .entities import Entity as _Entity

    def mask(ent: Any) -> Any:
        value = redactor.entity(ent.etype, ent.value)
        if value == ent.value:
            return ent
        # Constructed directly rather than through Entity.make: the masked token
        # is not a canonical email or handle, and its own canonicaliser would
        # reject it.
        return _Entity(ent.etype, value, "", dict(ent.attrs))

    masked = EntityGraph()
    remap = {n.entity.eid: mask(n.entity) for n in graph}
    for node in graph:
        fresh = masked.add(remap[node.entity.eid], score=node.score, depth=node.depth)
        fresh.expanded = node.expanded
        fresh.sources = set(node.sources)
    if graph.seed in remap:
        masked.seed = remap[graph.seed].eid
    for edge in graph.edges.values():
        src, dst = remap.get(edge.src), remap.get(edge.dst)
        if src is None or dst is None:
            continue
        for ob in edge.observations:
            masked.connect(src, dst, edge.label, Observation(
                kind=ob.kind, module=ob.module,
                url=redactor.text(ob.url) if ob.url else None,
                detail=redactor.text(ob.detail), evidence=ob.evidence, llr=ob.llr))
    masked.rescore()
    return masked


def probability_note(llr: float) -> str:
    """One sentence a reader can act on, from a log-odds number."""
    p = probability(llr)
    if p >= 0.97:
        return "near certain"
    if p >= 0.85:
        return "probable"
    if p >= 0.6:
        return "more likely than not"
    if p > 0.5:
        return "weakly suggestive"
    return "no support, or evidence against"
