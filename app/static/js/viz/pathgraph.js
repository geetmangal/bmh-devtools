// Layered AS-path graph in pure SVG. Columns are hops from the origin (origin on the right, collector peers and
// transits to the left), node size follows how many paths run through the AS, edge width follows how many paths use
// that link. Hover or focus a node to light up every route from it to the origin. Click or Enter opens the ASN lookup.
// Toggles: "Top paths / All" and "Hide collector peers". A plain list for screen readers sits under the picture.
import { h, svg, srOnly, plural } from '../ui/dom.js';
import { config } from '../ui/tool.js';

const MINCOL = 150, ROW = 56, PADL = 84, PADR = 84, PADT = 34, TOP_NODES = 14, LABEL_CH = 22;
const trunc = (s, n) => (s && s.length > n ? s.slice(0, n - 1) + '…' : s || '');
const ROLE_WORD = { origin: 'Origin', upstream: 'Upstream', transit: 'Transit', peer: 'Collector peer' };
const FILL = { origin: 'var(--ink)', upstream: 'var(--accent)', transit: 'var(--mute)', peer: 'var(--surface)' };

const isEmbed = () => !!document.documentElement.dataset.embed;
export const asnHref = (asn) => `${config.prefix}/asn-lookup?q=${encodeURIComponent('AS' + asn)}`;

/** Keep the heaviest nodes (origin always) and drop anything that no longer reaches the origin. */
function topSubset(nodes, edges, origin) {
  if (nodes.length <= TOP_NODES) return { nodes, edges };
  const keep = new Set([origin.id, ...[...nodes].filter((n) => n.id !== origin.id).sort((a, b) => (b.paths || 0) - (a.paths || 0)).slice(0, TOP_NODES - 1).map((n) => n.id)]);
  return prune(nodes.filter((n) => keep.has(n.id)), edges.filter((e) => keep.has(e.from) && keep.has(e.to)), origin);
}

/** Remove nodes with no remaining route to the origin. */
function prune(nodes, edges, origin) {
  const into = new Map();
  edges.forEach((e) => { if (!into.has(e.to)) into.set(e.to, []); into.get(e.to).push(e.from); });
  const ok = new Set([origin.id]), q = [origin.id];
  while (q.length) { for (const f of into.get(q.shift()) || []) if (!ok.has(f)) { ok.add(f); q.push(f); } }
  return { nodes: nodes.filter((n) => ok.has(n.id)), edges: edges.filter((e) => ok.has(e.from) && ok.has(e.to)) };
}

/**
 * pathGraph({ graph, pathsTotal }) -> figure element.
 * graph: {nodes:[{id,asn,name,role,tier1,depth,paths,share}], edges:[{from,to,count}]}
 */
export function pathGraph({ graph, pathsTotal } = {}) {
  const allNodes = (graph && graph.nodes) || [], allEdges = (graph && graph.edges) || [];
  const origin = allNodes.find((n) => n.role === 'origin') || allNodes.find((n) => !n.depth) || allNodes[0];
  if (!origin) return h('p', { class: 'text-sm text-mute' }, 'The path graph is not available for this prefix.');
  const isPeer = (n) => n.role === 'peer';
  const state = { all: allNodes.length <= TOP_NODES, hidePeers: false };

  const wrap = h('div', { class: 'pg-wrap', tabindex: '-1' });
  const tip = h('p', { class: 'text-sm min-h-[1.5rem] mt-2', 'aria-live': 'polite' }, 'Hover or focus a network to light up its routes to the origin. Click it to open its ASN report.');
  const listBox = h('div');

  function compute() {
    let nodes = allNodes, edges = allEdges;
    if (state.hidePeers) {
      nodes = nodes.filter((n) => !isPeer(n) || n.id === origin.id);
      const set = new Set(nodes.map((n) => n.id));
      edges = edges.filter((e) => set.has(e.from) && set.has(e.to));
    }
    ({ nodes, edges } = prune(nodes, edges, origin));
    if (!state.all) ({ nodes, edges } = topSubset(nodes, edges, origin));
    return { nodes, edges };
  }

  let lastW = 0;
  function draw() {
    const { nodes, edges } = compute();
    const maxD = Math.max(1, ...nodes.map((n) => n.depth || 0));
    const maxPaths = Math.max(1, ...nodes.map((n) => n.paths || 0)), maxCount = Math.max(1, ...edges.map((e) => e.count || 0));
    const cols = Array.from({ length: maxD + 1 }, () => []);
    nodes.forEach((n) => cols[Math.min(n.depth || 0, maxD)].push(n));
    // Spread the columns over the whole card: origin at the right edge (with padding), never narrower than MINCOL per column
    // (then the card scrolls sideways, e.g. at 375px).
    const avail = Math.floor(wrap.clientWidth || lastW || 760);
    const W = Math.max(avail, PADL + PADR + maxD * MINCOL), colw = maxD ? (W - PADL - PADR) / maxD : 0;
    const x = (d) => (maxD ? W - PADR - d * colw : W / 2);
    const radius = (n) => (n.id === origin.id ? 20 : 5 + 9 * Math.sqrt((n.paths || 0) / maxPaths));
    const rows = Math.max(...cols.map((c) => c.length), 1), H = PADT + rows * ROW + 16;
    const pos = new Map();
    // Column 0 (origin) centred; the other columns are ordered by the weighted y of the nodes they feed, which untangles most edges.
    const place = (list, d) => list.forEach((n, i) => pos.set(n.id, [x(d), PADT + (H - PADT - 16) / 2 + (i - (list.length - 1) / 2) * ROW]));
    place(cols[0], 0);
    for (let d = 1; d <= maxD; d++) {
      const bary = (n) => { let s = 0, w = 0; edges.forEach((e) => { if (e.from === n.id && pos.has(e.to)) { s += (e.count || 1) * pos.get(e.to)[1]; w += e.count || 1; } }); return w ? s / w : H / 2; };
      cols[d].sort((a, b) => bary(a) - bary(b) || (b.paths || 0) - (a.paths || 0));
      place(cols[d], d);
    }

    const out = new Map();
    edges.forEach((e) => { (out.get(e.from) || out.set(e.from, []).get(e.from)).push(e); });
    const edgeEls = new Map(), nodeEls = new Map();
    const gEdges = svg('g'), gNodes = svg('g'), gHead = svg('g');

    edges.forEach((e) => {
      const a = pos.get(e.from), b = pos.get(e.to), na = nodes.find((n) => n.id === e.from), nb = nodes.find((n) => n.id === e.to);
      if (!a || !b) return;
      const x1 = a[0] + radius(na), x2 = b[0] - radius(nb), mx = (x1 + x2) / 2;
      const p = svg('path', { class: 'pg-edge', d: `M${x1.toFixed(1)} ${a[1].toFixed(1)} C${mx.toFixed(1)} ${a[1].toFixed(1)} ${mx.toFixed(1)} ${b[1].toFixed(1)} ${x2.toFixed(1)} ${b[1].toFixed(1)}`, 'stroke-width': (1.2 + 6 * Math.sqrt((e.count || 0) / maxCount)).toFixed(1) },
        svg('title', null, `AS${na.asn} to AS${nb.asn}: ${plural(e.count || 0, 'path')}`));
      edgeEls.set(e, p); gEdges.append(p);
    });

    function light(n) {
      const seenN = new Set([n.id]), seenE = new Set(), q = [n.id];
      while (q.length) for (const e of out.get(q.shift()) || []) { seenE.add(e); if (!seenN.has(e.to)) { seenN.add(e.to); q.push(e.to); } }
      edgeEls.forEach((el, e) => { el.classList.toggle('pg-hi', seenE.has(e)); el.classList.toggle('pg-dim', !seenE.has(e)); });
      nodeEls.forEach((el, id) => { el.classList.toggle('pg-hi', seenN.has(id)); el.classList.toggle('pg-dim', !seenN.has(id)); });
    }
    function unlight() { edgeEls.forEach((el) => el.classList.remove('pg-hi', 'pg-dim')); nodeEls.forEach((el) => el.classList.remove('pg-hi', 'pg-dim')); }

    nodes.forEach((n) => {
      const [cx, cy] = pos.get(n.id), r = radius(n), role = n.id === origin.id ? 'origin' : (n.role in FILL ? n.role : 'transit');
      const label = `AS${n.asn}${n.name ? ' ' + n.name : ''}`;
      const sum = `${ROLE_WORD[role]}: ${label}. ${plural(n.paths || 0, 'path')}${n.share != null ? ` (${Math.round(n.share * 100)}% of paths)` : ''}${n.tier1 ? '. Tier-1 network' : ''}`;
      const a = svg('a', { class: 'pg-node', href: asnHref(n.asn), 'aria-label': `${sum}. Open ASN report`, target: isEmbed() ? '_blank' : null, rel: isEmbed() ? 'noopener' : null },
        svg('circle', { class: 'pg-c', cx: cx.toFixed(1), cy: cy.toFixed(1), r: r.toFixed(1), fill: FILL[role], stroke: role === 'peer' ? 'var(--mute)' : null, 'stroke-dasharray': role === 'peer' ? '3 2' : null }),
        role === 'origin' ? svg('text', { x: cx, y: cy + 3.5, 'text-anchor': 'middle', 'font-size': 10, 'font-weight': 700, fill: 'var(--bg)', 'pointer-events': 'none' }, 'ORIGIN') : null,
        svg('text', { class: 'pg-label', x: cx, y: cy + r + 12, 'text-anchor': 'middle' }, trunc(`AS${n.asn} ${n.name || ''}`.trim(), 22)),
        n.tier1 ? svg('g', { class: 'pg-t1', 'data-lx': cx.toFixed(1), 'data-ly': (cy + r + 12).toFixed(1), 'data-ch': String(Math.min(LABEL_CH, `AS${n.asn} ${n.name || ''}`.trim().length)), transform: `translate(${(cx + Math.min(LABEL_CH, `AS${n.asn} ${n.name || ''}`.trim().length) * 3 + 4).toFixed(1)} ${(cy + r + 3).toFixed(1)})` }, svg('rect', { width: 20, height: 11, rx: 5.5 }), svg('text', { x: 10, y: 8.3, 'text-anchor': 'middle' }, 'T1')) : null,
        svg('title', null, sum));
      const show = () => { light(n); tip.textContent = sum + '.'; };
      a.addEventListener('mouseenter', show); a.addEventListener('focus', show);
      a.addEventListener('mouseleave', unlight); a.addEventListener('blur', unlight);
      nodeEls.set(n.id, a); gNodes.append(a);
    });

    const headWord = (d) => (d === 0 ? 'ORIGIN' : d === 1 ? 'UPSTREAMS' : `${d} HOPS OUT`);
    for (let d = 0; d <= maxD; d++) if (cols[d].length) gHead.append(svg('text', { class: 'pg-head', x: x(d), y: 16, 'text-anchor': 'middle' }, headWord(d)));

    wrap.replaceChildren(svg('svg', { viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: 'group', 'aria-label': `Graph of ${nodes.length} networks between route collectors and AS${origin.asn}. The same information is in the list below.` }, gHead, gEdges, gNodes));
    lastW = wrap.clientWidth || lastW;
    // Seat each Tier-1 badge right after its label (measured when the text is laid out, estimated otherwise).
    wrap.querySelectorAll('.pg-t1').forEach((g) => {
      const t = g.parentNode.querySelector('.pg-label'); let len = 0;
      try { len = t.getComputedTextLength(); } catch { len = 0; }
      if (len > 0) g.setAttribute('transform', `translate(${(Number(g.dataset.lx) + len / 2 + 4).toFixed(1)} ${(Number(g.dataset.ly) - 9.5).toFixed(1)})`);
    });

    // Text equivalent: every link towards the origin, strongest first.
    const byId = new Map(nodes.map((n) => [n.id, n]));
    const lines = [...edges].sort((a, b) => (b.count || 0) - (a.count || 0)).map((e) => h('li', null, `AS${byId.get(e.from)?.asn} → AS${byId.get(e.to)?.asn}`, h('span', { class: 'text-mute' }, ` (${plural(e.count || 0, 'path')})`)));
    listBox.replaceChildren(h('details', { class: 'mt-3' },
      h('summary', { class: 'text-sm font-semibold text-mute' }, `Show the graph as a list (${plural(nodes.length, 'network')}, ${plural(edges.length, 'link')})`),
      h('ul', { class: 'text-sm columns-1 sm:columns-2 list-none m-0 p-0 mt-2 space-y-0.5' }, lines)),
    srOnly(`Graph with ${plural(nodes.length, 'network')} and ${plural(edges.length, 'link')} leading to AS${origin.asn}${pathsTotal ? `, built from ${plural(pathsTotal, 'path')}` : ''}.`));
    foot.textContent = nodes.length < allNodes.length ? `Showing ${nodes.length} of ${allNodes.length} networks.` : `Showing all ${nodes.length} networks.`;
  }

  // Controls
  const foot = h('span', { class: 'text-xs text-mute', role: 'status', 'aria-live': 'polite' });
  const bTop = h('button', { type: 'button', 'aria-pressed': 'false' }, 'Top paths'), bAll = h('button', { type: 'button', 'aria-pressed': 'false' }, 'All paths');
  const sync = () => { bTop.setAttribute('aria-pressed', String(!state.all)); bAll.setAttribute('aria-pressed', String(state.all)); };
  bTop.addEventListener('click', () => { state.all = false; sync(); draw(); });
  bAll.addEventListener('click', () => { state.all = true; sync(); draw(); });
  const hide = h('input', { type: 'checkbox', id: 'pg-hide-' + Math.random().toString(36).slice(2, 7) });
  hide.addEventListener('change', () => { state.hidePeers = hide.checked; draw(); });
  const hasPeers = allNodes.some(isPeer), canTrim = allNodes.length > TOP_NODES;
  sync();

  const legendItem = (role, text, dashed) => h('li', { class: 'inline-flex items-center gap-1.5' },
    h('span', { class: 'inline-block w-3 h-3 rounded-full', style: `background:${FILL[role]};${dashed ? 'border:1.5px dashed var(--mute)' : ''}`, 'aria-hidden': 'true' }), text);

  const fig = h('figure', { class: 'm-0' },
    h('div', { class: 'flex flex-wrap items-center gap-x-4 gap-y-2 mb-2' },
      canTrim ? h('div', { class: 'seg', role: 'group', 'aria-label': 'How many paths to draw' }, bTop, bAll) : null,
      hasPeers ? h('label', { class: 'inline-flex items-center gap-1.5 text-sm cursor-pointer' }, hide, 'Hide collector peers') : null,
      foot),
    wrap, tip,
    h('ul', { class: 'flex flex-wrap gap-x-4 gap-y-1 text-xs list-none m-0 p-0 mt-2' },
      legendItem('origin', 'Origin (announces the prefix)'), legendItem('upstream', 'Upstream (next to the origin)'), legendItem('transit', 'Transit'), legendItem('peer', 'Collector peer', true),
      h('li', { class: 'inline-flex items-center gap-1.5' }, h('span', { class: 'pill pill-info' }, 'T1'), 'Tier-1 network'),
      h('li', { class: 'text-mute' }, 'Bigger circle = more paths through it. Thicker line = more paths use that link.')),
    listBox);
  draw();
  // The card has no width until it is on the page, and it changes with the window: redraw when it moves by more than a few px.
  if (typeof ResizeObserver === 'function') {
    let raf = 0;
    new ResizeObserver(() => {
      const w = wrap.clientWidth;
      if (!w || Math.abs(w - lastW) < 12) return;
      cancelAnimationFrame(raf); raf = requestAnimationFrame(() => { if (wrap.isConnected) draw(); });
    }).observe(wrap);
  }
  return fig;
}
