// bgp.tools-style AS graph in pure SVG: upstreams in a column on the left, the target in the centre, downstreams
// on the right and peers on an arc below the target. Node size follows the neighbour's "power" (how many route
// collector peers see the link). Hover shows name and ASN, click opens that ASN, keyboard Enter/Space too.
// A list of the same neighbours is always available below the picture (and for screen readers).
import { h, svg, srOnly } from '../ui/dom.js';

const W = 900, MAX_PER_GROUP = 14, MAX_PEERS = 9;
const COL = { upstream: 'var(--accent)', downstream: 'var(--ok)', peer: 'var(--mute)', target: 'var(--ink)' };
const WORD = { upstream: 'Upstream', downstream: 'Downstream', peer: 'Peer / unclear', target: 'This AS' };

const trunc = (s, n) => (s && s.length > n ? s.slice(0, n - 1) + '…' : s || '');

/** asGraph({ graph: {nodes, edges}, onPivot(asn) }) - graph is the API's `graph` object. */
export function asGraph({ graph, onPivot } = {}) {
  const nodes = graph.nodes || [], edges = graph.edges || [];
  const target = nodes.find((n) => n.role === 'target') || nodes[0];
  const group = (role) => nodes.filter((n) => n.role === role).sort((a, b) => (b.power || 0) - (a.power || 0));
  const up = group('upstream'), down = group('downstream'), peers = group('peer');
  const shown = { upstream: up.slice(0, MAX_PER_GROUP), downstream: down.slice(0, MAX_PER_GROUP), peer: peers.slice(0, MAX_PEERS) };
  const maxPower = Math.max(1, ...nodes.map((n) => n.power || 0));
  const radius = (n) => (n.role === 'target' ? 26 : 8 + 14 * Math.sqrt((n.power || 0) / maxPower));

  const ROW = 40, colRows = Math.max(shown.upstream.length, shown.downstream.length, 1);
  const colH = colRows * ROW + 40, cx = W / 2;
  const cy = Math.max(colH / 2, 90);
  const R = 150, arcH = shown.peer.length ? R + 90 : 0;
  const H = Math.max(colH, cy + 40 + arcH);

  const pos = new Map();
  pos.set(target.id, [cx, cy]);
  const column = (list, x) => list.forEach((n, i) => pos.set(n.id, [x, cy + (i - (list.length - 1) / 2) * ROW]));
  column(shown.upstream, 150); column(shown.downstream, W - 150);
  shown.peer.forEach((n, i) => {
    const k = shown.peer.length, a = k === 1 ? Math.PI / 2 : (Math.PI * (0.18 + (0.64 * i) / (k - 1)));
    pos.set(n.id, [cx + Math.cos(a) * R * 1.55, cy + 55 + Math.sin(a) * R]);
  });

  const tip = h('div', { class: 'text-sm min-h-[1.5rem] mt-1', 'aria-live': 'polite' }, 'Hover or focus a network to see its name. Click to open it.');
  const pivot = (n) => { if (onPivot) onPivot(n.asn); else location.search = '?q=' + encodeURIComponent('AS' + n.asn); };

  const edgeEls = edges.map((e) => {
    const a = pos.get(e.source), b = pos.get(e.target);
    if (!a || !b) return null;
    const w = 1 + 2.5 * Math.sqrt((e.power || 0) / maxPower);
    return svg('line', { x1: a[0], y1: a[1], x2: b[0], y2: b[1], stroke: 'var(--line)', 'stroke-width': w.toFixed(1), 'stroke-dasharray': e.type === 'peer' ? '5 4' : null });
  });

  const nodeEls = Object.entries(shown).flatMap(([role, list]) => list).concat([target]).map((n) => {
    const [x, y] = pos.get(n.id), r = radius(n), role = n.role;
    const label = `AS${n.asn}${n.name ? ' ' + n.name : ''}`;
    const left = role === 'upstream', right = role === 'downstream', isTarget = role === 'target';
    const g = svg('g', { tabindex: 0, role: 'link', 'aria-label': `${WORD[role]}: ${label}${isTarget ? '' : '. Open'}`, style: isTarget ? '' : 'cursor:pointer', class: 'asnode' },
      svg('circle', { cx: x, cy: y, r, fill: COL[role], opacity: isTarget ? 1 : 0.88, stroke: 'var(--surface)', 'stroke-width': 2 }),
      isTarget ? svg('text', { x, y: y + 4, 'text-anchor': 'middle', 'font-size': 11, 'font-weight': 700, fill: 'var(--bg)' }, 'AS' + n.asn) : null,
      isTarget ? svg('text', { x, y: y - r - 8, 'text-anchor': 'middle', 'font-size': 12, 'font-weight': 600, fill: 'var(--ink)' }, trunc(n.name, 34)) : null,
      !isTarget ? svg('text', { x: left ? x - r - 8 : right ? x + r + 8 : x, y: left || right ? y + 4 : y + r + 14 + ((shown.peer.indexOf(n) % 2) * 12), 'text-anchor': left ? 'end' : right ? 'start' : 'middle', 'font-size': 11, fill: 'var(--ink)' }, trunc(`AS${n.asn} ${n.name || ''}`.trim(), 26)) : null,
      svg('title', null, label));
    const show = () => { tip.textContent = `${WORD[role]}: ${label}${n.power ? ` (seen by ${n.power} route collector peers)` : ''}`; g.querySelector('circle').setAttribute('stroke', 'var(--accent)'); };
    const hide = () => { g.querySelector('circle').setAttribute('stroke', 'var(--surface)'); };
    g.addEventListener('mouseenter', show); g.addEventListener('focus', show); g.addEventListener('mouseleave', hide); g.addEventListener('blur', hide);
    if (!isTarget) {
      g.addEventListener('click', () => pivot(n));
      g.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); pivot(n); } });
    }
    return g;
  });

  const heads = [['Upstreams', 150, shown.upstream.length], ['Downstreams', W - 150, shown.downstream.length]].map(([t, x, k]) =>
    k ? svg('text', { x, y: 16, 'text-anchor': 'middle', 'font-size': 11, 'font-weight': 700, fill: 'var(--mute)' }, t.toUpperCase()) : null);
  if (shown.peer.length) heads.push(svg('text', { x: cx, y: H - 6, 'text-anchor': 'middle', 'font-size': 11, 'font-weight': 700, fill: 'var(--mute)' }, 'PEERS AND UNCLEAR NEIGHBOURS'));

  const li = (n) => h('li', null, h('a', { href: '?q=' + encodeURIComponent('AS' + n.asn) }, `AS${n.asn}`), n.name ? ' ' + n.name : '', n.power ? h('span', { class: 'text-mute' }, ` (power ${n.power})`) : null);
  const listBlock = (title, list, total) => (list.length ? h('div', null, h('h4', { class: 'font-semibold text-sm mb-1' }, `${title} (${total})`), h('ul', { class: 'text-sm columns-1 sm:columns-2 list-none m-0 p-0 space-y-0.5' }, list.map(li))) : null);

  const legend = h('ul', { class: 'flex flex-wrap gap-x-4 gap-y-1 text-xs list-none m-0 p-0 mt-2' }, ['upstream', 'target', 'downstream', 'peer'].map((r) =>
    h('li', { class: 'inline-flex items-center gap-1.5' }, h('span', { class: 'inline-block w-2.5 h-2.5 rounded-full', style: `background:${COL[r]}`, 'aria-hidden': 'true' }), WORD[r])),
    h('li', { class: 'text-mute' }, 'Bigger circle = seen by more collector peers. Dashed line = peering.'));

  const hidden = (up.length - shown.upstream.length) + (down.length - shown.downstream.length) + (peers.length - shown.peer.length);
  return h('figure', { class: 'm-0' },
    svg('svg', { viewBox: `0 0 ${W} ${H}`, width: '100%', role: 'group', 'aria-label': `AS graph of AS${target.asn}: ${up.length} upstream, ${down.length} downstream, ${peers.length} peer or unclear neighbours` },
      ...edgeEls, ...heads, ...nodeEls),
    tip, legend,
    h('details', { class: 'mt-3' }, h('summary', { class: 'text-sm font-semibold text-mute' }, 'Show the neighbours as a list'),
      h('div', { class: 'mt-2 grid gap-3' }, listBlock('Upstreams', up, up.length), listBlock('Downstreams', down, down.length), listBlock('Peers and unclear', peers, peers.length))),
    hidden > 0 ? h('p', { class: 'text-xs text-mute mt-1' }, `The picture shows the strongest neighbours (up to ${MAX_PER_GROUP} upstream or downstream, ${MAX_PEERS} peers); ${hidden} more are in the list.`) : null,
    srOnly(`Upstream networks: ${up.map((n) => 'AS' + n.asn).join(', ') || 'none'}. Downstream: ${down.map((n) => 'AS' + n.asn).join(', ') || 'none'}.`));
}
