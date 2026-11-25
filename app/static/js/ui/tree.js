// Indented tree with connector lines (certificate chain, SPF include tree). CSS lives in assets/tools.css (.tree).
import { h, icon, srOnly, statusOf } from './dom.js';

/** tree({ label, sub, status, children: [...] }) - each node may carry `badge` text. */
export function tree(root) {
  const node = (n) => h('li', null,
    h('div', { class: 'flex flex-wrap items-center gap-2' },
      n.status ? h('span', { class: statusOf(n.status).cls }, icon(n.status, 14)) : null,
      h('span', { class: 'font-medium mono text-sm break-all' }, n.label),
      n.badge ? h('span', { class: 'pill pill-mute' }, n.badge) : null),
    n.sub ? h('div', { class: 'text-xs text-mute ml-6 break-all' }, n.sub) : null,
    n.children && n.children.length ? h('ul', null, n.children.map(node)) : null);
  const flat = [];
  (function walk(n, d) { flat.push(`${'-'.repeat(d)}${n.label}${n.sub ? ` (${n.sub})` : ''}`); (n.children || []).forEach((c) => walk(c, d + 1)); })(root, 0);
  return h('div', { class: 'tree', role: 'tree' }, h('ul', null, node(root)), srOnly('Chain: ' + flat.join('; ')));
}
