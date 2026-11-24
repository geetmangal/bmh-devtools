// Small data table used inside "Technical details" panels. Cells may be strings, numbers or Nodes.
import { h } from './dom.js';

/** dataTable(['Resolver','Answer'], [[a, b], ...], { mono: [1] }) */
export function dataTable(headers, rows, { mono = [] } = {}) {
  return h('div', { class: 'overflow-x-auto' }, h('table', null,
    h('thead', null, h('tr', null, headers.map((x) => h('th', { scope: 'col' }, x)))),
    h('tbody', null, rows.map((r) => h('tr', null, r.map((c, i) => h('td', { class: mono.includes(i) ? 'mono break-all' : '' }, c == null ? '' : c)))))));
}

/** keyValueTable([['Registrar', 'x'], ...]) - skips empty values. */
export function keyValueTable(pairs) {
  const rows = pairs.filter(([, v]) => v != null && v !== '' && !(Array.isArray(v) && !v.length));
  return h('div', { class: 'overflow-x-auto' }, h('table', null, h('tbody', null, rows.map(([k, v]) =>
    h('tr', null, h('th', { class: 'w-40 whitespace-nowrap', scope: 'row' }, k),
      h('td', { class: 'mono break-all' }, Array.isArray(v) ? v.flatMap((x, i) => (i ? [h('br'), String(x)] : [String(x)])) : v instanceof Node ? v : String(v)))))));
}
