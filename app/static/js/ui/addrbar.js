// IP range bar for the subnet calculator: network address | usable range | broadcast, plus a split diagram.
import { h, srOnly } from './dom.js';

/**
 * addrBar({ network, first, last, broadcast, total, usable, prefix, bits })
 * The bar is schematic (a /24 and a /8 look the same): it shows which parts of the block are reserved.
 */
export function addrBar({ network, first, last, broadcast, total, usable, prefix, bits }) {
  const hasBcast = !!broadcast && usable !== total;
  const seg = (cls, flex, top, bottom, title) => h('div', { class: `${cls} px-2 py-2 text-xs min-w-0 ${flex}`, title },
    h('div', { class: 'font-semibold truncate' }, top), h('div', { class: 'mono truncate' }, bottom));
  return h('div', null,
    h('div', { class: 'flex w-full overflow-hidden rounded-xl border border-line' },
      seg('bg-surface2', 'w-24 flex-none', 'Network', network, 'The first address names the subnet and is not given to a host'),
      seg('bg-accent text-white', 'flex-1', `${usable} usable`, `${first} to ${last}`, 'Addresses you can assign to hosts'),
      hasBcast ? seg('bg-surface2', 'w-24 flex-none', 'Broadcast', broadcast, 'The last address reaches every host on the subnet') : null),
    h('div', { class: 'mt-1 flex justify-between text-xs text-mute' }, h('span', null, `/${prefix} leaves ${bits - prefix} host bits`), h('span', null, `${total} addresses in total`)),
    srOnly(`Network ${network}. Usable range ${first} to ${last}, ${usable} hosts.${hasBcast ? ` Broadcast ${broadcast}.` : ''}`));
}

/** splitDiagram({ parent, parentPrefix, newPrefix, count, sample: [cidr...] }) - a block cut into equal parts. */
export function splitDiagram({ parent, parentPrefix, newPrefix, count, sample = [] }) {
  const shown = Math.min(Number(count), 64);
  const cells = Array.from({ length: shown }, (_, i) => h('div', { class: `h-8 flex-1 border-r border-surface ${i % 2 ? 'bg-accent' : 'bg-accent opacity-60'}`, title: sample[i] || '' }));
  return h('div', null,
    h('div', { class: 'flex w-full overflow-hidden rounded-lg border border-line', 'aria-hidden': 'true' }, cells),
    h('div', { class: 'mt-1 text-xs text-mute' }, `${parent}/${parentPrefix} cut into ${count} subnets of /${newPrefix}${Number(count) > shown ? ` (first ${shown} drawn)` : ''}`),
    srOnly(`${parent}/${parentPrefix} split into ${count} subnets of /${newPrefix}.`));
}
