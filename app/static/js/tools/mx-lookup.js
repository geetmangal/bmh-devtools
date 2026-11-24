import { h, srOnly, icon, plural } from '../ui/dom.js';
import { checkCard } from '../ui/card.js';
import { domainTool, findingCards, resultVerdict, stat } from '../ui/findings.js';

/** Priority ladder: MX host -> IPs -> reverse DNS, with a tick when the name and address match each other (FCrDNS). */
function ladder(rows) {
  const groups = new Map();
  rows.forEach((r) => { const k = r.priority; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(r); });
  return h('ol', { class: 'list-none m-0 p-0 space-y-3' }, [...groups.entries()].sort((a, b) => a[0] - b[0]).map(([prio, list], gi) =>
    h('li', { class: 'flex gap-3' },
      h('div', { class: 'flex-none w-16 text-center rounded-lg border border-line py-2' }, h('div', { class: 'text-xs text-mute' }, gi === 0 ? 'tried first' : 'backup'), h('div', { class: 'text-xl font-bold mono' }, String(prio))),
      h('div', { class: 'min-w-0 flex-1 space-y-2' }, list.map((r) => h('div', { class: 'rounded-lg border border-line p-2.5' },
        h('div', { class: 'flex flex-wrap items-center gap-2' }, h('span', { class: 'font-semibold mono break-all' }, r.host),
          r.provider ? h('span', { class: 'pill pill-info' }, r.provider) : null, r.cname ? h('span', { class: 'pill pill-warn' }, `CNAME to ${r.cname}`) : null),
        (r.addresses || []).length ? h('ul', { class: 'list-none m-0 p-0 mt-1.5 space-y-1' }, r.addresses.map((a) => h('li', { class: 'text-sm flex flex-wrap items-center gap-x-2' },
          h('span', { class: 'text-mute', 'aria-hidden': 'true' }, '└'),
          h('span', { class: 'mono' }, a.ip), h('span', { class: 'text-xs text-mute' }, a.family === 6 || a.family === 'IPv6' ? 'IPv6' : 'IPv4'),
          h('span', { class: 'text-mute', 'aria-hidden': 'true' }, '→'),
          h('span', { class: 'mono text-xs break-all' }, (a.ptr || []).join(', ') || 'no reverse name'),
          h('span', { class: a.fcrdns ? 'st-ok inline-flex items-center gap-1 text-xs' : 'st-warn inline-flex items-center gap-1 text-xs' }, icon(a.fcrdns ? 'ok' : 'warn', 12), a.fcrdns ? 'names match' : 'names do not match')))) : h('div', { class: 'text-xs st-bad mt-1' }, 'This host has no IP address.'))))))),
  );
}

function render(res) {
  const d = res.data || {};
  const rows = d.ladder || [];
  const out = [resultVerdict(res)];
  if (rows.length) {
    out.push(h('div', { class: 'flex flex-wrap gap-2' }, stat('Mail servers', String(rows.length)), stat('Provider', d.provider || 'Self-hosted or unknown')));
    out.push(checkCard({ status: 'info', title: `${plural(rows.length, 'mail server')} receive mail for ${res.target}`, body: ladder(rows),
      meaning: 'Senders try the lowest priority number first and fall back to higher numbers if it is down. Each host should have an IP address, and that address should point back to the same name (a forward-confirmed reverse DNS match), which many receivers check.',
      details: d.providers }));
    out.push(srOnly(rows.map((r) => `Priority ${r.priority}: ${r.host}`).join('; ')));
  }
  out.push(...findingCards(res.findings));
  return out;
}

domainTool({ endpoint: '/mail/mx', render });
