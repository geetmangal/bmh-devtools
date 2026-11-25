import { h } from '../ui/dom.js';
import { initTool, config } from '../ui/tool.js';
import { verdict } from '../ui/verdict.js';
import { codeBlock, checkCard } from '../ui/card.js';
import { stat } from '../ui/findings.js';

// What is my IP: no input. GET /ports/myip gives the address our server sees, then the light PTR lookup and the
// registry whois of that address fill in prefix, origin AS and holder. Runs through initTool (bmh:result event).

const first = (groups, ...keys) => {
  for (const k of keys) for (const g of groups || []) for (const kv of g) if (String(kv.key).toLowerCase() === k && kv.value) return String(kv.value);
  return null;
};

/** Pull prefix, netname, holder and origin AS out of the registry records returned by GET /prefix-whois. */
export function summarise(w) {
  if (!w) return null;
  const recs = w.records || [], irr = w.irr_records || [];
  const origin = first(irr, 'origin') || first(recs, 'origin');
  return {
    prefix: first(irr, 'route', 'route6') || first(recs, 'cidr', 'inetnum', 'inet6num', 'route', 'route6'),
    netname: first(recs, 'netname'),
    holder: first(recs, 'orgname', 'org-name', 'owner', 'organization', 'descr'),
    asn: origin ? origin.toUpperCase().replace(/^(?!AS)/, 'AS') : null,
    country: first(recs, 'country'),
    abuse: w.abuse_email || null,
  };
}

const reason = (r) => (r.status === 'rejected' ? (r.reason && r.reason.message) || 'unavailable' : null);

async function run(ctx) {
  const me = await ctx.api('/ports/myip', null);
  const ip = String(me.ip || '').trim();
  const out = { ip, public: !!me.public, version: ip.includes(':') ? 6 : 4, ptr: null, whois: null, notes: [] };
  if (!ip || !out.public) return out;
  const [ptr, who] = await Promise.allSettled([
    ctx.api('/rdns/lookup', { ip }),
    ctx.api(`/prefix-whois/${encodeURIComponent(ip)}`, null),
  ]);
  if (ptr.status === 'fulfilled') out.ptr = ptr.value; else out.notes.push(`Reverse DNS: ${reason(ptr)}`);
  if (who.status === 'fulfilled') out.whois = who.value; else out.notes.push(`Registry data: ${reason(who)}`);
  document.getElementById('tool-ip').value = ip; // carried into the bmh:result event by the shared runner
  return out;
}

const linkTo = (slug, text, ip) => h('a', { href: `${config.prefix}/${slug}${slug === 'port-checker' ? '' : '?q=' + encodeURIComponent(ip)}`, class: 'chip' }, text);

function render(d) {
  if (!d.ip) return [verdict({ status: 'warn', title: 'Address not detected', summary: 'We could not read your IP address from this connection. Reload the page to try again.' })];
  if (!d.public) {
    return [verdict({ status: 'warn', title: 'Not a public address', summary: `${d.ip} is a private or reserved address, so it cannot be looked up. This usually means a proxy or test setup sits in front of this page.`, meta: d.ip })];
  }
  const s = summarise(d.whois);
  const ptr = d.ptr && d.ptr.ptr && d.ptr.ptr[0] ? d.ptr.ptr[0].hostname : null;
  const out = [
    verdict({ status: 'info', title: `Your IPv${d.version} address`, summary: 'This is the address other servers see when you connect to them from this device.', meta: d.ip }),
    h('div', null, h('div', { class: 'text-xs text-mute mb-1' }, 'Your public IP address'), codeBlock(d.ip, 'Copy IP')),
    h('div', { class: 'flex flex-wrap gap-2' },
      stat('Type', `IPv${d.version}`, d.version === 6 ? '128-bit address' : '32-bit address'),
      stat('Reverse DNS (PTR)', ptr || 'none', d.ptr ? (d.ptr.fcrdns ? 'forward-confirmed' : null) : 'not available'),
      stat('Prefix', (s && s.prefix) || 'n/a', s && s.netname ? s.netname : 'from registry data'),
      stat('Origin AS', (s && s.asn) || 'n/a', (s && s.holder) || 'holder not listed')),
  ];
  const rows = [['IP address', d.ip], ['IP version', `IPv${d.version}`], ['PTR', ptr || 'none'], ['Prefix', s && s.prefix], ['Origin AS', s && s.asn], ['Holder', s && s.holder], ['Country', s && s.country]].filter((r) => r[1]);
  out.push(checkCard({ status: 'info', title: 'Network details', body: h('dl', { class: 'grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm' }, rows.flatMap(([k, v]) => [h('dt', { class: 'text-mute' }, k), h('dd', { class: 'mono break-all' }, v)])),
    meaning: 'Prefix, origin AS and holder come from public registry records, not from live BGP. A blank value means the registry did not list one. Use the BGP prefix lookup for the live route.' }));
  if (d.notes.length) out.push(h('p', { class: 'text-sm text-mute', role: 'status' }, d.notes.join(' ')));
  out.push(h('div', { class: 'card-flat px-3 py-2 text-sm no-print' }, h('span', { class: 'text-mute' }, 'Check this address: '),
    h('span', { class: 'inline-flex flex-wrap gap-2 align-middle' }, linkTo('port-checker', 'Open ports', d.ip), linkTo('blacklist-check', 'Blacklist check', d.ip), linkTo('bgp-prefix-lookup', 'BGP prefix', d.ip), linkTo('whois-lookup', 'WHOIS', d.ip))));
  return out;
}

initTool({ form: '#tool-form', run, render, prefill: () => true });
