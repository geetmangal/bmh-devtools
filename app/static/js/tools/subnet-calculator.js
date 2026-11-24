import { h, $, clear, icon } from '../ui/dom.js';
import { initTool, qParam } from '../ui/tool.js';
import { verdict } from '../ui/verdict.js';
import { checkCard } from '../ui/card.js';
import { addrBar, splitDiagram } from '../ui/addrbar.js';
import { keyValueTable } from '../ui/table.js';

const esc = (s) => String(s);
const fmtInt = (s) => (s.length > 15 ? s : Number(s).toLocaleString('en-US'));

// ---------- parsing ----------
function parseV4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  if (o.some((x) => x > 255)) return null;
  return BigInt(((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3]);
}
function parseV6(s) {
  if (!/^[0-9a-fA-F:.]+$/.test(s) || s.split('::').length > 2) return null;
  let [head, tail] = s.includes('::') ? s.split('::') : [s, null];
  let h = head ? head.split(':') : [], t = tail ? tail.split(':') : [];
  // embedded IPv4 in last group
  const fix = (arr) => { if (arr.length && arr[arr.length - 1].includes('.')) { const v = parseV4(arr.pop()); if (v === null) throw 0; arr.push((Number(v >> 16n)).toString(16), (Number(v & 0xffffn)).toString(16)); } return arr; };
  try { h = fix(h); t = fix(t); } catch { return null; }
  const groups = tail === null ? h : [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-fA-F]{1,4}$/.test(g))) return null;
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g, 16)), 0n);
}
const fmtV4 = (n) => [24, 16, 8, 0].map((s) => Number((n >> BigInt(s)) & 255n)).join('.');
function fmtV6(n) {
  const g = []; for (let i = 7; i >= 0; i--) g.push(Number((n >> BigInt(i * 16)) & 0xffffn));
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8;) { if (g[i] !== 0) { i++; continue; } let j = i; while (j < 8 && g[j] === 0) j++; if (j - i > bestLen && j - i > 1) { best = i; bestLen = j - i; } i = j; }
  const hex = g.map((x) => x.toString(16));
  if (best < 0) return hex.join(':');
  return (hex.slice(0, best).join(':') || '') + '::' + (hex.slice(best + bestLen).join(':') || '');
}
const expV6 = (n) => { const g = []; for (let i = 7; i >= 0; i--) g.push(Number((n >> BigInt(i * 16)) & 0xffffn).toString(16).padStart(4, '0')); return g.join(':'); };
const binV4 = (n) => fmtV4(n).split('.').map((o) => Number(o).toString(2).padStart(8, '0')).join('.');
const binV6 = (n) => expV6(n).split(':').map((h) => parseInt(h, 16).toString(2).padStart(16, '0')).join(':');
const inNet = (n, netStr) => { const [a, p] = netStr.split('/'); const base = a.includes(':') ? parseV6(a) : parseV4(a); const bits = a.includes(':') ? 128 : 32; const mask = ((1n << BigInt(bits)) - 1n) ^ ((1n << BigInt(bits - +p)) - 1n); return (n & mask) === (base & mask); };

function calc(input) {
  input = input.trim();
  let [addr, pfx] = input.split('/');
  const v6 = addr.includes(':');
  const bits = v6 ? 128 : 32;
  const ip = v6 ? parseV6(addr) : parseV4(addr);
  if (ip === null) throw new Error('Invalid ' + (v6 ? 'IPv6' : 'IPv4') + ' address');
  const prefix = pfx === undefined ? bits : Number(pfx);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) throw new Error('Prefix must be 0-' + bits);
  const all = (1n << BigInt(bits)) - 1n;
  const mask = prefix === 0 ? 0n : (all ^ ((1n << BigInt(bits - prefix)) - 1n));
  const net = ip & mask, bcast = net | (all ^ mask);
  const total = 1n << BigInt(bits - prefix);
  const fmt = v6 ? fmtV6 : fmtV4;
  let first, last, usable;
  if (v6) { usable = prefix >= 127 ? total : total - 1n; first = prefix >= 127 ? net : net + 1n; last = bcast; }
  else { usable = prefix >= 31 ? total : total - 2n; first = prefix >= 31 ? net : net + 1n; last = prefix >= 31 ? bcast : bcast - 1n; }
  const r = {
    version: v6 ? 6 : 4, ip: fmt(ip), network: fmt(net), cidr: fmt(net) + '/' + prefix, prefix,
    netmask: fmt(mask), wildcard: fmt(all ^ mask), broadcast: v6 ? null : fmt(bcast),
    first_usable: fmt(first), last_usable: fmt(last), total_addresses: total.toString(), usable_hosts: usable.toString(),
    ip_binary: v6 ? binV6(ip) : binV4(ip), netmask_binary: v6 ? null : binV4(mask),
    ip_hex: '0x' + ip.toString(16).padStart(v6 ? 32 : 8, '0'), ip_integer: ip.toString(),
  };
  if (v6) {
    r.compressed = fmtV6(ip); r.exploded = expV6(ip);
    r.is_private = inNet(ip, 'fc00::/7'); r.is_loopback = ip === 1n; r.is_link_local = inNet(ip, 'fe80::/10'); r.is_multicast = inNet(ip, 'ff00::/8');
    r.is_global = inNet(ip, '2000::/3') && !inNet(ip, '2001:db8::/32');
    const nib = expV6(net).replace(/:/g, '').slice(0, Math.max(1, prefix >> 2));
    r.reverse_dns_zone = [...nib].reverse().join('.') + '.ip6.arpa';
  } else {
    const f = Number(ip >> 24n);
    r.class = f < 128 ? 'A' : f < 192 ? 'B' : f < 224 ? 'C' : f < 240 ? 'D (multicast)' : 'E (reserved)';
    r.is_private = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'].some((n) => inNet(ip, n));
    r.is_loopback = inNet(ip, '127.0.0.0/8'); r.is_link_local = inNet(ip, '169.254.0.0/16'); r.is_multicast = inNet(ip, '224.0.0.0/4');
    r.is_global = !r.is_private && !r.is_loopback && !r.is_link_local && !r.is_multicast && !['0.0.0.0/8', '100.64.0.0/10', '192.0.2.0/24', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '240.0.0.0/4'].some((n) => inNet(ip, n));
    const oct = fmtV4(net).split('.').slice(0, Math.max(1, prefix >> 3));
    r.reverse_dns_zone = oct.reverse().join('.') + '.in-addr.arpa';
  }
  r._raw = { net, mask, bits, prefix, fmt };
  return r;
}


const cidrEl = $('#sn-cidr');
let lastRaw = null;

const LABELS = [['cidr', 'CIDR'], ['ip', 'Address'], ['network', 'Network'], ['broadcast', 'Broadcast'], ['first_usable', 'First usable'], ['last_usable', 'Last usable'],
  ['usable_hosts', 'Usable hosts'], ['total_addresses', 'Total addresses'], ['netmask', 'Netmask'], ['wildcard', 'Wildcard mask'], ['class', 'Class'],
  ['is_private', 'Private'], ['is_global', 'Public (global)'], ['is_loopback', 'Loopback'], ['is_link_local', 'Link-local'], ['is_multicast', 'Multicast'],
  ['reverse_dns_zone', 'Reverse DNS zone'], ['compressed', 'Compressed'], ['exploded', 'Exploded'], ['ip_binary', 'Address (binary)'], ['netmask_binary', 'Netmask (binary)'], ['ip_hex', 'Hex'], ['ip_integer', 'Integer']];

function kind(r) {
  if (r.is_loopback) return ['Loopback', 'Addresses that point back to the machine itself; they never leave it.'];
  if (r.is_link_local) return ['Link-local', 'Only valid on the local network segment; routers do not forward it. Often self-assigned when DHCP fails.'];
  if (r.is_multicast) return ['Multicast', 'Addresses used to send one packet to a group of receivers.'];
  if (r.is_private) return ['Private', 'Reserved for use inside a network (offices, VPCs, home). It is not routed on the public internet; you need NAT to reach the internet.'];
  if (r.is_global) return ['Public (global)', 'Routable on the internet. Only the organisation it was allocated to may announce it.'];
  return ['Reserved or special use', 'This range is set aside for documentation, testing or another special purpose and is not normal public space.'];
}

function render(r) {
  const [kName, kMean] = kind(r);
  const hostAddr = r.ip !== r.network;
  const out = [verdict({
    status: 'ok', title: r.cidr,
    summary: `${fmtInt(r.total_addresses)} addresses in total, ${fmtInt(r.usable_hosts)} usable for hosts, from ${r.first_usable} to ${r.last_usable}${r.version === 4 && r.prefix < 31 ? '' : ''}.`,
    meta: `${kName} ${r.version === 6 ? 'IPv6' : 'IPv4'} range`,
  })];
  out.push(checkCard({ status: 'info', title: 'Address range',
    body: addrBar({ network: r.network, first: r.first_usable, last: r.last_usable, broadcast: r.broadcast, total: fmtInt(r.total_addresses), usable: fmtInt(r.usable_hosts), prefix: r.prefix, bits: r.version === 6 ? 128 : 32 }),
    meaning: r.version === 4
      ? `A /${r.prefix} keeps ${r.prefix} bits for the network and leaves ${32 - r.prefix} for hosts. ${r.prefix < 31 ? 'The first address names the network and the last is the broadcast address, so neither can be given to a host.' : 'Point-to-point /31 links and single /32 hosts use every address.'}`
      : `A /${r.prefix} keeps ${r.prefix} bits for the network and leaves ${128 - r.prefix} for hosts. IPv6 has no broadcast address.`,
    details: keyValueTable(LABELS.filter(([k]) => r[k] !== null && r[k] !== undefined).map(([k, l]) => [l, typeof r[k] === 'boolean' ? (r[k] ? 'yes' : 'no') : r[k]])) }));
  if (hostAddr) {
    out.push(checkCard({ status: 'info', title: `${r.ip} is a host address inside ${r.cidr}`,
      meaning: `You typed a specific host. The subnet it belongs to starts at ${r.network}; that is the address you would put in a routing table or firewall rule as ${r.cidr}.` }));
  }
  out.push(checkCard({ status: 'info', title: `${kName} address space`, meaning: kMean }));
  if (r.version === 4) {
    out.push(checkCard({ status: 'info', title: `Netmask ${r.netmask}, wildcard ${r.wildcard}`,
      meaning: 'The netmask marks which bits are the network part. The wildcard is its inverse, used in Cisco-style access lists and OSPF statements.',
      details: keyValueTable([['Netmask (binary)', r.netmask_binary], ['Address (binary)', r.ip_binary], ['Class', r.class], ['Reverse DNS zone', r.reverse_dns_zone]]) }));
  } else {
    out.push(checkCard({ status: 'info', title: `Reverse DNS zone: ${r.reverse_dns_zone}`, meaning: 'PTR records for addresses in this prefix are published in this zone, usually by whoever owns the block.' }));
  }
  return out;
}

const tool = initTool({
  form: '#sn-form',
  run() {
    const c = calc(cidrEl.value);
    lastRaw = c._raw;
    const { _raw, ...pub } = c;
    return pub;
  },
  render,
  state: () => ({ q: cidrEl.value.trim() }),
  prefill: (p) => { const q = qParam(p, 'cidr'); if (q) cidrEl.value = q; return true; },
});
cidrEl.addEventListener('input', () => tool.execute());

// ---------- split ----------
$('#sn-split-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const out = $('#sn-split'); clear(out);
  try {
    const r = calc(cidrEl.value);
    const np = Number($('#sn-newprefix').value), { net, bits, prefix, fmt } = r._raw;
    if (!Number.isInteger(np) || np <= prefix || np > bits) throw new Error(`New prefix must be between ${prefix + 1} and ${bits}.`);
    const count = 1n << BigInt(np - prefix);
    if (count > 1024n) throw new Error(`That makes ${count} subnets; the cap is 1024. Choose a shorter prefix.`);
    const size = 1n << BigInt(bits - np), subs = [];
    for (let i = 0n; i < count; i++) { const a = net + i * size; subs.push([`${fmt(a)}/${np}`, `${fmt(a)} - ${fmt(a + size - 1n)}`]); }
    out.append(splitDiagram({ parent: fmt(net), parentPrefix: prefix, newPrefix: np, count: String(count), sample: subs.map((s) => s[0]) }),
      h('div', { class: 'mt-3 max-h-72 overflow-auto mono text-sm' }, subs.map((s) => h('div', null, s[0], ' ', h('span', { class: 'text-mute' }, s[1])))));
  } catch (err) { out.append(h('p', { class: 'st-bad flex items-center gap-1.5', role: 'alert' }, icon('bad', 14), err.message)); }
});

// ---------- summarise ----------
$('#sn-sum-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const out = $('#sn-sum'); clear(out);
  try {
    const nets = $('#sn-sum-input').value.split(/\s+/).filter(Boolean).map((c) => calc(c)._raw);
    if (!nets.length) throw new Error('Enter at least one CIDR.');
    if (new Set(nets.map((n) => n.bits)).size > 1) throw new Error('Do not mix IPv4 and IPv6.');
    const { bits, fmt } = nets[0];
    const lo = nets.reduce((m, n) => (n.net < m ? n.net : m), nets[0].net);
    const hi = nets.reduce((m, n) => { const b = n.net + (1n << BigInt(bits - n.prefix)) - 1n; return b > m ? b : m; }, 0n);
    let p = Math.min(...nets.map((n) => n.prefix));
    const all = (1n << BigInt(bits)) - 1n;
    const maskOf = (pp) => (pp === 0 ? 0n : all ^ ((1n << BigInt(bits - pp)) - 1n));
    while (p > 0 && ((lo & maskOf(p)) !== (hi & maskOf(p)))) p--;
    const exact = []; let cur = lo;
    while (cur <= hi) {
      let pp = bits;
      while (pp > 0) { const m = maskOf(pp - 1); if ((cur & m) !== cur) break; if (cur + (1n << BigInt(bits - pp + 1)) - 1n > hi) break; pp--; }
      exact.push(fmt(cur) + '/' + pp); cur += 1n << BigInt(bits - pp); if (cur === 0n) break;
    }
    out.append(h('div', null, h('span', { class: 'text-mute' }, 'Single covering supernet: '), h('span', { class: 'st-ok font-semibold' }, `${fmt(lo & maskOf(p))}/${p}`)),
      h('div', { class: 'mt-2' }, h('span', { class: 'text-mute' }, `Exact summary of ${fmt(lo)} - ${fmt(hi)}:`), ...exact.flatMap((x) => [h('br'), x])));
  } catch (err) { out.append(h('span', { class: 'st-bad', role: 'alert' }, err.message)); }
});
