import { h, plural, pill } from '../ui/dom.js';
import { checkCard } from '../ui/card.js';
import { dataTable, keyValueTable } from '../ui/table.js';
import { domainTool, findingCards, resultVerdict, stat } from '../ui/findings.js';

const TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'CAA', 'SOA'];
const human = (s) => {
  if (s == null) return '';
  if (s >= 86400 && s % 86400 === 0) return `${s / 86400} d`;
  if (s >= 3600 && s % 3600 === 0) return `${s / 3600} h`;
  if (s >= 60 && s % 60 === 0) return `${s / 60} min`;
  return `${s} s`;
};
const ttlChip = (s) => h('span', { class: `pill ${s < 300 ? 'pill-warn' : 'pill-info'} ml-2`, title: `${s} seconds` }, `TTL ${human(s)}`);
const recText = (r) => (typeof r === 'string' ? r : r && typeof r === 'object' ? Object.values(r).join(' ') : String(r));

function recordTables(d) {
  return TYPES.filter((t) => (d.records?.[t] || []).length).map((t) => {
    const rows = d.records[t];
    return h('div', null,
      h('h4', { class: 'text-sm font-semibold mb-1 flex items-center' }, `${t} records (${rows.length})`, d.ttl?.[t] != null ? ttlChip(d.ttl[t]) : null),
      dataTable([t], rows.map((r) => [recText(r)]), { mono: [0] }));
  });
}

const DNSSEC = {
  signed: ['ok', 'Signed and verified'], unverified: ['warn', 'Signed, not verified by our resolver'], broken: ['bad', 'Broken chain of trust'], partial: ['warn', 'Partly set up'], unsigned: ['mute', 'Not signed'],
};

function render(res) {
  const d = res.data || {};
  const out = [resultVerdict(res)];
  const tables = recordTables(d);
  if (tables.length) out.push(checkCard({ status: 'info', title: 'Records by type', body: h('div', { class: 'space-y-4' }, tables),
    meaning: 'These are the answers the public DNS gives for this name. TTL is how long other resolvers may keep an answer before asking again: a low TTL means changes spread fast, a high TTL means fewer lookups.' }));
  if (d.ns) {
    const servers = d.ns.servers || [];
    out.push(checkCard({ status: d.ns.count >= 2 ? 'ok' : 'warn', title: `Name servers: ${d.ns.count}`,
      body: h('div', null, dataTable(['Server', 'Addresses', 'Authoritative'], servers.map((s) => [s.host, (s.ips || []).join(', ') || 'none', s.authoritative ? 'yes' : s.answers === false ? 'no answer' : 'unknown']), { mono: [0, 1] }),
        d.ns.networks != null ? h('p', { class: 'text-sm mt-2' }, `Spread over ${plural(Array.isArray(d.ns.networks) ? d.ns.networks.length : d.ns.networks, 'network')}.`) : null),
      meaning: 'At least two name servers on different networks keep your domain resolving if one of them fails.',
      fix: d.ns.count < 2 ? { steps: ['Add a second name server at your registrar, ideally on a different network.'] } : null }));
  }
  if (d.soa && Object.keys(d.soa).length) {
    const s = d.soa;
    out.push(checkCard({ status: 'info', title: 'Zone timers (SOA)', body: keyValueTable([
      ['Primary server', s.mname], ['Admin mailbox', s.rname], ['Serial', s.serial != null ? `${s.serial}${s.serial_format ? ' (' + s.serial_format + ')' : ''}` : null],
      ['Refresh', s.refresh != null ? human(s.refresh) : null], ['Retry', s.retry != null ? human(s.retry) : null], ['Expire', s.expire != null ? human(s.expire) : null], ['Negative cache', s.minimum != null ? human(s.minimum) : null]]),
    meaning: 'The SOA record controls how secondary name servers copy the zone. Refresh and retry set how often they check; expire is how long they keep answering if they cannot reach the primary.' }));
  }
  if (d.caa) {
    const cas = d.caa.allowed_cas || [];
    out.push(checkCard({ status: (d.caa.records || []).length ? 'ok' : 'info', title: (d.caa.records || []).length ? 'CAA: who may issue certificates' : 'CAA: not set',
      body: cas.length ? h('div', { class: 'flex flex-wrap gap-2' }, cas.map((c) => h('span', { class: 'pill pill-info' }, c.name || c.domain)), d.caa.iodef ? h('span', { class: 'text-sm' }, `Violations reported to ${d.caa.iodef}`) : null) : d.caa.no_issuance ? h('p', { class: 'text-sm' }, 'Issuance is forbidden for everyone.') : null,
      meaning: 'CAA records list which certificate authorities may issue TLS certificates for the domain. With none set, any authority may.',
      fix: (d.caa.records || []).length ? null : { steps: ['Add a CAA record for the authority you use, for example the one that issues your certificates.'], code: `${res.target}. CAA 0 issue "letsencrypt.org"`, codeLabel: 'Example record' } }));
  }
  if (d.dnssec) {
    const [s, word] = DNSSEC[d.dnssec.state] || ['mute', d.dnssec.state];
    out.push(checkCard({ status: s, title: `DNSSEC: ${word}`,
      body: h('div', { class: 'flex flex-wrap items-center gap-2 text-sm' }, pill(s, word),
        h('span', { class: 'pill pill-mute' }, `DS at parent: ${(d.dnssec.ds || []).length ? 'yes' : 'no'}`), h('span', { class: 'pill pill-mute' }, `DNSKEY: ${d.dnssec.dnskey_count ?? 0}`), h('span', { class: 'pill pill-mute' }, `Validated: ${d.dnssec.ad ? 'yes' : 'no'}`)),
      meaning: 'DNSSEC signs your DNS answers so they cannot be forged on the way. It needs both a signed zone and a matching DS record at the registry; a mismatch makes the domain fail to resolve for validating resolvers.',
      fix: d.dnssec.state === 'broken' ? { steps: ['Remove the DS record at your registrar, or re-publish the DNSKEY it points to. Do this quickly: validating resolvers reject the domain meanwhile.'] } : null }));
  }
  out.push(...findingCards(res.findings));
  return out;
}

domainTool({ endpoint: '/mail/dns', render });
void stat;
