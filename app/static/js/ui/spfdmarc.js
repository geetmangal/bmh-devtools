// SPF and DMARC record builders: pure functions (no DOM, no network) used by tools/spf-dmarc-generator.js.
// Each builder returns {record, ..., warnings: [{status: 'warn'|'bad'|'info', title, meaning}]}.

const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$/i;
const EMAIL_RE = /^[^\s@,;:<>]+@([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

const words = (s) => String(s || '').split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);

export function validIp4(tok) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(tok);
  return !!m && m.slice(1, 5).every((o) => Number(o) <= 255) && (m[5] === undefined || Number(m[5]) <= 32);
}

export function validIp6(tok) {
  const [addr, len, extra] = tok.split('/');
  if (extra !== undefined || !/^[0-9a-f:.]+$/i.test(addr) || !addr.includes(':')) return false;
  if (len !== undefined && !(/^\d{1,3}$/.test(len) && Number(len) <= 128)) return false;
  try { new URL(`http://[${addr}]/`); return true; } catch { return false; }
}

/** Reduce what a visitor typed to a bare domain name. */
export function bareDomain(v) {
  let s = String(v || '').trim().toLowerCase();
  if (s.includes('@') && !s.includes('//')) s = s.split('@').pop();
  return s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').split(/[/?#]/)[0].replace(/:\d+$/, '').replace(/\.$/, '');
}

/** Split a record into DNS TXT strings of at most 255 characters (they are joined again without a space). */
export const txtStrings = (record) => record.match(/[\s\S]{1,255}/g) || [''];

/**
 * buildSpf({ includes: [domain], ip4: 'text', ip6: 'text', extraIncludes: 'text', a: bool, mx: bool, all: '~all'|'-all', domain })
 * lookups = includes + a + mx (ip4, ip6 and all cost nothing). Nested includes are unknown here, so with any include the
 * number is "at least".
 */
export function buildSpf(o) {
  const warnings = [];
  const seen = new Set();
  const mechs = [];
  const add = (m, label) => {
    if (seen.has(m)) { warnings.push({ status: 'warn', title: `Duplicate entry: ${m}`, meaning: `${label || m} is listed twice. The second copy is dropped from the record, but it usually means two settings say the same thing.` }); return false; }
    seen.add(m); mechs.push(m); return true;
  };
  const bad = (what, tok) => warnings.push({ status: 'bad', title: `Not a valid ${what}: ${tok.slice(0, 60)}`, meaning: `It was left out of the record. A wrong value makes receivers treat the whole SPF record as an error.` });

  const ips4 = [], ips6 = [];
  for (let t of words(o.ip4)) {
    t = t.replace(/^ip4:/i, '');
    if (!validIp4(t)) { bad('IPv4 address or range', t); continue; }
    if (add(`ip4:${t}`, t)) ips4.push(t);
  }
  for (let t of words(o.ip6)) {
    t = t.replace(/^ip6:/i, '');
    if (!validIp6(t)) { bad('IPv6 address or range', t); continue; }
    if (add(`ip6:${t.toLowerCase()}`, t)) ips6.push(t);
  }
  if (o.a) add('a');
  if (o.mx) add('mx');
  let includes = 0;
  const inc = [...(o.includes || []), ...words(o.extraIncludes).map((t) => t.replace(/^include:/i, ''))];
  for (const d0 of inc) {
    const d = d0.toLowerCase();
    if (!DOMAIN_RE.test(d)) { bad('domain name for include', d0); continue; }
    if (add(`include:${d}`, d)) includes += 1;
  }
  const all = o.all === '-all' ? '-all' : '~all';
  const record = ['v=spf1', ...mechs, all].join(' ');
  const lookups = includes + (o.a ? 1 : 0) + (o.mx ? 1 : 0);
  const exact = includes === 0;

  if (lookups > 10) warnings.push({ status: 'bad', title: `${lookups} DNS lookups: over the limit of 10`, meaning: 'Receivers stop at 10 lookups and treat the record as a permanent error, so mail can fail SPF. Remove services you do not use or replace includes with ip4 or ip6 ranges.' });
  else if (lookups >= 7 || (!exact && lookups >= 5)) warnings.push({ status: 'warn', title: `${exact ? '' : 'At least '}${lookups} DNS lookups: getting close to 10`, meaning: 'The records you include can contain includes of their own, which count too. Check the exact total with the SPF checker once the record is published.' });
  if (!mechs.length) warnings.push({ status: 'info', title: 'This record allows no server to send mail', meaning: 'With no senders listed, v=spf1 ~all or -all says that nothing is allowed. That is right for a domain that never sends mail, and wrong if it does.' });
  if (o.all === '-all' && includes + ips4.length + ips6.length > 0) warnings.push({ status: 'info', title: '-all rejects mail from any sender you forgot', meaning: 'Make sure every service that sends as your domain is ticked before you switch from ~all to -all, or its mail will be refused.' });
  if (record.length > 255) warnings.push({ status: 'warn', title: `The record is ${record.length} characters, over the 255 limit for one DNS string`, meaning: 'A single TXT string holds at most 255 characters. Most DNS panels split a longer value for you; if yours does not, publish it as several quoted strings (shown below). Receivers join them without a space.' });
  if (record.length > 450) warnings.push({ status: 'warn', title: 'The record is very long', meaning: 'DNS answers above about 450 bytes may not fit in one UDP packet. Shorten the record by dropping unused services.' });
  return { record, strings: txtStrings(record), lookups, exact, includes, length: record.length, warnings };
}

/**
 * buildDmarc({ p, sp, pct, rua, ruf, adkim, aspf, fo, domain })
 */
export function buildDmarc(o) {
  const warnings = [];
  const p = ['none', 'quarantine', 'reject'].includes(o.p) ? o.p : 'none';
  const sp = ['none', 'quarantine', 'reject'].includes(o.sp) ? o.sp : '';
  const domain = bareDomain(o.domain);
  let pct = o.pct === '' || o.pct == null ? 100 : Number(o.pct);
  if (!Number.isInteger(pct) || pct < 0 || pct > 100) { warnings.push({ status: 'bad', title: 'pct must be a whole number from 0 to 100', meaning: 'The pct tag was left out, which means 100.' }); pct = 100; }

  const uris = (text, tag) => {
    const out = [];
    for (const raw of words(text)) {
      const addr = raw.replace(/^mailto:/i, '');
      if (!EMAIL_RE.test(addr)) { warnings.push({ status: 'bad', title: `Not a valid email address in ${tag}: ${raw.slice(0, 60)}`, meaning: 'It was left out of the record. DMARC report addresses are written as mailto:name@example.com.' }); continue; }
      if (!out.includes(addr)) out.push(addr);
      else warnings.push({ status: 'warn', title: `Duplicate address in ${tag}: ${addr}`, meaning: 'The second copy was dropped.' });
    }
    return out;
  };
  const rua = uris(o.rua, 'rua'), ruf = uris(o.ruf, 'ruf');
  const parts = ['v=DMARC1', `p=${p}`];
  if (sp) parts.push(`sp=${sp}`);
  if (pct !== 100) parts.push(`pct=${pct}`);
  if (rua.length) parts.push('rua=' + rua.map((a) => `mailto:${a}`).join(','));
  if (ruf.length) parts.push('ruf=' + ruf.map((a) => `mailto:${a}`).join(','));
  if (o.adkim === 's') parts.push('adkim=s');
  if (o.aspf === 's') parts.push('aspf=s');
  const fo = ['1', 'd', 's'].includes(o.fo) ? o.fo : '0';
  if (fo !== '0') parts.push(`fo=${fo}`);
  const record = parts.join('; ');

  if (p === 'none') warnings.push({ status: 'info', title: 'p=none only monitors', meaning: 'Receivers send you reports but still deliver failing mail. It is the right first step: read the reports for a few weeks, then move to quarantine and reject.' });
  if (p !== 'none' && pct < 100) warnings.push({ status: 'info', title: `Policy applies to ${pct}% of failing mail`, meaning: 'A pct below 100 is a staged rollout. Raise it to 100 once the reports show only mail you do not recognise failing.' });
  if (p === 'none' && pct !== 100) warnings.push({ status: 'warn', title: 'pct has no effect with p=none', meaning: 'There is nothing to apply to a percentage of mail when the policy is only monitoring.' });
  if (!rua.length) warnings.push({ status: 'warn', title: 'No aggregate report address (rua)', meaning: 'Without rua you receive no reports, so you cannot see who sends mail as your domain or what fails. Add an address that someone reads, or a DMARC report service.' });
  if (fo !== '0' && !ruf.length) warnings.push({ status: 'warn', title: 'fo is set but there is no ruf address', meaning: 'The fo tag only controls failure reports, which are sent to the ruf address. Add one or leave fo at 0.' });
  if (ruf.length) warnings.push({ status: 'info', title: 'Few receivers send failure reports (ruf)', meaning: 'Large mailbox providers mostly do not send them because they can contain message content. Rely on the aggregate reports.' });
  if (domain) {
    const ext = [...new Set([...rua, ...ruf].map((a) => a.split('@')[1].toLowerCase()).filter((d) => d !== domain && !d.endsWith('.' + domain)))];
    if (ext.length) warnings.push({ status: 'warn', title: `Reports go to another domain: ${ext.join(', ')}`, meaning: `Receivers only send reports to a different domain if that domain publishes a TXT record at ${domain}._report._dmarc.${ext[0]} with the value v=DMARC1. Report services usually give you this record; without it the reports are dropped.` });
  }
  return { record, host: '_dmarc', fqdn: domain ? `_dmarc.${domain}` : '_dmarc.example.com', p, pct, strings: txtStrings(record), warnings };
}
