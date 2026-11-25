// Command-bar input detection and routing. Pure functions (no DOM) so they are easy to reason about.
// detect(input) -> { type, value, prefix, tool? }
//   type: ip | prefix | asn | domain | email | url | host | empty
// route(det, tools) -> { slug, params } | null   (null: no tool for this input yet)

const PREFIXES = ['mx', 'spf', 'dmarc', 'dkim', 'blacklist', 'asn', 'smtp', 'health', 'trace', 'ping', 'whois', 'dns', 'ports', 'ssl', 'bimi', 'mtasts', 'mta-sts', 'headers'];

const V4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const V6 = /^[0-9a-f:.]+$/i;
const DOMAIN = /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{1,62}$/i;
const EMAIL = /^[^@\s]+@([a-z0-9-]+\.)+[a-z]{2,}$/i;

export function isIPv4(s) { return V4.test(s); }
export function isIPv6(s) { return s.includes(':') && V6.test(s) && s.split(':').length >= 3 && s.split(':').length <= 8 + 1; }

export function detect(raw) {
  let input = (raw || '').trim();
  if (!input) return { type: 'empty', value: '' };
  if (/^myip$/i.test(input)) return { type: 'myip', value: '', prefix: null };
  let prefix = null;
  const m = /^([a-z][a-z-]*):\s*(\S.*)$/i.exec(input);
  if (m && PREFIXES.includes(m[1].toLowerCase()) && !/^\/\//.test(m[2])) { prefix = m[1].toLowerCase(); input = m[2].trim(); }
  const base = (type) => ({ type, value: input, prefix });
  if (prefix === 'asn' && /^\d{1,10}$/.test(input)) return { type: 'asn', value: 'AS' + input, prefix };
  if (/^https?:\/\//i.test(input)) return base('url');
  if (EMAIL.test(input)) return base('email');
  if (/^AS\d{1,10}$/i.test(input)) return { type: 'asn', value: input.toUpperCase(), prefix };
  const cidr = /^([^/]+)\/(\d{1,3})$/.exec(input);
  if (cidr && (isIPv4(cidr[1]) ? +cidr[2] <= 32 : isIPv6(cidr[1]) && +cidr[2] <= 128)) return base('prefix');
  if (isIPv4(input) || isIPv6(input)) return base('ip');
  if (DOMAIN.test(input)) return { type: 'domain', value: input.toLowerCase(), prefix };
  if (/^[a-z0-9][a-z0-9-]{0,62}$/i.test(input)) return base('host');
  return base('unknown');
}

const hostOf = (det) => {
  if (det.type === 'email') return det.value.split('@')[1].toLowerCase();
  if (det.type === 'url') { try { return new URL(det.value).hostname; } catch { return det.value; } }
  return det.value;
};

// Which tools to suggest first, per detected input type (the rest follow in tab-rail order, capped by CHIP_MAX).
const CHIP_ORDER = {
  domain: ['domain-health', 'mx-lookup', 'spf-checker', 'dmarc-checker', 'dns-lookup', 'whois-lookup', 'ttfb-ssl-checker', 'dkim-checker', 'blacklist-check'],
  ip: ['looking-glass', 'blacklist-check', 'reverse-dns-lookup', 'bgp-prefix-lookup', 'whois-lookup'],
  prefix: ['bgp-prefix-lookup', 'subnet-calculator', 'whois-lookup'],
  asn: ['asn-lookup'],
};
CHIP_ORDER.email = CHIP_ORDER.domain; CHIP_ORDER.url = ['ttfb-ssl-checker', ...CHIP_ORDER.domain]; CHIP_ORDER.host = CHIP_ORDER.domain;
const CHIP_MAX = 8;

/** Tools whose `accepts` includes the detected type (domain/url/email also count as host), best match first. */
export function chipsFor(det, tools) {
  if (det.type === 'empty' || det.type === 'unknown') return [];
  const kinds = new Set([det.type]);
  if (['domain', 'url', 'email'].includes(det.type)) kinds.add('host').add('domain');
  const list = tools.filter((t) => (t.accepts || []).some((a) => kinds.has(a)));
  const order = CHIP_ORDER[det.type] || [];
  const rank = (t) => { const i = order.indexOf(t.slug); return i < 0 ? 99 : i; };
  return list.map((t, i) => [t, i]).sort((a, b) => rank(a[0]) - rank(b[0]) || a[1] - b[1]).map((x) => x[0]).slice(0, CHIP_MAX);
}

/** Where Enter goes. `tools` is the toolbox config list (only tools that exist are routable). */
export function route(det, tools) {
  const has = (slug) => tools.some((t) => t.slug === slug);
  const v = det.type === 'url' || det.type === 'email' ? hostOf(det) : det.value;
  const go = (slug, params = {}) => (has(slug) ? { slug, params: { q: params.q ?? v, ...params } } : null);
  switch (det.prefix) {
    case 'trace': return go('looking-glass', { tool: 'traceroute' });
    case 'ping': return go('looking-glass', { tool: 'ping' });
    case 'whois': return go('whois-lookup');
    case 'dns': return go('dns-lookup') || go('dns-propagation-checker');
    case 'ports': return go('port-checker');
    case 'ssl': return go('ttfb-ssl-checker', { q: det.type === 'url' ? det.value : 'https://' + v });
    case 'mx': return go('mx-lookup');
    case 'spf': return go('spf-checker');
    case 'dmarc': return go('dmarc-checker');
    case 'bimi': return go('bimi-checker');
    case 'mtasts': case 'mta-sts': return go('mta-sts-checker');
    case 'headers': { const r = go('http-headers-checker', { q: det.type === 'url' ? det.value : v }); if (r) return r; break; } // ignored when the tool is not installed
    case 'health': return go('domain-health');
    case 'smtp': return go('smtp-test');
    case 'blacklist': return go('blacklist-check');
    case 'asn': return go('asn-lookup', { q: det.type === 'asn' ? det.value : v });
    case 'dkim':
      // dkim:selector@domain  or  dkim:domain
      if (det.type === 'email') { const [sel, dom] = det.value.split('@'); return go('dkim-checker', { q: dom.toLowerCase(), selector: sel }); }
      return go('dkim-checker');
    default: break;
  }
  switch (det.type) {
    case 'myip': return has('what-is-my-ip') ? { slug: 'what-is-my-ip', params: {} } : null;
    case 'ip': return go('looking-glass') || go('reverse-dns-lookup');
    case 'prefix': return go('bgp-prefix-lookup') || go('subnet-calculator');
    case 'asn': return go('asn-lookup');
    case 'domain': case 'host': return go('domain-health') || go('dns-propagation-checker');
    case 'url': return go('ttfb-ssl-checker', { q: det.value });
    case 'email': return go('domain-health') || go('dns-propagation-checker', { type: 'MX' });
    default: return null;
  }
}

/** Query parameters for opening `slug` with the detected input (used by the chips). */
export function paramsFor(slug, det) {
  const host = hostOf(det);
  switch (slug) {
    case 'ttfb-ssl-checker': return { q: det.type === 'url' ? det.value : 'https://' + host };
    case 'looking-glass': case 'dns-propagation-checker': case 'whois-lookup': return det.type === 'ip' || det.type === 'prefix' ? { q: det.value } : { q: host };
    case 'mx-lookup': case 'spf-checker': case 'dmarc-checker': case 'bimi-checker': case 'mta-sts-checker': case 'dkim-checker': case 'domain-health': case 'dns-lookup': case 'smtp-test': return { q: host };
    case 'http-headers-checker': return { q: det.type === 'url' ? det.value : host };
    case 'blacklist-check': return { q: det.type === 'ip' ? det.value : host };
    default: return { q: det.value };
  }
}

/** Human label for the detected type, shown next to the chips. */
export const TYPE_LABEL = { ip: 'an IP address', prefix: 'an IP prefix', asn: 'an AS number', domain: 'a domain', email: 'an email address', url: 'a URL', host: 'a hostname', myip: 'a request for your own IP address' };
