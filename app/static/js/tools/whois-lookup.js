import { h, $, plural } from '../ui/dom.js';
import { initTool, qParam } from '../ui/tool.js';
import { verdict } from '../ui/verdict.js';
import { checkCard } from '../ui/card.js';
import { gauge } from '../ui/gauge.js';
import { dateline } from '../ui/timeline.js';
import { keyValueTable } from '../ui/table.js';

const qEl = $('#whois-query');
const DAY = 86400000;
const days = (iso) => Math.floor((new Date(iso) - Date.now()) / DAY);

// EPP status codes in plain words: [explanation, status for the chip]
const EPP = {
  clienttransferprohibited: ['The registrar has locked the domain so it cannot be transferred away without unlocking it. This is a good protection.', 'ok'],
  servertransferprohibited: ['The registry has locked the domain against transfers.', 'ok'],
  clientdeleteprohibited: ['The registrar blocks deletion of the domain.', 'ok'],
  serverdeleteprohibited: ['The registry blocks deletion of the domain.', 'ok'],
  clientupdateprohibited: ['The registrar blocks changes to the domain details.', 'ok'],
  serverupdateprohibited: ['The registry blocks changes to the domain details.', 'ok'],
  clienthold: ['The registrar has switched the domain off in DNS, so it does not resolve. Usually a billing or verification problem.', 'bad'],
  serverhold: ['The registry has switched the domain off in DNS, so it does not resolve.', 'bad'],
  pendingdelete: ['The domain has expired and is being deleted. It will soon be available to register.', 'bad'],
  redemptionperiod: ['The domain has expired and is in a grace period where only the owner can still restore it, usually for a fee.', 'bad'],
  pendingtransfer: ['A transfer to another registrar is in progress.', 'warn'],
  pendingupdate: ['A change to the domain is waiting to be processed.', 'warn'],
  autorenewperiod: ['The domain recently auto-renewed.', 'info'],
  addperiod: ['The domain was registered recently.', 'info'],
  ok: ['Nothing special: the domain is active with no locks.', 'info'],
  active: ['The domain is active.', 'info'],
};
const eppKey = (s) => String(s).replace(/[\s_-]/g, '').toLowerCase();

function eppChips(list) {
  return h('ul', { class: 'list-none m-0 p-0 space-y-2' }, list.map((s) => {
    const e = EPP[eppKey(s)] || ['A status flag set by the registry or registrar. Look the code up at icann.org/epp for its exact meaning.', 'info'];
    return h('li', { class: 'flex flex-wrap items-start gap-2' }, h('span', { class: `pill pill-${e[1] === 'info' ? 'info' : e[1]} mono` }, s), h('span', { class: 'text-sm flex-1 min-w-[14rem]' }, e[0]));
  }));
}

function renderDomain(d) {
  const ev = d.events || {}, exp = ev.expiration, left = exp ? days(exp) : null;
  const statuses = d.status || [];
  const holdish = statuses.some((s) => ['clienthold', 'serverhold', 'pendingdelete', 'redemptionperiod'].includes(eppKey(s)));
  const status = holdish || (left != null && left < 0) ? 'bad' : left != null && left <= 30 ? 'warn' : 'ok';
  const name = d.registered_domain || d.name || qEl.value.trim();
  const registrar = (d.entities || []).find((e) => (e.roles || []).includes('registrar'));
  const summary = left == null ? `${name} is registered${registrar ? ' through ' + registrar.name : ''}. The registry did not publish an expiry date.`
    : left < 0 ? `${name} expired ${-left} days ago and may be lost soon unless it is renewed.`
      : `${name} is registered${registrar ? ' through ' + registrar.name : ''} and expires in ${plural(left, 'day')} (${exp.slice(0, 10)}).`;
  const out = [verdict({ status, title: holdish ? 'Domain has a problem status' : left != null && left < 0 ? 'Expired' : left != null && left <= 30 ? 'Expires soon' : 'Registered and active', summary, meta: `Source: ${d.protocol.toUpperCase()} ${d.source || ''}` })];

  if (ev.registration || ev.last_changed || exp) {
    out.push(checkCard({
      status: left == null ? 'info' : left < 0 ? 'bad' : left <= 30 ? 'warn' : 'ok', title: left == null ? 'Registration dates' : left < 0 ? 'The registration has expired' : `Registration runs for ${plural(left, 'more day')}`,
      body: h('div', { class: 'flex flex-wrap items-center gap-6' },
        left != null ? gauge({ value: Math.max(0, Math.min(left, 365)), max: 365, label: left < 0 ? '0' : String(left), unit: 'days left', status: left < 0 ? 'bad' : left <= 30 ? 'warn' : 'ok', semi: true, size: 150, sr: `${left} days until the domain expires` }) : null,
        h('div', { class: 'flex-1 min-w-[18rem]' }, dateline({ points: [{ label: 'Registered', date: ev.registration, status: 'info' }, { label: 'Last changed', date: ev.last_changed, status: 'info' }, { label: 'Expires', date: exp, status: left == null ? 'info' : left < 0 ? 'bad' : left <= 30 ? 'warn' : 'ok' }] }))),
      meaning: 'The expiry date is when the registration lapses unless it is renewed. Expired domains stop working and can eventually be released for anyone to register.',
      fix: left != null && left <= 30 ? { steps: ['Renew the domain with your registrar now, ideally for several years.', 'Turn on auto-renew and check the payment card on file.', 'Make sure the contact email at the registrar is one you read.'] } : null,
    }));
  }
  if (statuses.length) {
    out.push(checkCard({ status: holdish ? 'bad' : 'info', title: `${plural(statuses.length, 'status code')} set on this domain`, body: eppChips(statuses),
      meaning: 'EPP status codes are flags the registry and registrar put on a domain. Most are locks that protect it; a few signal a problem.',
      fix: holdish ? { steps: ['Contact your registrar and ask why the domain is on hold; it is often an unpaid renewal or unverified contact email.', 'Fix the cause, then ask them to lift the hold. DNS starts working again shortly afterwards.'] } : null }));
  }
  out.push(checkCard({ status: (d.nameservers || []).length ? 'ok' : 'warn', title: (d.nameservers || []).length ? `Nameservers: ${d.nameservers.length}` : 'No nameservers listed',
    body: (d.nameservers || []).length ? h('ul', { class: 'list-none m-0 p-0 mono text-sm' }, d.nameservers.map((n) => h('li', null, n))) : null,
    meaning: 'Nameservers say where the domain\'s DNS is hosted. If you move DNS to a new provider, this list must change at the registrar.',
    details: keyValueTable([['Domain', d.name], ['Registrar', registrar && registrar.name], ['IANA ID', registrar && registrar.iana_id], ['DNSSEC', d.dnssec ? 'signed' : 'not signed']]) }));
  out.push(checkCard({ status: d.dnssec ? 'ok' : 'info', title: d.dnssec ? 'DNSSEC is switched on' : 'DNSSEC is not enabled',
    meaning: d.dnssec ? 'DNS answers for this domain are digitally signed, so they cannot be silently altered in transit.' : 'DNSSEC adds signatures to DNS answers. It is optional; it helps against forged DNS replies but needs support from your DNS host.',
    details: keyValueTable([['Registered', ev.registration], ['Last changed', ev.last_changed], ['Expires', exp], ['Status', statuses]]) }));
  return out;
}

function renderIp(d) {
  const ev = d.events || {};
  const out = [verdict({ status: 'info', title: 'Network owner found', summary: `${qEl.value.trim()} belongs to ${d.name || d.handle || 'a network'}${d.country ? ' (' + d.country + ')' : ''}${d.cidr ? ', inside ' + [].concat(d.cidr).join(', ') : ''}.`, meta: `Source: ${d.protocol.toUpperCase()} ${d.source || ''}` })];
  out.push(checkCard({ status: 'ok', title: `Network ${d.name || d.handle || ''}`.trim(),
    body: keyValueTable([['Network name', d.name], ['Handle', d.handle], ['Range', d.start && d.end ? d.start + ' - ' + d.end : ''], ['CIDR', d.cidr], ['Type', d.network_type], ['Country', d.country], ['Status', d.status]]),
    meaning: 'The regional internet registry that allocated this address block says who it was given to. Use the abuse contact to report problems from this range.',
    details: keyValueTable([['Registered', ev.registration], ['Last changed', ev.last_changed], ...((d.entities || []).map((e) => [(e.roles || []).join(', ') || 'entity', [e.name, e.handle].filter(Boolean).join(' / ')]))]) }));
  return out;
}

function render(d) {
  if (d.protocol === 'whois') {
    return [verdict({ status: 'info', title: 'Classic WHOIS answer', summary: `This registry has no RDAP service, so the raw WHOIS text is shown. Personal details are removed.`, meta: d.source }),
      checkCard({ status: 'info', title: 'Raw WHOIS text', details: d.raw })];
  }
  return d.type === 'domain' ? renderDomain(d) : renderIp(d);
}

initTool({
  form: '#whois-form',
  run: (ctx) => ctx.api('/whois/lookup', { query: qEl.value.trim() }),
  render,
  state: () => ({ q: qEl.value.trim() }),
  prefill: (p) => { const q = qParam(p, 'query'); if (q) qEl.value = q; return !!q; },
});
