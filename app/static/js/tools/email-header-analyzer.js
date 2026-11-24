// Email header analyzer: everything happens in the browser. No API call is made and nothing is stored.
import { h, $, fmtMs, icon, pill } from '../ui/dom.js';
import { initTool } from '../ui/tool.js';
import { verdict } from '../ui/verdict.js';
import { checkCard } from '../ui/card.js';
import { keyValueTable } from '../ui/table.js';

const box = $('#tool-input');

/** Unfold and split into [name, value] pairs (RFC 5322 folding: continuation lines start with space or tab). */
export function parseHeaders(text) {
  const lines = text.replace(/\r\n?/g, '\n').split('\n');
  const out = [];
  for (const ln of lines) {
    if (/^[ \t]/.test(ln) && out.length) out[out.length - 1][1] += ' ' + ln.trim();
    else { const m = /^([!-9;-~]+):\s*(.*)$/.exec(ln); if (m) out.push([m[1], m[2]]); else if (!ln.trim() && out.length) break; }
  }
  return out;
}
const all = (hs, n) => hs.filter(([k]) => k.toLowerCase() === n).map(([, v]) => v);
const first = (hs, n) => all(hs, n)[0] || '';

/** Received hops, oldest first, with the delay from the previous hop. */
export function receivedHops(hs) {
  const hops = all(hs, 'received').map((v) => {
    const semi = v.lastIndexOf(';');
    const when = semi >= 0 ? new Date(v.slice(semi + 1).trim()) : null;
    const from = /from\s+(\S+)/i.exec(v)?.[1] || '', by = /by\s+(\S+)/i.exec(v)?.[1] || '';
    const ip = /\[([0-9a-f:.]+)\]/i.exec(v)?.[1] || '';
    const tls = /(TLS|ESMTPS|using TLS)/i.test(v);
    return { from, by, ip, tls, raw: v, t: when && !isNaN(when) ? when.getTime() : null };
  }).reverse();
  hops.forEach((x, i) => { x.delay = i > 0 && x.t != null && hops[i - 1].t != null ? Math.max(0, x.t - hops[i - 1].t) : null; });
  return hops;
}

/** Authentication-Results -> {spf, dkim, dmarc} each {result, detail}. Takes the first match of each method. */
export function authResults(hs) {
  const res = {};
  for (const v of all(hs, 'authentication-results')) {
    for (const m of ['spf', 'dkim', 'dmarc']) {
      if (res[m]) continue;
      const r = new RegExp(`\\b${m}=([a-z]+)\\b([^;]*)`, 'i').exec(v);
      if (r) res[m] = { result: r[1].toLowerCase(), detail: r[2].trim() };
    }
  }
  if (!res.spf) { const s = first(hs, 'received-spf'); const r = /^\s*([a-z]+)/i.exec(s); if (r) res.spf = { result: r[1].toLowerCase(), detail: s }; }
  return res;
}

const RESULT_STATUS = { pass: 'ok', none: 'mute', neutral: 'warn', softfail: 'warn', fail: 'bad', temperror: 'warn', permerror: 'bad', policy: 'warn' };
const rs = (r) => RESULT_STATUS[r] || 'mute';

function render(text) {
  const hs = parseHeaders(text);
  if (hs.length < 3) throw new Error('That does not look like email headers. Paste the full "original message" headers, starting with Received: or Return-Path:.');
  const hops = receivedHops(hs), auth = authResults(hs);
  const total = hops.length > 1 && hops[0].t != null && hops[hops.length - 1].t != null ? hops[hops.length - 1].t - hops[0].t : null;
  const slow = hops.filter((x) => x.delay != null && x.delay > 60000);
  const fails = ['spf', 'dkim', 'dmarc'].filter((m) => auth[m] && rs(auth[m].result) === 'bad');
  const warns = ['spf', 'dkim', 'dmarc'].filter((m) => auth[m] && rs(auth[m].result) === 'warn');
  const status = fails.length ? 'bad' : warns.length || slow.length ? 'warn' : Object.keys(auth).length ? 'ok' : 'info';
  const out = [verdict({ status, title: fails.length ? 'Authentication failed' : status === 'ok' ? 'Message looks properly authenticated' : status === 'warn' ? 'Worth a closer look' : 'Headers read',
    summary: `${hops.length} hop${hops.length === 1 ? '' : 's'}${total != null ? ` over ${fmtMs(total)}` : ''}. ${Object.keys(auth).length ? ['spf', 'dkim', 'dmarc'].map((m) => `${m.toUpperCase()}: ${auth[m]?.result || 'not reported'}`).join(', ') + '.' : 'The headers carry no Authentication-Results line, so we cannot tell whether SPF, DKIM and DMARC passed.'}`, meta: first(hs, 'subject') || undefined })];

  out.push(checkCard({ status: 'info', title: 'Message details', body: keyValueTable([['From', first(hs, 'from')], ['To', first(hs, 'to')], ['Return-Path', first(hs, 'return-path')], ['Reply-To', first(hs, 'reply-to')], ['Message-ID', first(hs, 'message-id')], ['Date', first(hs, 'date')]]),
    meaning: 'If From and Return-Path are different domains, that is normal for mailing services, but it is also how forged mail looks, so DMARC alignment decides.' }));

  out.push(checkCard({ status, title: 'Authentication results',
    body: h('div', { class: 'flex flex-wrap gap-3' }, ['spf', 'dkim', 'dmarc'].map((m) => {
      const a = auth[m]; const s = a ? rs(a.result) : 'mute';
      return h('div', { class: 'card-flat px-3 py-2 min-w-[8rem]' }, h('div', { class: 'text-xs text-mute' }, m.toUpperCase()), h('div', { class: 'mt-0.5' }, pill(s, a ? a.result : 'not reported')), a?.detail ? h('div', { class: 'text-xs text-mute mono mt-1 break-all' }, a.detail.slice(0, 120)) : null);
    })),
    meaning: 'These results are written by the receiving mail server. SPF checks the sending server, DKIM checks a signature, and DMARC decides what to do when they do not match the From address.',
    fix: fails.length ? { steps: ['Open the sender\'s domain in the SPF, DKIM and DMARC checkers to see what is wrong.', 'If this is your own mail, add the sending service to your SPF record and enable DKIM signing for it.'] } : null }));

  if (hops.length) out.push(checkCard({ status: slow.length ? 'warn' : 'info', title: `Route: ${hops.length} hop${hops.length === 1 ? '' : 's'}${total != null ? `, ${fmtMs(total)} end to end` : ''}`,
    body: h('ol', { class: 'list-none m-0 p-0 space-y-2' }, (() => { const max = Math.max(1, ...hops.map((x) => x.delay || 0)); return hops.map((x, i) => h('li', { class: 'grid grid-cols-[1.75rem_minmax(0,1fr)] gap-x-3' },
      h('span', { class: 'text-xs text-mute mono pt-0.5' }, String(i + 1)),
      h('div', { class: 'min-w-0' },
        h('div', { class: 'text-sm mono break-all' }, x.by || '(unknown server)', x.from ? h('span', { class: 'text-mute' }, ` from ${x.from}${x.ip ? ' [' + x.ip + ']' : ''}`) : null),
        h('div', { class: 'flex items-center gap-2 mt-1' },
          h('div', { class: 'bar-track h-2 flex-1', 'aria-hidden': 'true' }, h('div', { class: 'h-2 rounded-full', style: `width:${x.delay == null ? 0 : Math.max(2, (x.delay / max) * 100)}%;background:${x.delay > 60000 ? 'var(--warn)' : 'var(--accent)'}` })),
          h('span', { class: `text-xs mono ${x.delay > 60000 ? 'st-warn' : 'text-mute'} inline-flex items-center gap-1` }, x.delay > 60000 ? icon('warn', 12) : null, x.delay == null ? (i === 0 ? 'origin' : 'no time') : x.delay > 60000 ? `${fmtMs(x.delay)} - slow hop` : fmtMs(x.delay)),
          x.tls ? h('span', { class: 'pill pill-ok' }, 'TLS') : null)))); })()),
    meaning: 'Read from the top: this is the path the message took, oldest hop first. The bar shows how long it waited since the previous hop. Delays over a minute usually mean a queue, greylisting or a busy filter at that server.' }));

  const spam = hs.filter(([k]) => /^(x-spam|x-ms-exchange-organization-scl|x-barracuda|x-mailer|user-agent|x-originating-ip|list-unsubscribe|precedence)/i.test(k));
  if (spam.length) out.push(checkCard({ status: 'info', title: 'Spam filter and client headers', body: keyValueTable(spam.map(([k, v]) => [k, v.slice(0, 200)])), meaning: 'Added by filters or the sender\'s software. A high spam score or missing List-Unsubscribe on bulk mail can hurt delivery.' }));
  out.push(checkCard({ status: 'info', title: 'All headers', meaning: 'The parsed headers, in order.', details: hs.map(([k, v]) => `${k}: ${v}`).join('\n') }));
  return out;
}

initTool({
  form: '#tool-form',
  run: async () => { const t = box.value; if (!t.trim()) throw new Error('Paste the message headers first.'); return { headers: t }; },
  render: (d) => render(d.headers),
  prefill: () => false,
});
