import { h, srOnly, pill, plural } from '../ui/dom.js';
import { checkCard, codeBlock } from '../ui/card.js';
import { tree } from '../ui/tree.js';
import { domainTool, findingCards, resultVerdict, stat } from '../ui/findings.js';

/** Lookup budget bar: x of 10 DNS lookups. Green up to 7, amber 8-10, red above 10 (the limit is 10, RFC 7208). */
function lookupBar(n, limit = 10) {
  const status = n <= 7 ? 'ok' : n <= limit ? 'warn' : 'bad';
  const word = status === 'ok' ? 'Plenty of room' : status === 'warn' ? 'Close to the limit' : 'Over the limit';
  const cells = Array.from({ length: Math.max(limit, n) }, (_, i) => h('span', {
    class: 'flex-1 h-3 rounded-sm', style: `background:${i < n ? (i >= limit ? 'var(--bad)' : i >= 7 ? 'var(--warn)' : 'var(--ok)') : 'var(--surface2)'};border:1px solid var(--line)`,
  }));
  return h('div', null,
    h('div', { class: 'flex items-center gap-3 mb-2' }, h('span', { class: 'text-2xl font-bold mono' }, `${n} / ${limit}`), pill(status, word)),
    h('div', { class: 'flex gap-1', 'aria-hidden': 'true' }, cells),
    srOnly(`${n} of ${limit} allowed DNS lookups used. ${word}.`));
}

const node = (t) => ({
  label: t.domain,
  sub: [t.kind && t.kind !== 'root' ? t.kind : null, t.error || (t.own != null ? `${plural(t.own, 'lookup')} here` : null)].filter(Boolean).join(' - '),
  status: t.error ? 'bad' : 'ok',
  badge: t.lookups != null ? `${t.lookups} total` : undefined,
  children: (t.children || []).map(node),
});

function render(res) {
  const d = res.data || {};
  const out = [resultVerdict(res, { meta: d.record ? undefined : res.target })];
  if (d.record) {
    out.push(h('div', { class: 'flex flex-wrap gap-2' },
      stat('DNS lookups', `${d.lookups ?? 0} / ${d.limit ?? 10}`, 'limit is 10'),
      stat('Failed lookups', `${d.void_lookups ?? 0} / ${d.void_limit ?? 2}`, 'limit is 2'),
      stat('Ends with', d.all || 'none', 'the catch-all rule')));
    out.push(checkCard({
      status: d.lookups > 10 ? 'bad' : d.lookups > 7 ? 'warn' : 'ok', title: 'DNS lookup budget',
      body: lookupBar(d.lookups ?? 0, d.limit ?? 10),
      meaning: 'Receivers stop evaluating SPF after 10 DNS lookups caused by include, a, mx, ptr, exists and redirect. Going over turns a valid record into a permanent error, and mail can then fail authentication.',
      fix: d.lookups > 7 ? { steps: ['Remove includes for services you no longer use.', 'Replace include entries with ip4: or ip6: ranges where the sender has a stable address.', 'If you must keep many senders, move some to a subdomain with its own SPF record.'] } : null,
    }));
    if (d.tree) {
      out.push(checkCard({
        status: 'info', title: 'Where the lookups come from',
        body: h('div', null, tree(node(d.tree)), d.truncated ? h('p', { class: 'text-xs text-mute mt-2' }, 'The tree was cut off at the depth limit.') : null),
        meaning: 'Each domain in the tree is another SPF record the receiver has to fetch. The number shows how many lookups that branch costs in total.',
        details: d.record,
      }));
    }
    out.push(h('div', null, h('div', { class: 'text-xs text-mute mb-1' }, 'Published record'), codeBlock(d.record, 'Copy')));
  }
  out.push(...findingCards(res.findings));
  return out;
}

domainTool({ endpoint: '/mail/spf', render });
