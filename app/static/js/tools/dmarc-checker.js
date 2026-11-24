import { h, srOnly, icon } from '../ui/dom.js';
import { checkCard, codeBlock } from '../ui/card.js';
import { domainTool, findingCards, resultVerdict, stat, nextSteps } from '../ui/findings.js';

const STEPS = [
  { key: 'none', title: 'none', note: 'Monitor only. Nothing is blocked; you receive reports.' },
  { key: 'quarantine', title: 'quarantine', note: 'Failing mail is sent to spam.' },
  { key: 'reject', title: 'reject', note: 'Failing mail is refused. Full protection.' },
];

/** none -> quarantine -> reject, with the current step highlighted and pct shown. */
function policyFlow(policy, pct) {
  const idx = STEPS.findIndex((s) => s.key === policy);
  const items = STEPS.flatMap((s, i) => {
    const cur = i === idx, done = idx > i;
    const box = h('li', { class: `flex-1 min-w-[8rem] rounded-xl border p-3 ${cur ? 'border-accent' : 'border-line'}`, style: cur ? 'background:var(--surface2);border-width:2px' : '', 'aria-current': cur ? 'step' : null },
      h('div', { class: 'flex items-center gap-1.5 text-sm font-semibold' }, h('span', { class: cur ? 'st-mute' : done ? 'st-ok' : 'text-mute' }, icon(cur ? 'info' : done ? 'ok' : 'mute', 14)), `p=${s.title}`),
      h('div', { class: 'text-xs text-mute mt-1' }, s.note),
      cur ? h('div', { class: 'text-xs font-semibold mt-1' }, `You are here${pct != null && pct < 100 ? `, applied to ${pct}% of mail` : ''}`) : null);
    return i < STEPS.length - 1 ? [box, h('li', { class: 'self-center text-mute hidden sm:block', 'aria-hidden': 'true' }, '→')] : [box];
  });
  return h('div', null, h('ol', { class: 'list-none m-0 p-0 flex flex-col sm:flex-row gap-2' }, items),
    srOnly(idx < 0 ? 'No DMARC policy is published.' : `Current policy is ${policy}${pct != null ? ` at ${pct} percent` : ''}. Steps are none, quarantine, reject.`));
}

/** From domain <-> SPF domain / DKIM domain, labelled strict or relaxed. */
function alignment(d, domain) {
  const mode = (v) => (v === 's' ? 'strict: exact match' : 'relaxed: same organisation');
  const row = (label, m) => h('div', { class: 'flex items-center gap-2 flex-wrap' },
    h('div', { class: 'rounded-lg border border-line px-3 py-1.5 text-sm font-semibold' }, label),
    h('div', { class: 'text-mute text-sm', 'aria-hidden': 'true' }, '↔'),
    h('div', { class: 'rounded-lg border border-line px-3 py-1.5 text-sm mono' }, `From: ${domain}`),
    h('span', { class: 'pill pill-info' }, mode(m)));
  return h('div', { class: 'space-y-2' },
    row('SPF domain (Return-Path)', d.aspf), row('DKIM domain (d=)', d.adkim),
    h('p', { class: 'text-xs text-mute' }, 'DMARC passes when SPF or DKIM passes and its domain lines up with the From address under these rules.'));
}

function rolloutPlan(policy) {
  const cur = policy === 'reject' ? 2 : policy === 'quarantine' ? 1 : 0;
  const plan = [
    ['Week 1-4: p=none with a report address (rua).', 'Read the reports and fix every legitimate sender that fails.'],
    ['Next: p=quarantine, start at pct=10.', 'Raise pct to 25, 50, then 100 as the reports stay clean.'],
    ['Finally: p=reject.', 'Keep watching the reports; add new senders to SPF or DKIM before they send.'],
  ];
  return h('ol', { class: 'list-none m-0 p-0 space-y-2' }, plan.map(([t, s], i) => h('li', { class: 'flex gap-2' },
    h('span', { class: i < cur ? 'st-ok' : i === cur ? 'st-mute' : 'text-mute' }, icon(i < cur ? 'ok' : i === cur ? 'info' : 'mute', 16)),
    h('div', null, h('div', { class: 'text-sm font-semibold' }, t, i === cur ? ' (you are here)' : ''), h('div', { class: 'text-xs text-mute' }, s)))));
}

function render(res) {
  const d = res.data || {};
  const domain = d.found_at || res.target;
  const out = [resultVerdict(res)];
  if (d.record) {
    out.push(h('div', { class: 'flex flex-wrap gap-2' },
      stat('Policy', d.policy || 'none', d.sp ? `subdomains: ${d.sp}` : null), stat('Applied to', `${d.pct ?? 100}%`, 'of failing mail'),
      stat('Reports', (d.rua || []).length ? String((d.rua || []).length) : 'none', 'aggregate addresses')));
  }
  out.push(checkCard({ status: d.policy === 'reject' ? 'ok' : d.policy === 'quarantine' ? 'info' : 'warn', title: 'Policy: what receivers do with failing mail',
    body: policyFlow(d.policy, d.pct),
    meaning: 'The policy tells other mail servers what to do when a message claiming to be from your domain fails SPF and DKIM. Most domains should move from none to quarantine to reject in stages.' }));
  if (d.record) {
    out.push(checkCard({ status: 'info', title: 'Alignment: which domains must match', body: alignment(d, domain),
      meaning: 'Passing SPF or DKIM is not enough on its own: the domain that passed has to match the visible From domain.', details: d.tags }));
    out.push(checkCard({ status: 'info', title: 'Staged rollout plan', body: rolloutPlan(d.policy),
      meaning: 'Going straight to reject can block your own legitimate mail. A staged rollout finds forgotten senders first.' }));
    out.push(h('div', null, h('div', { class: 'text-xs text-mute mb-1' }, `Published record${d.inherited ? ' (inherited from ' + d.found_at + ')' : ''}`), codeBlock(d.record, 'Copy')));
  } else if (d.starter) {
    out.push(h('div', null, h('div', { class: 'text-xs text-mute mb-1' }, 'Starter record to publish at _dmarc'), codeBlock(d.starter, 'Copy')));
  }
  out.push(...findingCards(res.findings));
  out.push(nextSteps([{ slug: 'dkim-checker', q: res.target, text: 'Now check DKIM' }, { slug: 'spf-checker', q: res.target, text: 'Check SPF' }]));
  return out;
}

domainTool({ endpoint: '/mail/dmarc', render });

