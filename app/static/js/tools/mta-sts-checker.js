import { h } from '../ui/dom.js';
import { codeBlock, checkCard } from '../ui/card.js';
import { errorCard } from '../ui/tool.js';
import { domainTool, findingCards, resultVerdict, stat, nextSteps } from '../ui/findings.js';

// One input, two API calls: POST /mail/mta-sts (record, policy file, mx coverage) and POST /mail/tls-rpt (report address).

function coverage(list) {
  return h('ul', { class: 'list-none m-0 p-0 space-y-1 text-sm' }, list.map((c) => h('li', { class: 'flex flex-wrap gap-2 items-center' },
    h('span', { class: c.covered ? 'st-ok' : 'st-bad', 'aria-hidden': 'true' }, c.covered ? '✓' : '✗'),
    h('span', { class: 'mono break-all' }, c.host),
    h('span', { class: 'text-mute' }, c.covered ? `covered by ${c.covered_by}` : 'not covered by the policy'))));
}

function stsSection(res) {
  const d = res.data || {}, pol = d.policy;
  const out = [resultVerdict(res, { title: res.status === 'pass' ? 'MTA-STS looks good' : undefined })];
  if (d.txt) {
    const cov = d.coverage || [];
    const ok = cov.filter((c) => c.covered).length;
    out.push(h('div', { class: 'flex flex-wrap gap-2' },
      stat('Mode', pol ? pol.mode || 'n/a' : 'no policy', pol && pol.mode === 'enforce' ? 'protected' : pol ? 'not enforced' : 'file not read'),
      stat('max_age', pol && pol.max_age != null ? String(pol.max_age) : 'n/a', 'seconds cached'),
      stat('MX covered', cov.length ? `${ok} / ${cov.length}` : 'n/a', 'mail servers in the policy'),
      stat('id', d.id || 'n/a', 'changes with the policy')));
    out.push(h('div', null, h('div', { class: 'text-xs text-mute mb-1' }, `TXT record at _mta-sts.${res.target}`), codeBlock(d.txt, 'Copy')));
    if (d.policy_text) out.push(h('div', null, h('div', { class: 'text-xs text-mute mb-1' }, `Policy file: https://mta-sts.${res.target}/.well-known/mta-sts.txt`), codeBlock(d.policy_text, 'Copy')));
    if (cov.length) out.push(checkCard({ status: cov.every((c) => c.covered) ? 'ok' : 'warn', title: 'Does the policy cover every MX host?', body: coverage(cov),
      meaning: 'Each mail server in your MX records must match an mx: line in the policy. In enforce mode a server that is not listed will not receive mail from senders that support MTA-STS.' }));
  }
  out.push(...findingCards(res.findings));
  return out;
}

function rptSection(rpt, err) {
  const head = h('h2', { class: 'text-lg font-bold mt-2' }, 'TLS-RPT: delivery failure reports');
  if (err) return [head, errorCard(`The TLS-RPT lookup failed: ${err}`)];
  const d = rpt.data || {};
  const out = [head, resultVerdict(rpt, { title: d.record ? (rpt.status === 'pass' ? 'TLS-RPT is set up' : 'TLS-RPT needs attention') : 'No TLS-RPT record' })];
  if (d.record) {
    out.push(h('div', { class: 'flex flex-wrap gap-2' }, stat('Report addresses', String((d.rua || []).length), (d.rua || []).join(', ') || 'none')));
    out.push(h('div', null, h('div', { class: 'text-xs text-mute mb-1' }, `TXT record at _smtp._tls.${rpt.target}`), codeBlock(d.record, 'Copy')));
  }
  out.push(...findingCards(rpt.findings, { prefix: 'TLS-RPT:' }));
  return out;
}

async function render(res, ctx) {
  let rpt = null, err = null;
  try { rpt = await ctx.api('/mail/tls-rpt', { domain: res.target }); } catch (e) { err = e.message || String(e); }
  return [...stsSection(res), ...rptSection(rpt, err),
    nextSteps([{ slug: 'smtp-test', q: res.target, text: 'Test TLS on your mail servers' }, { slug: 'mx-lookup', q: res.target, text: 'Look up MX records' }])];
}

domainTool({ endpoint: '/mail/mta-sts', render });
