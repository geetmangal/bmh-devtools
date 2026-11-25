import { h, $, plural, fmtMs } from '../ui/dom.js';
import { initTool, qParam } from '../ui/tool.js';
import { verdict } from '../ui/verdict.js';
import { checkCard } from '../ui/card.js';
import { dataTable } from '../ui/table.js';
import { st, bySeverity, stat, nextSteps } from '../ui/findings.js';

const el = $('#tool-input');

const GRADE_STATUS = { A: 'ok', B: 'ok', C: 'warn', D: 'warn', F: 'bad' };
const TITLE = { A: 'Strong security headers', B: 'Good, a few headers missing', C: 'Several headers missing', D: 'Weak security headers', F: 'Security headers missing' };

function findingCard(f) {
  const tabs = f.fix_tabs && f.fix_tabs.length ? f.fix_tabs : null;
  const fix = (f.fix && f.fix.length) || tabs ? { steps: f.fix || [], tabs } : null;
  return checkCard({ status: st(f.status), title: f.title, meaning: f.meaning, fix, details: f.details && Object.keys(f.details).length ? f.details : undefined });
}

function hopsTable(hops) {
  const rows = hops.map((x, i) => [String(i + 1), x.status == null ? 'not followed' : String(x.status), x.url,
    x.error ? 'Stopped: ' + x.error : (x.location || (x.status != null && x.status < 300 ? 'final page' : '')), x.ms == null ? '' : fmtMs(x.ms)]);
  return dataTable(['#', 'Status', 'URL', 'Next (Location)', 'Time'], rows, { mono: [1, 2, 3] });
}

function render(d) {
  const g = d.grade;
  const worst = st(d.status);
  const vStatus = g ? (worst === 'bad' && GRADE_STATUS[g.grade] === 'ok' ? 'warn' : GRADE_STATUS[g.grade]) : worst;
  const out = [verdict({ status: vStatus, grade: g ? g.grade : undefined, score: g ? g.score : undefined,
    title: g ? TITLE[g.grade] : 'Could not reach a final page', summary: d.summary, meta: `${d.final_url}${d.tls && d.tls.version ? ' - ' + d.tls.version : ''}` })];

  out.push(h('div', { class: 'flex flex-wrap gap-2' },
    stat('Redirects', String(d.flags.redirect_count), plural(d.hops.length, 'request')),
    stat('Final status', d.final_status == null ? 'n/a' : String(d.final_status), d.final_url.startsWith('https://') ? 'HTTPS' : 'plain HTTP'),
    g ? stat('Header score', `${g.score} / 100`, `grade ${g.grade}`) : null));

  out.push(checkCard({
    status: d.flags.loop || d.flags.too_many_hops ? 'bad' : d.flags.blocked || d.flags.no_https_redirect || d.flags.temporary_redirects.length || d.flags.long_chain ? 'warn' : 'ok',
    title: d.flags.redirect_count ? `Redirect chain: ${plural(d.flags.redirect_count, 'redirect')}` : 'No redirects: the first answer is the final page',
    body: hopsTable(d.hops),
    meaning: 'Each line is one request. A redirect answers with a 3xx status and the next address in the Location header. The tool follows up to 8 requests and only to public web addresses.',
  }));

  if (g) {
    out.push(checkCard({
      status: GRADE_STATUS[g.grade], title: `Security header grade ${g.grade} (${g.score} of 100)`,
      body: dataTable(['Header', 'Points', 'Result'], g.checks.map((c) => [c.label, `${c.points} / ${c.max}`, c.note]), { mono: [] }),
      meaning: 'Six headers are scored: HSTS (25), Content-Security-Policy (25), X-Content-Type-Options (15), clickjacking protection by X-Frame-Options or frame-ancestors (15), Referrer-Policy (10) and Permissions-Policy (10). A site served over plain HTTP is capped at F.',
    }));
  }
  out.push(...[...d.findings].sort(bySeverity).map(findingCard));

  if (d.headers && Object.keys(d.headers).length) {
    out.push(checkCard({ status: 'info', title: 'Response headers of the final page', details: dataTable(['Header', 'Value'], Object.entries(d.headers), { mono: [0, 1] }),
      meaning: 'Only well-known headers are shown. Cookies and other private headers are never returned.' }));
  }
  const host = (() => { try { return new URL(d.final_url).hostname; } catch { return ''; } })();
  out.push(nextSteps([{ slug: 'ttfb-ssl-checker', q: host, text: 'Check speed and certificate' }, { slug: 'dns-lookup', q: host, text: 'Look up DNS records' }]));
  return out;
}

initTool({
  form: '#tool-form',
  run: (ctx) => ctx.api('/http/headers', { url: el.value.trim() }),
  render,
  state: () => ({ q: el.value.trim() }),
  prefill: (p) => { const q = qParam(p, 'url', 'domain'); if (q) el.value = q; return !!q; },
});
