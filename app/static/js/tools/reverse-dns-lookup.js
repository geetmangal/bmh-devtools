import { h, $, icon, statusOf } from '../ui/dom.js';
import { initTool, qParam } from '../ui/tool.js';
import { verdict } from '../ui/verdict.js';
import { checkCard } from '../ui/card.js';
import { dataTable } from '../ui/table.js';

const ipEl = $('#rdns-ip');

/** IP -> PTR hostname -> forward IPs: three boxes with a tick or cross on each arrow. */
function flow(ip, p) {
  const box = (label, value, st) => h('div', { class: `tile ${statusOf(st).tile} flex-1 min-w-[10rem]` }, h('div', { class: 'text-xs text-mute' }, label), h('div', { class: 'mono text-sm break-all' }, value));
  const arrow = (ok, text) => h('div', { class: 'flex flex-col items-center justify-center px-1 text-xs', 'aria-hidden': 'true' }, h('span', { class: ok ? 'st-ok' : 'st-bad' }, icon(ok ? 'ok' : 'bad', 18)), h('span', { class: 'text-mute' }, text));
  return h('div', { class: 'flex flex-wrap items-stretch gap-1' },
    box('IP address', ip, 'info'), arrow(true, 'PTR'),
    box('PTR hostname', p.hostname, 'info'), arrow(p.forward_confirmed, 'A / AAAA'),
    box('Resolves back to', p.forward_ips.join(', ') || 'no address', p.forward_confirmed ? 'ok' : 'bad'));
}

function render(d) {
  const has = d.ptr.length > 0;
  const status = d.fcrdns ? 'ok' : has ? 'warn' : 'bad';
  const generic = d.ptr.filter((p) => p.generic);
  const out = [verdict({
    status, title: d.fcrdns ? 'Reverse DNS is correct' : has ? 'PTR exists, but does not match' : 'No PTR record',
    summary: d.fcrdns ? `${d.ip} has a PTR record whose hostname resolves back to the same address, which is what mail servers look for.` : has ? `${d.ip} has a PTR record, but its hostname does not resolve back to ${d.ip}, so mail servers may treat it as suspicious.` : `${d.ip} has no PTR record, so receiving mail servers cannot confirm who owns this address.`,
    meta: d.reverse_name,
  })];

  out.push(checkCard({
    status: has ? 'ok' : 'bad', title: has ? `PTR record found: ${d.ptr.map((p) => p.hostname).join(', ')}` : 'No PTR record found',
    meaning: has ? 'A PTR record is the reverse of an A or AAAA record: it names the host behind an IP address.' : 'Nobody has published a name for this address. The owner of the IP block (usually your hosting provider) controls this record.',
    fix: has ? null : { steps: ['Set the PTR (reverse DNS) in your hosting control panel, or ask your provider to set it; you cannot set it at your domain\'s DNS host.', 'Use the same hostname as your mail server\'s HELO name, for example mail.example.com.', 'Make sure that hostname has an A (or AAAA) record pointing at this IP, then run this check again.'] },
    details: d.reverse_name,
  }));

  if (has) {
    const bad = d.ptr.filter((p) => !p.forward_confirmed);
    out.push(checkCard({
      status: d.fcrdns ? 'ok' : 'warn', title: d.fcrdns ? 'Forward-confirmed: the hostname points back to this IP' : 'Forward check failed: the hostname does not point back to this IP',
      body: h('div', { class: 'space-y-3' }, d.ptr.map((p) => flow(d.ip, p))),
      meaning: d.fcrdns ? 'The PTR hostname resolves (A or AAAA) to this same IP. This is called FCrDNS and it shows the owner controls both sides.' : 'The hostname in the PTR record resolves to a different address, or to none. Mail servers often reject or spam-fold mail from such addresses.',
      fix: d.fcrdns ? null : { steps: [`Add an ${d.ip.includes(':') ? 'AAAA' : 'A'} record for ${bad[0] ? bad[0].hostname : 'your hostname'} that points to ${d.ip}.`, 'Or change the PTR so that it names a hostname which already points here.', 'DNS changes can take a few minutes to show up; run the check again to confirm.'], code: bad[0] ? `${bad[0].hostname}. 300 IN ${d.ip.includes(':') ? 'AAAA' : 'A'} ${d.ip}` : null, codeLabel: 'Copy record' },
      details: dataTable(['PTR hostname', 'Resolves to', 'Match'], d.ptr.map((p) => [p.hostname, p.forward_ips.join(', ') || 'none', p.forward_confirmed ? 'yes' : 'no']), { mono: [0, 1] }),
    }));
  }
  if (generic.length) {
    out.push(checkCard({ status: 'warn', title: 'The PTR hostname looks like a generic ISP name',
      meaning: `Names such as ${generic[0].hostname} (made from the IP address itself) tell receivers this is a consumer or default address. Mail providers treat mail from them with suspicion.`,
      fix: { steps: ['Replace it with a real hostname you control, such as mail.yourdomain.com.', 'Then point that hostname back at this IP with an A or AAAA record.'] } }));
  }
  const noteKids = [d.mail_note];
  const guide = d.guide_url || $('#results').dataset.guideUrl;
  if (guide) noteKids.push(' ', h('a', { href: guide }, 'How to set a PTR record on a VPS'), '.');
  out.push(checkCard({ status: 'info', title: 'Why this matters for email', body: h('p', { class: 'text-sm' }, ...noteKids) }));
  return out;
}

initTool({
  form: '#rdns-form',
  run: (ctx) => ctx.api('/rdns/lookup', { ip: ipEl.value.trim() }),
  render,
  state: (d) => ({ q: d.ip }),
  prefill: (p) => { const q = qParam(p, 'ip'); if (q) ipEl.value = q; return !!q; },
});
