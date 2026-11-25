import { h, $, plural } from '../ui/dom.js';
import { initTool, apiGet } from '../ui/tool.js';
import { verdict } from '../ui/verdict.js';
import { checkCard } from '../ui/card.js';
import { tiles, donut } from '../ui/tiles.js';
import { dataTable } from '../ui/table.js';

const ipEl = $('#port-ip'), numEl = $('#port-num'), commonBtn = $('#port-common');
const STATE = { open: { status: 'ok', word: 'Open' }, closed: { status: 'bad', word: 'Closed' }, filtered: { status: 'warn', word: 'Filtered' }, error: { status: 'bad', word: 'Error' } };
const RISKY = { 22: 'SSH', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 21: 'FTP', 110: 'POP3', 143: 'IMAP' };

apiGet('/ports/myip').then((d) => { ipEl.value = d.ip + (d.public ? '' : ' (not a public address)'); }).catch(() => { ipEl.value = 'unknown'; });

function render(d) {
  const r = d.results, by = (s) => r.filter((x) => x.state === s);
  const open = by('open'), closed = by('closed'), filtered = by('filtered'), err = by('error');
  const single = r.length === 1 ? r[0] : null;
  const status = single ? (STATE[single.state] || STATE.error).status : open.length ? 'ok' : filtered.length ? 'warn' : 'info';
  const name = (x) => `${x.port}${x.service ? ' (' + x.service + ')' : ''}`;
  const summary = single
    ? `Port ${name(single)} on ${d.ip} is ${single.state}${single.state === 'open' ? `: a connection was accepted in ${single.ms} ms.` : single.state === 'closed' ? ': the machine answered that nothing is listening there.' : single.state === 'filtered' ? ': nothing answered within 3 seconds, which usually means a firewall is dropping the traffic.' : '.'}`
    : `${plural(open.length, 'port')} open, ${closed.length} closed and ${filtered.length} filtered out of ${r.length} checked on ${d.ip}.`;
  const out = [verdict({ status, title: single ? `Port ${single.port} is ${STATE[single.state].word.toLowerCase()}` : `${open.length} of ${r.length} ports open`, summary, meta: d.note })];

  out.push(checkCard({
    status: 'info', title: 'Port results',
    body: h('div', { class: 'space-y-4' },
      r.length > 1 ? donut({ center: String(open.length), caption: 'open ports', segments: [{ value: open.length, status: 'ok', label: 'open' }, { value: closed.length, status: 'bad', label: 'closed' }, { value: filtered.length, status: 'warn', label: 'filtered' }, { value: err.length, status: 'mute', label: 'error' }] }) : null,
      tiles({ min: '10.5rem', items: r.map((x) => ({ label: `${x.port}`, sub: x.service || 'unknown service', status: (STATE[x.state] || STATE.error).status, word: `${(STATE[x.state] || STATE.error).word}${x.ms != null ? ` - ${x.ms} ms` : ''}` })) })),
    meaning: 'Open: something accepted the connection. Closed: the machine answered that nothing listens there. Filtered: no answer at all, usually a firewall silently dropping the traffic.',
    details: dataTable(['Port', 'Service', 'State', 'Time'], r.map((x) => [x.port, x.service || '', x.state, x.ms != null ? x.ms + ' ms' : '']), { mono: [0, 2, 3] }),
  }));

  const risky = open.filter((x) => RISKY[x.port]);
  if (risky.length) {
    out.push(checkCard({ status: 'warn', title: `${risky.map((x) => RISKY[x.port]).join(', ')} ${risky.length > 1 ? 'are' : 'is'} reachable from the whole internet`,
      meaning: 'Admin and database services should not be open to everyone: bots probe them all day for weak passwords and known bugs.',
      fix: { steps: ['Restrict the port to your own IP addresses in the server firewall or the cloud security group.', 'For SSH, use keys instead of passwords; for databases, bind to localhost or a private network.'] } }));
  }
  const want = single && single.state !== 'open' ? single : null;
  if (want) {
    out.push(checkCard({ status: want.state === 'filtered' ? 'warn' : 'bad', title: `Why port ${want.port} is not open`,
      meaning: want.state === 'closed' ? 'The server is reachable, but no program is listening on this port.' : 'The packets were silently dropped, so a firewall (on the server, your cloud security group or your router) is probably blocking it.',
      fix: { steps: ['Check the service is running and listening on a public address (for example with ss -ltnp on Linux).', 'Allow the port in the server firewall, the cloud security group and, at home, a router port-forward.', 'Behind CGNAT or a VPN the IP shown above is not your machine, so the test cannot reach it.'], code: 'ss -ltnp | grep :' + want.port, codeLabel: 'Copy command' } }));
  }
  return out;
}

const tool = initTool({
  heavy: true, // Turnstile: prefill only, the visitor presses the button
  form: '#port-form', buttons: ['#port-common'],
  run(ctx) {
    const port = parseInt(numEl.value, 10);
    if (ctx.common) return ctx.api('/ports/check', { common: true }, { heavy: true });
    if (!(port >= 1 && port <= 65535)) throw new Error('Enter a port between 1 and 65535.');
    return ctx.api('/ports/check', { port }, { heavy: true });
  },
  render,
});
commonBtn.addEventListener('click', () => tool.execute({ common: true }));
