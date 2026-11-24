import { h, $, plural, fmtMs } from '../ui/dom.js';
import { initTool, qParam } from '../ui/tool.js';
import { verdict } from '../ui/verdict.js';
import { checkCard } from '../ui/card.js';
import { gauge } from '../ui/gauge.js';
import { timeline } from '../ui/timeline.js';
import { dataTable } from '../ui/table.js';

const targetEl = $('#lg-target'), toolEl = $('#lg-tool');

/** Phase 3 hook: enrich each hop with ASN / organisation / geo (RIPEstat) before drawing. Currently a no-op. */
async function enrichHops(hops) { return hops; }

const rttStatus = (ms) => (ms < 80 ? 'ok' : ms < 200 ? 'warn' : 'bad');
const rttWords = (ms) => (ms < 30 ? 'excellent' : ms < 80 ? 'good' : ms < 200 ? 'noticeable' : 'slow');

function renderPing(d) {
  const s = d.summary || {}, r = s.rtt_ms;
  const loss = s.loss_pct ?? (d.reachable ? 0 : 100);
  const status = !d.reachable ? 'bad' : loss > 0 ? 'warn' : 'ok';
  const where = d.source.label;
  const summary = d.reachable
    ? `${d.target} answered ${s.received} of ${s.sent} pings ${where}${r ? ` with an average round trip of ${r.avg} ms` : ''}${loss > 0 ? `; ${loss}% of packets were lost` : ''}.`
    : `${d.target} did not answer any of the pings sent ${where}${d.timed_out ? ' (the test timed out)' : ''}.`;
  const out = [verdict({ status, title: !d.reachable ? 'No reply' : loss > 0 ? 'Reachable, with packet loss' : 'Reachable', summary, meta: `${d.target} - ${d.resolved_ip}` })];
  out.push(checkCard({
    status: d.reachable ? 'ok' : 'bad', title: d.reachable ? 'The target replies to ping' : 'The target does not reply to ping',
    meaning: d.reachable ? 'Packets reached the address and came back, so it is online and routed.' : 'No reply came back. The server may be down, or it may simply block ping (ICMP) while still serving websites and other services.',
    fix: d.reachable ? null : { steps: ['Try a traceroute to see where the path stops.', 'Check the server is running and its firewall allows ICMP echo (ping).', 'If it is a web server, test the site itself with the TTFB & SSL checker; many hosts hide ping on purpose.'] },
    details: d.output,
  }));
  if (r) {
    out.push(checkCard({
      status: rttStatus(r.avg), title: `Round-trip time is ${rttWords(r.avg)}: ${r.avg} ms on average`,
      body: h('div', { class: 'flex flex-wrap items-center gap-5' }, gauge({ value: Math.min(r.avg, 300), max: 300, label: String(r.avg), unit: 'ms avg', status: rttStatus(r.avg), semi: true, size: 150, sr: `Average round-trip time ${r.avg} milliseconds` }),
        h('dl', { class: 'grid grid-cols-3 gap-x-6 text-sm' }, ...[['Fastest', r.min], ['Average', r.avg], ['Slowest', r.max]].flatMap(([k, v]) => [h('dt', { class: 'text-mute col-span-3 sm:col-span-1 text-xs' }, k), h('dd', { class: 'mono m-0 col-span-3 sm:col-span-1 font-semibold' }, fmtMs(v))]))),
      meaning: 'This is the time for a packet to travel from our Noida network to the target and back (RTT). Distance sets the floor: roughly 1 ms per 100 km of fibre each way, plus routing and queuing.',
      fix: r.avg >= 200 ? { steps: ['If this target is your server, a location closer to your visitors (for Indian users, a server in India) cuts most of this delay.', 'Run a traceroute to see which hop adds the time.'] } : null,
    }));
  }
  if (d.reachable) {
    out.push(checkCard({
      status: loss === 0 ? 'ok' : 'warn', title: loss === 0 ? 'No packet loss' : `Packet loss: ${loss}%`,
      meaning: loss === 0 ? 'Every test packet got a reply.' : 'Some packets got no reply. A little loss on a short test can be a one-off, but loss that keeps showing up means congestion or a faulty link somewhere on the path.',
      fix: loss === 0 ? null : { steps: ['Run the test again a few times to see if the loss is steady.', 'Run a traceroute: loss that starts at one hop and continues to the end is a real problem at that hop.'] },
    }));
  }
  return out;
}

async function renderTrace(d) {
  const hops = await enrichHops(d.hops);
  const answered = hops.filter((x) => x.rtt_ms != null);
  const silent = hops.length - answered.length;
  const last = answered.length ? answered[answered.length - 1] : null;
  const status = d.reached ? 'ok' : 'warn';
  const summary = d.reached
    ? `Packets ${d.source.label} reach ${d.target} in ${plural(hops.length, 'hop')}${last ? `, ${last.rtt_ms} ms at the end` : ''}${silent ? `; ${plural(silent, 'router')} on the way did not reply, which is normal` : ''}.`
    : `The path ${d.source.label} to ${d.target} was followed for ${plural(hops.length, 'hop')}, but the destination itself did not answer (filtered or timed out).`;
  let prev = 0;
  const steps = hops.map((x) => {
    const jump = x.rtt_ms != null && x.rtt_ms - prev > 60 && prev > 0;
    if (x.rtt_ms != null) prev = x.rtt_ms;
    return { label: x.ip || '*', sub: `hop ${x.hop}${x.ip && x.ip === d.resolved_ip ? ' (destination)' : ''}${jump ? ' - latency jumps here' : ''}`, ms: x.rtt_ms, status: x.rtt_ms == null ? 'mute' : jump ? 'warn' : rttStatus(x.rtt_ms), note: x.rtt_ms == null ? 'no reply (100% loss)' : null };
  });
  return [
    verdict({ status, title: d.reached ? 'Destination reached' : 'Destination did not answer', summary, meta: `${d.target} - ${d.resolved_ip} - max ${d.max_hops} hops` }),
    checkCard({ status, title: `Path to the target: ${plural(hops.length, 'hop')}`, body: timeline({ steps }),
      meaning: 'Each line is one router your packets pass through, with the time to get a reply from it. Bars that grow sharply mean the packet crossed a long link (often an ocean or a different network).',
      details: d.output }),
    silent ? checkCard({ status: d.reached ? 'info' : 'warn', title: `${plural(silent, 'hop')} showed a star (no reply)`,
      meaning: d.reached ? 'Many routers do not answer or rate-limit these probes. A star in the middle is harmless as long as later hops answer.' : 'The probes stopped getting answers. The next router may be filtering traffic, or the target itself blocks these probes.',
      fix: d.reached ? null : { steps: ['Check the target\'s firewall allows UDP/ICMP probes, or test the real service port with the Open Port Checker.', 'Ask your provider whether the last answering hop belongs to their network.'] } }) : null,
  ];
}

function renderBgp(d) {
  const origins = d.origin_asns || [];
  const status = d.announced ? 'ok' : 'bad';
  const summary = d.announced
    ? `${d.target} (${d.ip}) is inside ${d.prefix}, which is announced to the internet${origins.length ? ' by ' + origins.map((a) => `${a.asn}${a.holder ? ' (' + a.holder + ')' : ''}`).join(', ') : ''}.`
    : `No BGP announcement covers ${d.ip}, so this address is not reachable from the public internet.`;
  return [
    verdict({ status, title: d.announced ? 'Announced' : 'Not announced', summary, meta: `${d.source.name}. ${d.source.note}` }),
    checkCard({ status, title: d.announced ? `Prefix ${d.prefix} is visible in global routing` : 'No route found for this address',
      body: origins.length ? h('div', { class: 'flex flex-wrap gap-2' }, origins.map((a) => h('span', { class: 'pill pill-info mono' }, `${a.asn} ${a.holder || ''}`.trim()))) : null,
      meaning: d.announced ? 'The network that owns this block tells the rest of the internet (using BGP) that it can deliver traffic to it. The AS shown is the origin: the network that announces the prefix.' : 'Either the block is unused, withdrawn, or the data source has not seen it. Traffic to it will not arrive.',
      fix: d.announced ? null : { steps: ['If this is your block, ask your upstream whether the prefix is announced and not filtered.', 'Check that RPKI and IRR records exist for the prefix so providers accept it.'] } }),
    (d.paths || []).length ? checkCard({ status: 'info', title: `${plural(d.paths.length, 'route collector')} show how to reach it`,
      meaning: 'An AS path lists the networks traffic passes through, ending at the origin. Shorter paths are usually preferred.',
      details: dataTable(['Collector', 'AS path'], d.paths.map((x) => [`${x.collector} ${x.location}`, x.as_path]), { mono: [1] }) }) : null,
  ];
}

initTool({
  form: '#lg-form',
  async run(ctx) {
    const target = targetEl.value.trim(), tool = toolEl.value;
    const data = tool === 'bgp' ? await ctx.api('/lg/bgp', { target }, { heavy: true }) : await ctx.api('/lg/run', { target, tool }, { heavy: true });
    return { ...data, _tool: tool };
  },
  render: (d) => (d._tool === 'bgp' ? renderBgp(d) : d._tool === 'ping' ? renderPing(d) : renderTrace(d)),
  state: (d) => ({ q: targetEl.value.trim(), tool: d._tool }),
  prefill: (p) => {
    const q = qParam(p, 'target');
    if (['ping', 'traceroute', 'bgp'].includes(p.get('tool'))) toolEl.value = p.get('tool');
    if (q) targetEl.value = q;
    return !!q;
  },
});
