import { h, $, clear, plural, fmtMs, icon, srOnly } from '../ui/dom.js';
import { initTool, qParam } from '../ui/tool.js';
import { verdict } from '../ui/verdict.js';
import { checkCard } from '../ui/card.js';
import { gauge } from '../ui/gauge.js';
import { progressBar } from '../ui/stream.js';
import { hopTimeline, traceMap } from '../viz/tracemap.js';
import { dataTable } from '../ui/table.js';

const targetEl = $('#lg-target'), toolEl = $('#lg-tool'), fromEl = $('#lg-from');
const NOIDA = { lat: 28.57, lon: 77.32, label: 'BMH Noida' };

/** The server already adds ASN, organisation and location to each hop (hopenrich); this keeps the hook for callers. */
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
  return [
    verdict({ status, title: d.reached ? 'Destination reached' : 'Destination did not answer', summary: summary + (d.path_summary ? ' ' + d.path_summary : ''), meta: `${d.target} - ${d.resolved_ip} - max ${d.max_hops} hops` }),
    checkCard({ status, title: `Path to the target: ${plural(hops.length, 'hop')}`, body: hopTimeline({ hops, segments: d.segments, destination: d.resolved_ip }),
      meaning: 'Each line is one router your packets pass through, with the time to get a reply from it. Bars that grow sharply mean the packet crossed a long link (often an ocean or a different network).',
      details: d.output }),
    mapCard(hops),
    silent ? checkCard({ status: d.reached ? 'info' : 'warn', title: `${plural(silent, 'hop')} showed a star (no reply)`,
      meaning: d.reached ? 'Many routers do not answer or rate-limit these probes. A star in the middle is harmless as long as later hops answer.' : 'The probes stopped getting answers. The next router may be filtering traffic, or the target itself blocks these probes.',
      fix: d.reached ? null : { steps: ['Check the target\'s firewall allows UDP/ICMP probes, or test the real service port with the Open Port Checker.', 'Ask your provider whether the last answering hop belongs to their network.'] } }) : null,
  ];
}

function mapCard(hops) {
  const m = traceMap(hops, { source: NOIDA });
  return m ? checkCard({ status: 'info', title: 'Where the path goes', body: m,
    meaning: 'The dots follow the hops in order. Private addresses and addresses we cannot place are left out, so the line can skip steps.' }) : null;
}

const LOCS = { india: 'India', asia: 'Asia', europe: 'Europe', 'north america': 'North America', world: 'Worldwide' };
const heat = (ms) => (ms == null ? 'mute' : rttStatus(ms));

/** Multi-location run through Globalping: a row per probe fills in as results arrive, with a latency heat strip. */
async function runGlobal(ctx, target, type, preset) {
  const rows = [], tbody = h('tbody');
  const bar = progressBar({ total: 6, noun: 'locations answered' });
  const table = h('div', { class: 'overflow-x-auto' }, h('table', null, h('thead', null, h('tr', null, ['Location', 'Network', 'Latency', 'Loss'].map((x) => h('th', { scope: 'col' }, x)))), tbody));
  const el = h('div', { class: 'space-y-3' }, bar.el, table);
  let total = 6;
  await ctx.stream('/lg/global', { target, type, preset, limit: 6 }, {
    onStart: () => clear(ctx.out).append(el),
    onItem: (o) => {
      if (o.type === 'created' && o.probes_count) { total = o.probes_count; bar.update(0, total); }
      if (o.type !== 'probe') return;
      const r = o.probe || {}, loc = r.probe || {}, st = r.stats || {};
      const last = (r.hops || []).length ? r.hops[r.hops.length - 1] : null;
      const avg = st.avg ?? (last?.timings?.length ? last.timings.reduce((a, t) => a + (t.rtt || 0), 0) / last.timings.length : null);
      rows.push({ loc, avg, loss: st.loss ?? null, status: r.status, hops: (r.hops || []).length });
      const s = heat(avg);
      tbody.append(h('tr', null, h('td', null, [loc.city, loc.country].filter(Boolean).join(', ') || 'Unknown'), h('td', { class: 'mono text-xs' }, loc.asn ? `AS${loc.asn} ${loc.network || ''}` : loc.network || ''),
        h('td', null, h('div', { class: 'flex items-center gap-2' }, h('div', { class: 'bar-track h-2.5 w-24', 'aria-hidden': 'true' }, h('div', { class: 'h-2.5 rounded-full', style: `width:${avg == null ? 0 : Math.min(100, (avg / 300) * 100)}%;background:var(--${s === 'mute' ? 'mute' : s})` })),
          h('span', { class: 'mono text-xs' }, avg == null ? (r.status === 'failed' ? 'failed' : 'no data') : fmtMs(avg)), avg != null ? h('span', { class: `text-xs st-${s}` }, rttWords(avg)) : null)),
        h('td', { class: 'mono text-xs' }, st.loss != null ? `${st.loss}%` : '')));
      bar.update(rows.length, total);
    },
  });
  bar.finish();
  return { target, type, preset, rows, _el: el };
}

function renderGlobal(d) {
  const ok = d.rows.filter((r) => r.avg != null);
  const best = ok.length ? ok.reduce((a, b) => (b.avg < a.avg ? b : a)) : null, worst = ok.length ? ok.reduce((a, b) => (b.avg > a.avg ? b : a)) : null;
  const status = !ok.length ? 'bad' : worst.avg >= 200 ? 'warn' : 'ok';
  const where = (r) => [r.loc.city, r.loc.country].filter(Boolean).join(', ');
  const summary = ok.length ? `${d.target} answered from ${ok.length} of ${d.rows.length} locations (${LOCS[d.preset] || d.preset}). Fastest: ${where(best)} at ${fmtMs(best.avg)}. Slowest: ${where(worst)} at ${fmtMs(worst.avg)}.` : `No location got an answer from ${d.target}.`;
  return [verdict({ status, title: ok.length ? 'Reachable from other locations' : 'No answer from any location', summary, meta: `${d.type} from ${LOCS[d.preset] || d.preset} via Globalping` }),
    checkCard({ status: 'info', title: 'Latency by location', body: d._el,
      meaning: 'Each row is a different probe somewhere in the world running the same test against your target. Bigger latency for far-away places is normal; a nearby place that is much slower than its neighbours points to a routing problem.',
      details: 'Measured by the Globalping network (globalping.io), a community probe network. Probes are volunteers\' devices, so their quality varies.' }),
    srOnly(d.rows.map((r) => `${where(r)}: ${r.avg == null ? 'no data' : fmtMs(r.avg)}`).join('; '))];
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
  heavy: true, // Turnstile: prefill only, the visitor presses the button
  form: '#lg-form',
  async run(ctx) {
    const target = targetEl.value.trim(), tool = toolEl.value, from = fromEl ? fromEl.value : 'local';
    if (tool !== 'bgp' && from !== 'local') {
      const g = await runGlobal(ctx, target, tool, from);
      const res = { target: g.target, type: g.type, preset: g.preset, rows: g.rows, _tool: 'global', _from: from };
      Object.defineProperty(res, '_el', { value: g._el, enumerable: false });
      return res;
    }
    const data = tool === 'bgp' ? await ctx.api('/lg/bgp', { target }, { heavy: true }) : await ctx.api('/lg/run', { target, tool }, { heavy: true });
    return { ...data, _tool: tool };
  },
  render: (d) => (d._tool === 'global' ? renderGlobal(d) : d._tool === 'bgp' ? renderBgp(d) : d._tool === 'ping' ? renderPing(d) : renderTrace(d)),
  state: (d) => ({ q: targetEl.value.trim(), tool: d._tool === 'global' ? toolEl.value : d._tool, ...(d._from && d._from !== 'local' ? { from: d._from } : {}) }),
  prefill: (p) => {
    const q = qParam(p, 'target');
    if (['ping', 'traceroute', 'bgp'].includes(p.get('tool'))) toolEl.value = p.get('tool');
    if (fromEl && [...fromEl.options].some((o) => o.value === p.get('from'))) fromEl.value = p.get('from');
    if (q) targetEl.value = q;
    return !!q;
  },
});
