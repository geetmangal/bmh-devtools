// "Next steps" block under a result. Listens for the bmh:result event ({slug, input, verdict}) that ui/tool.js
// dispatches, takes the page's related tools from the server-rendered [data-related] list, and links to each with
// the same input carried over as ?q= when that tool accepts it. DOM is built with h(): never raw HTML from data.
import { h } from './dom.js';
import { detect, chipsFor, paramsFor } from './detect.js';

const cfg = (() => { try { return JSON.parse(document.getElementById('toolbox-config').textContent); } catch { return { prefix: '/tools', tools: [] }; } })();
const TOOLS = cfg.tools || [];
const MAX = 3;
const GENERATOR = 'spf-dmarc-generator';
const FIX_FIRST = ['spf-checker', 'dmarc-checker'];

const slugOf = (href) => String(href || '').split(/[?#]/)[0].replace(/\/+$/, '').split('/').pop();
const find = (slug) => TOOLS.find((t) => t.slug === slug);

/** Related tools from the page: [{slug, name, blurb}] (own slug excluded). */
function relatedFromDom(own) {
  return [...document.querySelectorAll('[data-related] a')].map((a) => {
    const li = a.closest('li');
    const blurb = li ? li.querySelector('span') : null;
    return { slug: slugOf(a.getAttribute('href')), name: a.textContent.trim(), blurb: blurb ? blurb.textContent.trim() : '' };
  }).filter((r) => r.slug && r.slug !== own);
}

/** Build the ordered candidate list for a result. */
export function pickNext({ slug, verdict }, related) {
  const list = related.slice();
  if ((verdict === 'bad' || verdict === 'warn') && FIX_FIRST.includes(slug)) {
    const g = find(GENERATOR);
    if (g) {
      const i = list.findIndex((r) => r.slug === GENERATOR);
      const item = i >= 0 ? list.splice(i, 1)[0] : { slug: GENERATOR, name: g.name, blurb: g.short || '' };
      list.unshift(item);
    }
  }
  return list.filter((r) => (r.slug === GENERATOR ? !!find(GENERATOR) : true)).slice(0, MAX);
}

function href(slug, input) {
  const base = `${cfg.prefix}/${slug}`;
  const t = find(slug);
  if (!input || !t) return base;
  const det = detect(input);
  if (!chipsFor(det, [t]).length) return base; // tool does not take this kind of input
  return `${base}?${new URLSearchParams(paramsFor(slug, det)).toString()}`;
}

export function renderNextSteps({ slug, input, verdict }) {
  const prev = document.getElementById('next-steps');
  if (prev) prev.remove();
  const out = document.getElementById('results');
  if (!out) return;
  const items = pickNext({ slug, verdict }, relatedFromDom(slug));
  if (!items.length) return;
  const fixing = items[0].slug === GENERATOR;
  const cards = items.map((r, n) => {
    const t = find(r.slug);
    const lead = fixing && n === 0 ? 'Fix it' : (r.blurb || (t && t.short) || '');
    return h('a', { href: href(r.slug, input), class: 'card p-3 block no-underline', 'data-next-slug': r.slug },
      h('span', { class: 'font-semibold block' }, (t && t.name) || r.name),
      lead ? h('span', { class: 'text-mute text-sm block' }, lead) : null);
  });
  out.after(h('section', { id: 'next-steps', class: 'mt-4 no-print', 'aria-label': 'Next steps' },
    h('h2', { class: 'text-sm font-bold uppercase tracking-wide text-mute mb-2' }, 'Next steps'),
    h('div', { class: 'grid gap-2 sm:grid-cols-3' }, ...cards)));
}

document.addEventListener('bmh:result', (e) => { try { renderNextSteps(e.detail || {}); } catch { /* never break the result page */ } });
