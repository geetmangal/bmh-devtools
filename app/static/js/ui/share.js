// Share bar: copy the result link (?q=), copy the JSON, print (print CSS in assets/tools.css).
import { h, icon, copyText } from './dom.js';

let printHooked = false;
function hookPrint() {
  if (printHooked) return; printHooked = true;
  window.addEventListener('beforeprint', () => document.querySelectorAll('details.tech').forEach((d) => { d.dataset.wasOpen = d.open ? '1' : '0'; d.open = true; }));
  window.addEventListener('afterprint', () => document.querySelectorAll('details.tech').forEach((d) => { d.open = d.dataset.wasOpen === '1'; }));
}

/** shareBar({ getJson, getLink }) */
export function shareBar({ getJson, getLink } = {}) {
  hookPrint();
  const mk = (ic, text, fn) => {
    const b = h('button', { type: 'button', class: 'btn btn-ghost btn-sm inline-flex items-center gap-1.5' }, icon(ic, 14), h('span', null, text));
    b.addEventListener('click', async () => {
      const ok = await fn();
      const lab = b.querySelector('span'), prev = lab.textContent;
      if (ok !== undefined) { lab.textContent = ok ? 'Copied' : 'Copy failed'; setTimeout(() => { lab.textContent = prev; }, 1600); }
    });
    return b;
  };
  return h('div', { class: 'flex flex-wrap gap-2 no-print', role: 'group', 'aria-label': 'Share this result' },
    mk('share', 'Copy link', () => copyText(getLink ? getLink() : location.href)),
    getJson ? mk('json', 'Copy JSON', () => copyText(JSON.stringify(getJson(), null, 2))) : null,
    mk('print', 'Print / save PDF', () => { window.print(); }));
}
