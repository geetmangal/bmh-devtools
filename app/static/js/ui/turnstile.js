// Cloudflare Turnstile for heavy tools. When a heavy tool runs without a valid pass we lazy-load the Turnstile
// script (with this page's CSP nonce), render a managed widget inline in the result area, exchange the token
// for a signed 15-minute pass at POST /tools/api/v1/pass and retry. A 403 {"error":"pass_required"} clears the
// pass and challenges again. Pass is kept in sessionStorage (try/catch; falls back to memory).
import { h, store, icon } from './dom.js';

const KEY = 'bmh-pass', SRC = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
let mem = null, scriptP = null;

const sitekey = () => (document.body && document.body.dataset.turnstileSitekey) || '';
const apiBase = () => { try { return JSON.parse(document.getElementById('toolbox-config').textContent).api; } catch { return '/tools/api/v1'; } };

export function getPass() {
  let raw = mem;
  if (!raw) { try { raw = JSON.parse(store.get('sessionStorage', KEY) || 'null'); } catch { raw = null; } }
  return raw && raw.exp > Date.now() ? raw.pass : null;
}
export function clearPass() { mem = null; store.del('sessionStorage', KEY); }
function savePass(pass, expiresIn) {
  mem = { pass, exp: Date.now() + Math.max(30, expiresIn - 30) * 1000 };
  store.set('sessionStorage', KEY, JSON.stringify(mem));
}

function loadScript() {
  if (window.turnstile) return Promise.resolve();
  if (scriptP) return scriptP;
  const nonceEl = document.querySelector('script[nonce]');
  scriptP = new Promise((resolve, reject) => {
    const s = document.createElement('script');
    if (nonceEl && nonceEl.nonce) s.nonce = nonceEl.nonce;
    s.src = SRC; s.async = true; s.onload = () => resolve(); s.onerror = () => { scriptP = null; reject(new Error('Could not load the verification widget.')); };
    document.head.append(s);
  });
  return scriptP;
}

async function exchange(token) {
  const r = await fetch(apiBase() + '/pass', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
  const d = await r.json().catch(() => ({}));
  if (r.status === 503) throw new Error('The verification service is unreachable right now. Please try again in a minute.');
  if (!r.ok) throw new Error(typeof d.detail === 'string' ? d.detail : 'Verification failed.');
  savePass(d.pass, d.expires_in || 900);
  return d.pass;
}

export const turnstileEnabled = () => !!sitekey();

/** Explicit, reusable widget for strict tools (fresh token per run). mount(el) -> { token(), reset() }. */
export function mountWidget(el, { onChange } = {}) {
  let wid = null, tok = '';
  const set = (t) => { tok = t; if (onChange) onChange(!!t); };
  loadScript().then(() => {
    wid = window.turnstile.render(el, {
      sitekey: sitekey(),
      callback: (t) => set(t),
      'expired-callback': () => set(''),
      'timeout-callback': () => set(''),
      'error-callback': () => set(''),
    });
  }).catch(() => { el.textContent = 'The human check could not load. Reload the page and try again.'; });
  return {
    token: () => tok,
    reset: () => { set(''); try { if (wid != null) window.turnstile.reset(wid); } catch { /* widget gone */ } },
  };
}

/** Render the inline challenge in `container` and resolve with a fresh pass. */
function challenge(container) {
  const box = h('div', { class: 'card p-4', role: 'group', 'aria-label': 'Human check' },
    h('div', { class: 'flex items-center gap-2 font-semibold mb-2' }, icon('shield', 18), "Quick check that you're human…"),
    h('p', { class: 'text-sm text-mute mb-3' }, 'This stops bots from using our network tools. It usually takes a second and you only do it once per session.'));
  const slot = h('div'); box.append(slot);
  container.replaceChildren(box);
  return new Promise((resolve, reject) => {
    loadScript().then(() => {
      let wid;
      const done = () => { try { window.turnstile.remove(wid); } catch { /* already gone */ } box.remove(); };
      wid = window.turnstile.render(slot, {
        sitekey: sitekey(),
        callback: async (token) => { try { const p = await exchange(token); done(); resolve(p); } catch (e) { done(); reject(e); } },
        'error-callback': () => { reject(new Error('The human check failed to load. Reload the page and try again.')); },
        'timeout-callback': () => { reject(new Error('The human check timed out. Please run the check again.')); },
      });
    }).catch((e) => { box.remove(); reject(e); });
  });
}

export async function ensurePass(container, force = false) {
  if (!sitekey()) return null; // Turnstile not enabled on this server: no header needed
  if (!force) { const p = getPass(); if (p) return p; }
  return challenge(container);
}

/** fetch() for heavy endpoints: adds X-Tools-Pass and re-challenges once on 403 pass_required. */
export async function heavyFetch(url, init, container) {
  const attempt = async (force) => {
    const pass = await ensurePass(container, force);
    const headers = { ...(init.headers || {}) };
    if (pass) headers['X-Tools-Pass'] = pass;
    return fetch(url, { ...init, headers });
  };
  let r = await attempt(false);
  if (r.status === 403) {
    const j = await r.clone().json().catch(() => ({}));
    if (j && j.error === 'pass_required') { clearPass(); r = await attempt(true); }
  }
  return r;
}
