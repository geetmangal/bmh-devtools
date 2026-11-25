// Beginner / Expert toggle. Beginner shows verdict, plain meaning and fix steps; Expert also opens the
// technical details and shows a Raw JSON panel. Stored in localStorage (wrapped: it can throw).
import { store } from './dom.js';

const KEY = 'bmh-mode';
const listeners = new Set();

export function getMode() {
  return document.documentElement.dataset.mode === 'expert' ? 'expert' : 'beginner';
}

export function setMode(mode, persist = true) {
  mode = mode === 'expert' ? 'expert' : 'beginner';
  document.documentElement.dataset.mode = mode;
  if (persist) store.set('localStorage', KEY, mode);
  document.querySelectorAll('[data-mode-btn]').forEach((b) => {
    const on = b.dataset.modeBtn === mode;
    b.setAttribute('aria-pressed', String(on));
    b.classList.toggle('bg-accent', on);
    b.classList.toggle('text-white', on);
  });
  document.querySelectorAll('details.tech').forEach((d) => { d.open = mode === 'expert'; });
  listeners.forEach((fn) => fn(mode));
}

/** Subscribe to mode changes; returns an unsubscribe function. */
export function onMode(fn) { listeners.add(fn); return () => listeners.delete(fn); }

export function initMode() {
  const saved = store.get('localStorage', KEY);
  setMode(saved === 'expert' ? 'expert' : getMode(), false);
  document.querySelectorAll('[data-mode-btn]').forEach((b) => b.addEventListener('click', () => setMode(b.dataset.modeBtn)));
}
