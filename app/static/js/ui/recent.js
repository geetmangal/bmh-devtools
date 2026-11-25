// Recently used tools, kept in localStorage ("bmh-recent"), newest first, unique, max 6.
// Every access is wrapped: storage can be blocked (private mode, embeds, disabled cookies).
const KEY = 'bmh-recent';
const MAX = 6;

export function getRecent() {
  try {
    const v = JSON.parse(localStorage.getItem(KEY) || '[]');
    return Array.isArray(v) ? v.filter((s) => typeof s === 'string').slice(0, MAX) : [];
  } catch { return []; }
}

export function pushRecent(slug) {
  if (!slug || typeof slug !== 'string') return;
  try {
    const next = [slug, ...getRecent().filter((s) => s !== slug)].slice(0, MAX);
    localStorage.setItem(KEY, JSON.stringify(next));
  } catch { /* storage unavailable: recents are optional */ }
}
