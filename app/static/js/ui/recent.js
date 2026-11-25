/* Recently used tools (localStorage "bmh-recent"), newest first, max 6. */
const KEY = 'bmh-recent';
const MAX = 6;

export function getRecent() {
  try {
    const v = JSON.parse(localStorage.getItem(KEY) || '[]');
    return Array.isArray(v) ? v.filter((s) => typeof s === 'string').slice(0, MAX) : [];
  } catch { return []; }
}

export function pushRecent(slug) {
  try {
    const next = [slug, ...getRecent().filter((s) => s !== slug)].slice(0, MAX);
    localStorage.setItem(KEY, JSON.stringify(next));
  } catch { /* storage unavailable */ }
}
