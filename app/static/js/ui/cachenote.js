// One shared note under a result: tells the visitor whether it came from the short server cache and how old it is.
import { h } from './dom.js';

/** cacheNote(cache) -> <p> for {hit, age_s, ttl_s} from the API, or null when the response carries no cache info. */
export function cacheNote(cache) {
  if (!cache || typeof cache.hit !== 'boolean') return null;
  const ttl = Number.isFinite(cache.ttl_s) ? cache.ttl_s : 60;
  const text = cache.hit
    ? `Cached result, ${Math.max(0, Math.round(cache.age_s || 0))} s old. Results are cached for ${ttl} s; run again after that for a fresh check.`
    : 'Fresh result.';
  return h('p', { class: 'text-xs text-mute cache-note', 'data-cache': cache.hit ? 'hit' : 'miss' }, text);
}
