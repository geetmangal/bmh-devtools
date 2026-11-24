/* BookMyHost Toolbox embed helper (optional). Include once on the page that hosts the iframe:
 *   <script src="https://www.bookmyhost.com/tools/embed.js" async></script>
 * It resizes every <iframe data-bmh-tool> to the height the widget reports. Messages are accepted only from
 * this script's own origin and only in the fixed shape {type: 'bmh-tools:resize', height: <number>}. */
(function () {
  'use strict';
  var origin;
  try { origin = new URL(document.currentScript.src).origin; } catch (e) { origin = 'https://www.bookmyhost.com'; }
  window.addEventListener('message', function (ev) {
    if (ev.origin !== origin) return;
    var d = ev.data;
    if (!d || d.type !== 'bmh-tools:resize' || typeof d.height !== 'number' || !isFinite(d.height)) return;
    var frames = document.querySelectorAll('iframe[data-bmh-tool]');
    for (var i = 0; i < frames.length; i++) {
      if (frames[i].contentWindow === ev.source) {
        frames[i].style.height = Math.max(200, Math.min(4000, Math.ceil(d.height))) + 'px';
      }
    }
  });
})();
