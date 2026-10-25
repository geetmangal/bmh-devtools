// Shared page behaviour (no inline handlers: the CSP forbids inline script).
document.addEventListener('click', (ev) => {
  const btn = ev.target.closest('[data-copy-target]');
  if (!btn) return;
  const el = document.getElementById(btn.dataset.copyTarget);
  if (!el || !navigator.clipboard) return;
  navigator.clipboard.writeText(el.innerText).then(() => { btn.textContent = 'Copied'; });
});
