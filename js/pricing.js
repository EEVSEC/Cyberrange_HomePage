/* Pricing currency selector — USD / INR / AED, persisted to localStorage.
   Sets data-currency on <html>; CSS shows the matching .price-* span. The
   initial value is set by the inline bootstrap in <head> to avoid a flash. */
(() => {
  'use strict';
  const group = document.querySelector('.curr');
  if (!group) return;
  const btns = Array.from(group.querySelectorAll('.curr__btn'));
  const valid = { USD: 1, INR: 1, AED: 1 };

  function apply(cur, focus) {
    if (!valid[cur]) cur = 'USD';
    document.documentElement.dataset.currency = cur;
    try { localStorage.setItem('cr_currency', cur); } catch (e) {}
    btns.forEach(b => {
      const on = b.dataset.currency === cur;
      b.setAttribute('aria-checked', on ? 'true' : 'false');
      b.tabIndex = on ? 0 : -1;
      if (on && focus) b.focus();
    });
    if (window.track) window.track('currency_changed', { currency: cur });
  }

  // sync UI to whatever the bootstrap already set
  apply(document.documentElement.dataset.currency || 'USD', false);

  if (window.track) window.track('pricing_view');   // T-14

  group.addEventListener('click', (e) => {
    const b = e.target.closest('.curr__btn');
    if (b) apply(b.dataset.currency, false);
  });

  // arrow-key support for the radiogroup
  group.addEventListener('keydown', (e) => {
    if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(e.key)) return;
    e.preventDefault();
    const cur = document.documentElement.dataset.currency || 'USD';
    let i = btns.findIndex(b => b.dataset.currency === cur);
    i = (e.key === 'ArrowLeft' || e.key === 'ArrowUp') ? (i - 1 + btns.length) % btns.length
                                                       : (i + 1) % btns.length;
    apply(btns[i].dataset.currency, true);
  });
})();
