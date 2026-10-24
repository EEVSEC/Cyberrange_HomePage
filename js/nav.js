/* EEVSEC header: frosted-on-scroll state and the slide-in menu (vanilla, no dependencies). */
(function () {
  'use strict';
  var header = document.getElementById('siteHeader');
  var trigger = document.getElementById('menuTrigger');
  var menu = document.getElementById('siteMenu');
  var scrim = document.getElementById('menuScrim');
  var closeBtn = document.getElementById('menuClose');
  if (!header) return;

  /* frosted glass once the page has scrolled */
  function update() { header.setAttribute('data-scrolled', window.scrollY > 20 ? 'true' : 'false'); }
  update();
  window.addEventListener('scroll', update, { passive: true });

  if (!trigger || !menu) return;
  var root = document.documentElement;
  var lastFocus = null;

  function isOpen() { return menu.classList.contains('is-open'); }

  function open() {
    lastFocus = document.activeElement;
    scrim.hidden = false;
    /* two frames so the transition runs from the closed state */
    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        menu.classList.add('is-open');
        scrim.classList.add('is-open');
      });
    });
    menu.setAttribute('aria-hidden', 'false');
    trigger.setAttribute('aria-expanded', 'true');
    root.classList.add('menu-open');
    setTimeout(function () { if (closeBtn) closeBtn.focus({ preventScroll: true }); }, 160);
  }

  function close(restoreFocus) {
    menu.classList.remove('is-open');
    scrim.classList.remove('is-open');
    menu.setAttribute('aria-hidden', 'true');
    trigger.setAttribute('aria-expanded', 'false');
    root.classList.remove('menu-open');
    setTimeout(function () { if (!isOpen()) scrim.hidden = true; }, 400);
    if (restoreFocus !== false && lastFocus && lastFocus.focus) lastFocus.focus({ preventScroll: true });
  }

  trigger.addEventListener('click', function () { isOpen() ? close() : open(); });
  if (closeBtn) closeBtn.addEventListener('click', function () { close(); });
  scrim.addEventListener('click', function () { close(); });
  /* links close the panel (same-page anchors then scroll normally) */
  menu.addEventListener('click', function (e) {
    if (e.target.closest && e.target.closest('a')) close(false);
  });

  document.addEventListener('keydown', function (e) {
    if (!isOpen()) return;
    if (e.key === 'Escape') { close(); return; }
    if (e.key !== 'Tab') return;
    /* keep focus inside the open panel */
    var f = menu.querySelectorAll('a[href], button:not([disabled])');
    if (!f.length) return;
    var first = f[0], last = f[f.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  });
})();
