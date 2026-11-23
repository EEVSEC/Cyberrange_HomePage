/* CyberRange — lightweight engine for static sub-pages (legal, etc.)
   Handles only what text pages need: copyright year, sticky nav.
   The homepage uses the richer main.js; this avoids loading that here. */
(() => {
  'use strict';
  const $ = (s) => document.querySelector(s);

  /* copyright year */
  const yr = $('#year');
  if (yr) yr.textContent = new Date().getFullYear();

  const contents = $('.legal__toc details');
  if (contents) {
    const desktop = window.matchMedia('(min-width: 861px)');
    const update = () => { contents.open = desktop.matches; };
    update();
    desktop.addEventListener('change', update);
  }

  /* sticky nav shadow on scroll */
  const nav = $('#nav');
  if (nav) {
    const onScroll = () => nav.classList.toggle('is-stuck', window.scrollY > 24);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
  }
})();
