/* CyberRange — lightweight engine for static sub-pages (legal, etc.)
   Handles only what text pages need: theme toggle, copyright year, sticky nav.
   The homepage uses the richer main.js; this avoids loading that here. */
(() => {
  'use strict';
  const $ = (s) => document.querySelector(s);

  /* copyright year */
  const yr = $('#year');
  if (yr) yr.textContent = new Date().getFullYear();

  /* theme toggle — shares the cr-theme key with the homepage */
  const btn = $('#themeToggle');
  const html = document.documentElement;
  const meta = $('meta[name="color-scheme"]');
  if (btn) {
    btn.addEventListener('click', () => {
      const t = html.dataset.theme === 'dark' ? 'light' : 'dark';
      html.dataset.theme = t;
      try { localStorage.setItem('cr-theme', t); } catch (e) {}
      if (meta) meta.content = t === 'dark' ? 'dark light' : 'light dark';
    });
  }

  /* sticky nav shadow on scroll */
  const nav = $('#nav');
  if (nav) {
    const onScroll = () => nav.classList.toggle('is-stuck', window.scrollY > 24);
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
  }
})();
