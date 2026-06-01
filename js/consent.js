/* CyberRange consent notice + first-party cookies + optional admin visit log.
   - cr_consent  (essential): remembers Accept/Decline. Set on choice.
   - cr_visit    (analytics, consent-gated): first-party id + page-view count +
                 first/last seen. Set/updated ONLY after the visitor accepts.
   - COLLECT_URL (optional): if you paste your Google Apps Script web-app /exec
                 URL below, each consented visit is also beaconed to a Google
                 Sheet YOU own, so you (admin) can actually see the data. Leave
                 empty to keep everything on the visitor's device only.
                 Setup steps: visit-collector-setup.md. The script.google.com
                 origin is already allow-listed in each page's CSP.
   No third-party advertising or cross-site tracking cookies are used.
   Public API: window.crConsent.allows('analytics') | .record | .open(). */
(() => {
  'use strict';
  const C = window.crCookie;
  const CONSENT = 'cr_consent', VISIT = 'cr_visit', VERSION = 1;

  const COLLECT_URL = 'https://script.google.com/macros/s/AKfycbzwKKVfyfODFKZCAH1QmuWOHkl5lAZCTwPThlBstYM7IEEK6vkf9J07DaJVF2S55GOl/exec';   // visit log -> Google Sheet

  const nowISO = () => { try { return new Date().toISOString(); } catch (e) { return ''; } };

  const writeConsent = (choice) => {
    if (C) C.set(CONSENT, VERSION + '|' + choice + '|' + nowISO(), 180);
  };

  const readConsent = () => {
    const raw = C && C.get(CONSENT);
    if (raw) {
      const p = raw.split('|');                         // version | choice | ts
      const choice = p[1];
      return { v: parseInt(p[0], 10) || VERSION, choice: choice, ts: p[2] || null,
               categories: { essential: true, analytics: choice === 'accepted' } };
    }
    try {                                               // one-time migration from the old localStorage values
      const ls = localStorage.getItem('cr-consent');
      if (ls) { const o = JSON.parse(ls); if (o && o.choice) { writeConsent(o.choice); localStorage.removeItem('cr-consent'); return readConsent(); } }
      const legacy = localStorage.getItem('cr-cookie-consent');
      if (legacy === 'accepted' || legacy === 'declined') { writeConsent(legacy); localStorage.removeItem('cr-cookie-consent'); return readConsent(); }
    } catch (e) {}
    return null;
  };

  /* fire-and-forget beacon to the admin's own Google Sheet (only when configured) */
  function beacon(rec) {
    if (!COLLECT_URL) return;
    try {
      const payload = JSON.stringify({
        id: rec.id, n: rec.n, ts: rec.last,
        path: location.pathname + location.search,
        ref: document.referrer || '',
        lang: navigator.language || ''
      });
      const blob = new Blob([payload], { type: 'text/plain;charset=UTF-8' });
      if (navigator.sendBeacon && navigator.sendBeacon(COLLECT_URL, blob)) return;
      fetch(COLLECT_URL, { method: 'POST', mode: 'no-cors', keepalive: true,
                           headers: { 'Content-Type': 'text/plain;charset=UTF-8' }, body: payload });
    } catch (e) {}
  }

  const trackVisit = () => {                            // first-party, only when analytics is allowed
    if (!C || !window.crConsent.allows('analytics')) return;
    let rec = null;
    const v = C.get(VISIT);
    if (v) { try { rec = JSON.parse(v); } catch (e) { rec = null; } }
    if (!rec || !rec.id) {
      let id;
      try { id = crypto.randomUUID(); } catch (e) { id = 'v' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }
      rec = { id: id, n: 0, first: nowISO() };
    }
    rec.n = (rec.n || 0) + 1;
    rec.last = nowISO();
    C.set(VISIT, JSON.stringify(rec), 365);
    beacon(rec);
  };

  window.crConsent = {
    record: readConsent(),
    allows: function (category) {
      if (category === 'essential') return true;
      const r = this.record;
      return !!(r && r.categories && r.categories[category]);
    },
    open: function () { build(true); },
  };

  let barEl = null;
  function decide(choice) {
    writeConsent(choice);
    window.crConsent.record = readConsent();
    if (choice === 'accepted') trackVisit(); else if (C) C.remove(VISIT);
    try { window.dispatchEvent(new CustomEvent('cr:consent', { detail: window.crConsent.record })); } catch (e) {}
  }

  function build(force) {
    if (barEl) return;
    if (!force && window.crConsent.record) return;      // already decided
    const bar = document.createElement('div');
    barEl = bar;
    bar.className = 'consent';
    bar.setAttribute('role', 'region');
    bar.setAttribute('aria-label', 'Cookie notice');
    bar.innerHTML =
      '<div class="consent__inner">' +
        '<p class="consent__text">We use a cookie to remember your choice, and your theme preference locally. ' +
        'With your consent, we use analytics cookies, including Google Analytics, to understand how our site is used. We do not use advertising cookies. ' +
        'Our forms are protected by Google reCAPTCHA, which may set a Google cookie when you use a form. ' +
        'See our <a href="/privacy.html">Privacy Policy</a> and <a href="/cookies.html">Cookie Policy</a>.</p>' +
        '<div class="consent__actions">' +
          '<button type="button" class="btn btn--ghost consent__btn" data-consent="declined">Decline</button>' +
          '<button type="button" class="btn btn--primary consent__btn" data-consent="accepted">Accept</button>' +
        '</div>' +
      '</div>';
    document.body.appendChild(bar);

    requestAnimationFrame(() => requestAnimationFrame(() => bar.classList.add('is-in')));

    bar.addEventListener('click', (e) => {
      const b = e.target.closest('[data-consent]');
      if (!b) return;
      decide(b.dataset.consent);
      bar.classList.remove('is-in');
      setTimeout(() => { bar.remove(); barEl = null; }, 360);
    });
  }

  const start = () => {
    if (window.crConsent.record) { trackVisit(); }      // returning visitor who already accepted: count this view
    else { build(false); }
  };
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
