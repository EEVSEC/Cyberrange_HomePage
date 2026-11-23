/* CyberRange analytics loader. Loaded AFTER consent.js so window.crConsent exists.

   - Google Analytics 4 (GA_ID): sets cookies and is a third-party tracker, so it
     loads ONLY after the visitor consents (window.crConsent.allows('analytics')),
     and also the moment they click Accept (the 'cr:consent' event). Get your
     Measurement ID (G-XXXXXXXXXX) from analytics.google.com > Admin > Data
     streams > Web. See deployment-notes.md.
   - Optional Cloudflare, Plausible, or Umami measurements also wait for consent.

   All matching origins are already allow-listed in each page's CSP. Leave every
   value blank to keep analytics off. */
(function () {
  'use strict';

  // --- Google Analytics 4 (consent-gated; sets _ga cookies) ---
  var GA_ID = 'G-2DJ0DCR7CD';     // GA4 Measurement ID (loads only after consent)

  // --- Optional cookieless measurements (consent-gated) ---
  var CLOUDFLARE_TOKEN = '55c1d7d86e2c484098673dcae8d0145c';
  var PLAUSIBLE_DOMAIN = '';
  var PLAUSIBLE_SRC    = 'https://plausible.io/js/script.js';
  var UMAMI_ID  = '';
  var UMAMI_SRC = 'https://cloud.umami.is/script.js';

  var head = document.head || document.documentElement;
  function load(src, attrs) {
    var s = document.createElement('script');
    s.src = src; s.async = true;
    for (var k in attrs) { if (Object.prototype.hasOwnProperty.call(attrs, k)) s.setAttribute(k, attrs[k]); }
    head.appendChild(s);
  }

  var extraLoaded = false;
  function syncConsent() {
    var allowed = window.crConsent && window.crConsent.allows('analytics');
    if (GA_ID) window['ga-disable-' + GA_ID] = !allowed;
    if (!allowed) return;

    if (!extraLoaded) {
      extraLoaded = true;
      if (CLOUDFLARE_TOKEN) {
        load('https://static.cloudflareinsights.com/beacon.min.js', { 'data-cf-beacon': JSON.stringify({ token: CLOUDFLARE_TOKEN }) });
      } else if (PLAUSIBLE_DOMAIN) {
        load(PLAUSIBLE_SRC, { 'data-domain': PLAUSIBLE_DOMAIN });
      } else if (UMAMI_ID) {
        load(UMAMI_SRC, { 'data-website-id': UMAMI_ID });
      }
    }
    loadGA();
  }

  // Google Analytics: only with consent.
  var gaDone = false;
  function loadGA() {
    if (gaDone || !GA_ID) return;
    if (!(window.crConsent && window.crConsent.allows('analytics'))) return;
    gaDone = true;
    load('https://www.googletagmanager.com/gtag/js?id=' + GA_ID, {});
    window.dataLayer = window.dataLayer || [];
    function gtag() { window.dataLayer.push(arguments); }
    window.gtag = gtag;
    gtag('js', new Date());
    gtag('config', GA_ID);
  }
  syncConsent();
  window.addEventListener('cr:consent', syncConsent);

  /* ── T-14: consent-gated event tracking ──────────────────────
     Public API: window.track('event_name', { ...params }).
     Event names are snake_case for GA4. Fires only after the visitor
     has consented to analytics; otherwise it is a silent no-op.
     Standard events: waitlist_submit, waitlist_role_chosen, pricing_view,
     contact_message_sent, contact_email_click, ai_bot_open,
     ai_bot_message_sent, ai_bot_handoff_to_human, currency_changed,
     lang_switcher_clicked. */
  window.track = function (name, params) {
    if (!name) return;
    if (!(window.crConsent && window.crConsent.allows('analytics'))) return;
    loadGA();
    if (typeof window.gtag === 'function') window.gtag('event', name, params || {});
  };
})();
