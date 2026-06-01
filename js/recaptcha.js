/* Invisible reCAPTCHA v2 helper for CyberRange forms (waitlist + Byte contact).

   LAZY: Google's script is fetched only when a visitor actually engages a form
   (focuses the waitlist, or opens the Byte contact flow) via prime(), so the
   third-party _GRECAPTCHA cookie is set only for people who use a form, never
   on a plain page view.

   Static site, no backend, so verification differs per form:
     • Contact form  -> the token is sent to Web3Forms, which verifies it
       server-side with the SECRET key. The SECRET key lives ONLY in your
       Web3Forms dashboard (Settings > Spam Protection > Custom reCAPTCHA v2);
       it must never appear in this file or anywhere in the repo.
     • Waitlist form -> Loops.so does not verify reCAPTCHA, so the token is a
       client-side gate only; the hidden honeypot is the second layer.

   Leave SITE_KEY blank to turn reCAPTCHA OFF (prime() is a no-op and execute()
   resolves to ''). The google.com / gstatic.com origins are allow-listed in
   each page's Content-Security-Policy. */
(function () {
  'use strict';

  var SITE_KEY = '6Le97QYtAAAAAKi7qMzTI9gbHL4Mlo5yi1hoCdU5';   // reCAPTCHA v2 Invisible SITE key (public)

  if (!SITE_KEY) {
    window.crRecaptcha = { enabled: false, prime: function () {}, execute: function () { return Promise.resolve(''); } };
    return;
  }

  var widgetId = null, pending = null, readyResolve, ready = null, started = false;

  function load() {
    if (started) return;
    started = true;
    ready = new Promise(function (res) { readyResolve = res; });

    var container = document.createElement('div');
    container.style.display = 'none';
    (document.body || document.documentElement).appendChild(container);

    window.__crRecaptchaOnload = function () {
      widgetId = window.grecaptcha.render(container, {
        sitekey: SITE_KEY,
        size: 'invisible',
        badge: 'bottomright',
        callback: function (token) { if (pending) { pending.resolve(token); pending = null; } },
        'error-callback': function () { if (pending) { pending.reject(new Error('recaptcha-error')); pending = null; } },
        'expired-callback': function () { if (pending) { pending.reject(new Error('recaptcha-expired')); pending = null; } }
      });
      readyResolve();
    };

    var s = document.createElement('script');
    s.src = 'https://www.google.com/recaptcha/api.js?onload=__crRecaptchaOnload&render=explicit';
    s.async = true; s.defer = true;
    (document.head || document.documentElement).appendChild(s);
  }

  window.crRecaptcha = {
    enabled: true,
    /* Warm up reCAPTCHA on first form interaction (focus / open contact). */
    prime: load,
    /* Resolves with a fresh token, or rejects if the challenge fails/expires. */
    execute: function () {
      load();
      return ready.then(function () {
        return new Promise(function (resolve, reject) {
          pending = { resolve: resolve, reject: reject };
          try { window.grecaptcha.reset(widgetId); } catch (e) {}
          window.grecaptcha.execute(widgetId);
        });
      });
    }
  };
})();
