/* Invisible reCAPTCHA v2 helper for CyberRange forms (checkout + Byte contact).

   LAZY: Google's script is fetched only when a visitor actually engages a form
   (starts checkout, or opens the Byte contact flow) via prime(), so the
   third-party _GRECAPTCHA cookie is set only for people who use a form, never
   on a plain page view.

   The access and contact forms run a browser-side challenge before sending
   data to their respective providers. Provider-side verification is separate.

   Leave SITE_KEY blank to turn reCAPTCHA OFF (prime() is a no-op and execute()
   resolves to ''). The google.com / gstatic.com origins are allow-listed in
   each page's Content-Security-Policy. */
(function () {
  'use strict';

  var loopback = ['localhost', '127.0.0.1', '[::1]'].includes(window.location.hostname);
  var SITE_KEY = (loopback && window.CR_DEV_RECAPTCHA_SITE_KEY) || '6Le97QYtAAAAAKi7qMzTI9gbHL4Mlo5yi1hoCdU5';

  if (!SITE_KEY) {
    window.crRecaptcha = { enabled: false, prime: function () {}, execute: function () { return Promise.resolve(''); } };
    return;
  }

  var widgetId = null;
  var loading = null;
  var pending = null;

  function load() {
    if (loading) return loading;
    loading = new Promise(function (resolve, reject) {
      var container = document.createElement('div');
      container.style.display = 'none';
      document.body.appendChild(container);

      var script = document.createElement('script');
      var timeout = setTimeout(fail, 8000);

      function fail() {
        clearTimeout(timeout);
        script.remove();
        container.remove();
        reject(new Error('recaptcha-load'));
      }

      window.__crRecaptchaOnload = function () {
        try {
          widgetId = window.grecaptcha.render(container, {
            sitekey: SITE_KEY,
            size: 'invisible',
            badge: 'bottomright',
            callback: function (token) { if (pending) pending(null, token); },
            'error-callback': function () { if (pending) pending(new Error('recaptcha-error')); },
            'expired-callback': function () { if (pending) pending(new Error('recaptcha-expired')); }
          });
          clearTimeout(timeout);
          resolve();
        } catch (error) {
          fail();
        }
      };

      script.src = 'https://www.google.com/recaptcha/api.js?onload=__crRecaptchaOnload&render=explicit';
      script.async = true;
      script.onerror = fail;
      document.head.appendChild(script);
    }).catch(function (error) {
      loading = null;
      throw error;
    });
    return loading;
  }

  window.crRecaptcha = {
    enabled: true,
    prime: function () { load().catch(function () {}); },
    execute: async function () {
      await load();
      if (pending) throw new Error('recaptcha-busy');
      return new Promise(function (resolve, reject) {
        var timeout = setTimeout(function () {
          pending(new Error('recaptcha-timeout'));
        }, 60000);
        pending = function (error, token) {
          clearTimeout(timeout);
          pending = null;
          if (error) reject(error); else resolve(token);
        };
        try {
          window.grecaptcha.reset(widgetId);
          window.grecaptcha.execute(widgetId);
        } catch (error) {
          pending(error);
        }
      });
    }
  };
})();
