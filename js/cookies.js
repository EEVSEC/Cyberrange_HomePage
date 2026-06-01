/* First-party cookie helpers for CyberRange. Exposes window.crCookie.
   Defaults: Path=/, SameSite=Lax, and Secure ONLY on https (so cookies still
   work during local http preview). Values are URL-encoded. */
(function () {
  'use strict';
  var secure = (location.protocol === 'https:') ? '; Secure' : '';
  window.crCookie = {
    set: function (name, value, days) {
      var exp = '';
      if (days) { var d = new Date(); d.setTime(d.getTime() + days * 864e5); exp = '; Expires=' + d.toUTCString(); }
      document.cookie = name + '=' + encodeURIComponent(value) + exp + '; Path=/; SameSite=Lax' + secure;
    },
    get: function (name) {
      var key = name.replace(/([.*+?^${}()|[\]\\])/g, '\\$1');
      var m = document.cookie.match('(?:^|; )' + key + '=([^;]*)');
      return m ? decodeURIComponent(m[1]) : null;
    },
    remove: function (name) {
      document.cookie = name + '=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; SameSite=Lax' + secure;
    }
  };
})();
