/* Contact page form — submits to Web3Forms (same inbox as the Byte widget,
   hi@eevsec.com). Static site, no backend. Inline validation + loading state
   + inline success/failure (no redirect). Honeypot via Web3Forms `botcheck`. */
(() => {
  'use strict';
  const form = document.getElementById('contactForm');
  if (!form) return;

  const email   = document.getElementById('cformEmail');
  const topic   = document.getElementById('cformTopic');
  const subject = document.getElementById('cformSubject');
  const submit  = document.getElementById('cformSubmit');
  const status  = document.getElementById('cformStatus');
  const bot     = document.getElementById('cformBot');

  const validEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);

  // inline email validation on blur
  email.addEventListener('blur', () => {
    if (email.value && !validEmail(email.value)) email.classList.add('is-invalid');
  });
  email.addEventListener('input', () => email.classList.remove('is-invalid'));

  function setStatus(msg, kind) {
    status.hidden = false;
    status.textContent = msg;
    status.className = 'cform__status' + (kind ? ' cform__status--' + kind : '');
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (bot && bot.checked) return;                 // honeypot tripped — silently drop

    if (!form.name.value.trim()) { setStatus('Please add your name.', 'err'); form.name.focus(); return; }
    if (!validEmail(email.value)) { setStatus('Please enter a valid email address.', 'err'); email.classList.add('is-invalid'); email.focus(); return; }
    if (!form.message.value.trim()) { setStatus('Please add a short message.', 'err'); form.message.focus(); return; }

    // route intent into the email subject line
    subject.value = '[' + topic.value + '] EEVSEC CyberRange contact';

    submit.dataset.state = 'loading';
    submit.disabled = true;
    setStatus('Sending…', '');

    try {
      const res = await fetch('https://api.web3forms.com/submit', {
        method: 'POST',
        headers: { 'Accept': 'application/json' },
        body: new FormData(form)
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.success) {
        form.reset();
        setStatus("Sent. We'll reply to your email — usually within one business day.", 'ok');
        if (window.track) window.track('contact_message_sent', { topic: topic.value });
      } else {
        setStatus("Couldn't send that. Email us directly at hi@eevsec.com.", 'err');
      }
    } catch (err) {
      setStatus("Network hiccup. Email us directly at hi@eevsec.com.", 'err');
    } finally {
      delete submit.dataset.state;
      submit.disabled = false;
    }
  });
})();
