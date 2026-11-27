/* Contact page form — submits to Web3Forms (same inbox as the Byte widget,
   hi@eevsec.com). Static site, no backend. Inline validation + loading state
   + inline success/failure (no redirect). Honeypot via Web3Forms `botcheck`. */
(() => {
  'use strict';
  const form = document.getElementById('contactForm');
  if (!form) return;

  const name    = document.getElementById('cformName');
  const message = document.getElementById('cformMsg');
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
  submit.disabled = false;
  form.addEventListener('focusin', () => window.crRecaptcha?.prime());


  function setStatus(msg, kind) {
    status.hidden = false;
    status.textContent = msg;
    status.className = 'cform__status' + (kind ? ' cform__status--' + kind : '');
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (submit.disabled || (bot && bot.checked)) return;

    if (!name.value.trim()) { setStatus('Please add your name.', 'err'); name.focus(); return; }
    if (!validEmail(email.value)) { setStatus('Please enter a valid email address.', 'err'); email.classList.add('is-invalid'); email.focus(); return; }
    if (!message.value.trim()) { setStatus('Please add a short message.', 'err'); message.focus(); return; }

    // route intent into the email subject line
    const selectedTopic = topic.value;
    subject.value = '[' + selectedTopic + '] EEVSEC CyberRange contact';

    submit.dataset.state = 'loading';
    submit.disabled = true;
    setStatus('Sending…', '');

    if (window.crRecaptcha?.enabled) {
      try {
        await window.crRecaptcha.execute();
      } catch {
        setStatus('Verification is unavailable. Try again or email us at hi@eevsec.com.', 'err');
        delete submit.dataset.state;
        submit.disabled = false;
        return;
      }
    }


    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 12000);
    try {
      const res = await fetch(form.action, {
        method: 'POST',
        headers: { 'Accept': 'application/json' },
        body: new FormData(form),
        signal: controller.signal
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.success) {
        form.reset();
        setStatus("Sent. We'll reply to your email, usually within one business day.", 'ok');
        if (window.track) window.track('contact_message_sent', { topic: selectedTopic });
      } else {
        setStatus("Couldn't send that. Email us directly at hi@eevsec.com.", 'err');
      }
    } catch (err) {
      setStatus("Network hiccup. Email us directly at hi@eevsec.com.", 'err');
    } finally {
      clearTimeout(timeout);
      delete submit.dataset.state;
      submit.disabled = false;
    }
  });
})();
