/* CyberRange "Byte" widget. A corner node that answers FAQs and runs an
   in-chat contact flow (asks name, email, message one at a time, then submits
   to Web3Forms which emails hi@eevsec.com). Static site, no backend. Injected
   on every page; self-loads its stylesheet. The question list is a real
   terminal-style menu: move the cursor with the up/down arrows (or Home/End),
   press Enter to select, or just click. faq.html is kept (de-linked) as the
   structured FAQPage fallback for crawlers / no-JS. */
(() => {
  'use strict';
  const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const ACCESS_KEY = 'ceb3bf16-4844-48c6-b2fd-71e89236c59e';   // Web3Forms

  const FAQ = [
    { q: 'What is the EEVSEC CyberRange?',
      a: 'CyberRange is a live, competitive cybersecurity training arena. You test your offensive and defensive skills on real, isolated machines, in real time, against a real opponent, with a state-aware AI Coach in your corner. It is not a course and not a CTF.' },
    { q: 'How does a live PvP match work?',
      a: 'Two players enter one scenario and choose a side, attacker or defender. The platform provisions a separate isolated virtual machine for each of you, pairs you up, and the AI Coach watches both sides and analyses the match in real time. When it ends, you get a breakdown of what happened and what to improve.' },
    { q: 'Do you use fake boxes or scripted walkthroughs?',
      a: 'No. We reject predictable scripts and canned scenarios. Every exercise runs on real, isolated virtual machines under live pressure against a human opponent, so no two matches play out the same way.' },
    { q: "Is the AI Coach's feedback private?",
      a: 'Yes. The AI Coach sits inside your own isolated session. It tracks your actions, answers your questions, and gives hints and post-match review that stay private to your account. Your opponent never sees your guidance, and you never see theirs.' },
    { q: 'What scenarios can I train on?',
      a: 'Six environments, each modelled on a real-world domain: IoT and semiconductor, digital forensics, cloud and zero-trust, adversarial AI, red and blue automation, and SCADA/ICS critical infrastructure.',
      links: [{ t: 'See scenarios', h: '/#scenarios' }] },
    { q: 'Who is CyberRange for?',
      a: 'Security teams and SOC analysts drilling incident response, learners and students building real skill, universities running hands-on labs, and recruiters who want to see how people think under pressure rather than read a resume.' },
    { q: 'How do I get access?',
      a: 'CyberRange is in pre-launch. Join the waitlist to reserve your spot and be first in when the arena opens.',
      links: [{ t: 'Join the waitlist', h: '/#join' }] },
    { q: 'How do you handle my data and refunds?',
      a: 'We collect only what we need and never sell your data. Subscriptions can be cancelled at any time. See our policies for the full details.',
      links: [{ t: 'Privacy Policy', h: '/privacy.html' }, { t: 'Refund Policy', h: '/returns.html' }] },
  ];

  const validEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
  const pad2 = (n) => ('0' + n).slice(-2);

  const css = document.createElement('link');
  css.rel = 'stylesheet';
  css.href = '/css/faqbot.css?v=10';
  document.head.appendChild(css);

  const root = document.createElement('div');
  root.className = 'faqbot';
  root.innerHTML =
    '<button class="faqbot__bubble" id="faqbotBubble" type="button" aria-label="Open Byte, frequently asked questions" aria-expanded="false">' +
      '<span class="faqbot__glyph" aria-hidden="true">&gt;<i>_</i></span>' +
    '</button>' +
    '<div class="faqbot__panel" id="faqbotPanel" role="dialog" aria-label="Byte, frequently asked questions" aria-hidden="true">' +
      '<div class="faqbot__head">' +
        '<div class="faqbot__dots" aria-hidden="true"><span class="faqbot__dot faqbot__dot--r"></span><span class="faqbot__dot faqbot__dot--y"></span><span class="faqbot__dot faqbot__dot--g"></span></div>' +
        '<span class="faqbot__tabtitle">byte@eevsec: ~/faq</span>' +
        '<button class="faqbot__close" id="faqbotClose" type="button" aria-label="Close" title="Close">&times;</button>' +
      '</div>' +
      '<div class="faqbot__body" id="faqbotBody"></div>' +
      '<div class="faqbot__foot">' +
        '<span class="faqbot__foot-msg" id="faqbotFootMsg">Another question? <a href="#" id="faqbotContactLink">Get in touch</a></span>' +
        '<button class="faqbot__stop" id="faqbotStop" type="button" hidden><b aria-hidden="true">^C</b> interrupt</button>' +
        '<div class="faqbot__compose" id="faqbotCompose" hidden>' +
          '<span class="faqbot__prompt" aria-hidden="true"><span class="faqbot__pu">byte@eevsec</span>:<span class="faqbot__pp">~</span>$</span>' +
          '<input class="faqbot__field" id="faqbotField" type="text" autocomplete="off" placeholder="type, then enter" aria-label="Your reply" />' +
          '<button class="faqbot__send" id="faqbotSend" type="button" aria-label="Send">&#8629;</button>' +
          '<button class="faqbot__cancel" id="faqbotCancel" type="button" aria-label="Cancel" title="Cancel">^C</button>' +
        '</div>' +
      '</div>' +
    '</div>';
  document.body.appendChild(root);

  const $ = (id) => root.querySelector(id);
  const bubble = $('#faqbotBubble'), panel = $('#faqbotPanel'), closeBtn = $('#faqbotClose'),
        body = $('#faqbotBody'), footMsg = $('#faqbotFootMsg'), stopBtn = $('#faqbotStop'),
        compose = $('#faqbotCompose'), field = $('#faqbotField'), sendBtn = $('#faqbotSend'),
        cancelBtn = $('#faqbotCancel'), contactLink = $('#faqbotContactLink');
  let built = false, stopGo = null, contactStep = null, currentMenu = null, settleRAF = 0;
  const contact = { name: '', email: '', message: '' };

  const scrollDown = () => { body.scrollTop = body.scrollHeight; };
  const setFooter = (mode) => {           // 'msg' | 'typing' | 'compose'
    footMsg.hidden = mode !== 'msg';
    stopBtn.hidden = mode !== 'typing';
    compose.hidden = mode !== 'compose';
  };

  const PROMPT_HTML = '<span class="faqbot__pu">byte@eevsec</span>:<span class="faqbot__pp">~</span>$ ';
  const addMsg = (cls, text) => {
    const m = document.createElement('div');
    m.className = 'faqbot__msg faqbot__msg--' + cls;
    if (cls === 'user') {                              // echo user input behind a shell prompt
      const p = document.createElement('span');
      p.className = 'faqbot__prompt'; p.setAttribute('aria-hidden', 'true');
      p.innerHTML = PROMPT_HTML;
      m.appendChild(p);
    }
    if (text) m.appendChild(document.createTextNode(text));
    body.appendChild(m); scrollDown();
    return m;
  };

  /* move the cursor onto an option (and bring it into view) */
  const focusOption = (el) => {
    if (!el) return;
    try { el.scrollIntoView({ block: 'nearest' }); } catch (e) {}
    el.focus();
  };
  const focusMenu = () => {
    if (root.dataset.open !== 'true' || contactStep) return;
    const menu = currentMenu && currentMenu.isConnected ? currentMenu : body.querySelector('.faqbot__qlist');
    if (!menu) { closeBtn.focus(); return; }
    focusOption(menu.querySelector('.faqbot__q[tabindex="0"]') || menu.querySelector('.faqbot__q'));
  };
  /* run focus / scroll AFTER the panel has laid out and painted */
  const requestSettle = () => {
    if (settleRAF) cancelAnimationFrame(settleRAF);
    settleRAF = requestAnimationFrame(() => {
      settleRAF = requestAnimationFrame(() => {
        settleRAF = 0;
        if (contactStep) { scrollDown(); field.focus(); }
        else { focusMenu(); }
      });
    });
  };

  /* ── the question menu: arrow-key + click terminal selector ── */
  const addQuestionList = () => {
    const list = document.createElement('div');
    list.className = 'faqbot__qlist';
    list.setAttribute('role', 'menu');
    list.setAttribute('aria-label', 'Choose a question or talk to the team');

    const make = (label, onSelect, opts) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'faqbot__q' + (opts && opts.contact ? ' faqbot__q--contact' : '');
      b.setAttribute('role', 'menuitem');
      b.tabIndex = -1;
      if (opts && opts.num != null) {
        const n = document.createElement('span');
        n.className = 'faqbot__q-num'; n.setAttribute('aria-hidden', 'true');
        n.textContent = pad2(opts.num);
        b.appendChild(n);
      }
      b.appendChild(document.createTextNode(label));
      b.addEventListener('click', onSelect);
      list.appendChild(b);
      return b;
    };

    FAQ.forEach((item, i) => make(item.q, () => answer(i, list), { num: i + 1 }));
    make('Talk to the team', startContact, { contact: true });

    const opts = Array.prototype.slice.call(list.querySelectorAll('.faqbot__q'));
    if (opts.length) opts[0].tabIndex = 0;                 // roving tabindex: one stop in the page tab order
    if (!reduced) opts.forEach((b, i) => { b.style.animationDelay = (i * 0.04) + 's'; });

    const move = (from, dir) => {
      let to = from + dir;
      if (to < 0) to = opts.length - 1; else if (to >= opts.length) to = 0;
      opts[from].tabIndex = -1; opts[to].tabIndex = 0; focusOption(opts[to]);
    };
    list.addEventListener('keydown', (e) => {
      const cur = opts.indexOf(document.activeElement);
      if (cur < 0) return;
      if (e.key === 'ArrowDown') { e.preventDefault(); move(cur, 1); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); move(cur, -1); }
      else if (e.key === 'Home') { e.preventDefault(); move(cur, -cur); }
      else if (e.key === 'End') { e.preventDefault(); move(cur, opts.length - 1 - cur); }
    });

    body.appendChild(list);
    currentMenu = list;
    return list;
  };

  /* ── FAQ answer (typed, with Stop) ── */
  const typeInto = (el, text, done) => {
    const caret = document.createElement('span'); caret.className = 'faqbot__caret'; el.appendChild(caret);
    let i = 0, timer = null, fin = false;
    const finish = () => {
      if (fin) return; fin = true; clearTimeout(timer);
      if (i < text.length) caret.insertAdjacentText('beforebegin', text.slice(i));
      caret.remove(); done && done();
    };
    const step = () => {
      if (fin) return;
      caret.insertAdjacentText('beforebegin', text[i]); i++; scrollDown();
      if (i < text.length) timer = setTimeout(step, 12); else finish();
    };
    timer = setTimeout(step, 60);
    return finish;
  };

  const finishAnswer = (bot, item) => {
    setFooter('msg'); stopGo = null;
    if (item.links) {
      const ld = document.createElement('div'); ld.className = 'faqbot__links';
      item.links.forEach((l) => { const a = document.createElement('a'); a.className = 'faqbot__link'; a.href = l.h; a.textContent = l.t; ld.appendChild(a); });
      bot.appendChild(ld);
    }
    addQuestionList();
    focusMenu();                              // hand the cursor to the fresh menu for arrow-key picking
  };

  const answer = (idx, listEl) => {
    if (stopGo) stopGo();
    if (contactStep) return;                 // ignore FAQ clicks mid contact flow
    if (listEl) listEl.remove();
    const item = FAQ[idx];
    addMsg('user', item.q);
    const bot = addMsg('bot', '');
    if (reduced) { bot.textContent = item.a; finishAnswer(bot, item); return; }
    setFooter('typing');
    bot.innerHTML = '<span class="faqbot__typing" aria-hidden="true"><i></i><i></i><i></i></span>';
    let finishType = null;
    const indTimer = setTimeout(() => { bot.textContent = ''; finishType = typeInto(bot, item.a, () => finishAnswer(bot, item)); }, 650);
    stopGo = () => { clearTimeout(indTimer); if (finishType) finishType(); else { bot.textContent = item.a; finishAnswer(bot, item); } };
  };
  stopBtn.addEventListener('click', () => { if (stopGo) stopGo(); });

  /* ── in-chat contact flow ── */
  function startContact() {
    buildOnce();
    if (window.crRecaptcha && window.crRecaptcha.enabled) window.crRecaptcha.prime();
    if (stopGo) stopGo();
    contactStep = 'name';
    contact.name = ''; contact.email = ''; contact.message = '';
    addMsg('bot', "Happy to help, I'll pass this to the team. What's your name?");
    setFooter('compose');
    field.value = '';
    requestSettle();                          // scroll to the prompt + focus the input after layout
  }

  const submitContact = async () => {
    addMsg('bot', 'Sending...');
    let captchaToken = '';
    if (window.crRecaptcha && window.crRecaptcha.enabled) {
      try { captchaToken = await window.crRecaptcha.execute(); }
      catch (e) {
        addMsg('bot', "Couldn't verify you're human. You can reach us directly at hi@eevsec.com.");
        contactStep = null; setFooter('msg'); addQuestionList(); focusMenu(); return;
      }
    }
    try {
      const res = await fetch('https://api.web3forms.com/submit', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({
          access_key: ACCESS_KEY,
          subject: 'CyberRange enquiry' + (contact.name ? ' from ' + contact.name : ''),
          from_name: contact.name || 'CyberRange website',
          replyto: contact.email,
          name: contact.name, email: contact.email, message: contact.message,
          source: 'Byte chat widget',
          'g-recaptcha-response': captchaToken,
        }),
      });
      const data = await res.json();
      if (data && data.success) addMsg('bot', "Sent. We'll get back to you at " + contact.email + " shortly.");
      else addMsg('bot', 'That did not go through. You can reach us directly at hi@eevsec.com.');
    } catch (err) {
      addMsg('bot', 'That did not go through. You can reach us directly at hi@eevsec.com.');
    }
    contactStep = null; setFooter('msg'); addQuestionList(); focusMenu();
  };

  const stepContact = () => {
    if (!contactStep) return;
    const val = field.value.trim();
    if (contactStep === 'name') {
      addMsg('user', val || '(skipped)'); contact.name = val; contactStep = 'email';
      addMsg('bot', "Thanks" + (val ? ', ' + val : '') + ". What's the best email to reach you?");
      field.value = ''; field.focus(); return;
    }
    if (contactStep === 'email') {
      if (!validEmail(val)) { addMsg('bot', "That doesn't look like a valid email. Mind trying again?"); field.value = ''; field.focus(); return; }
      addMsg('user', val); contact.email = val; contactStep = 'message';
      addMsg('bot', 'Got it. What do you need? A sentence or two is plenty.');
      field.value = ''; field.focus(); return;
    }
    if (contactStep === 'message') {
      if (!val) { field.focus(); return; }
      addMsg('user', val); contact.message = val; contactStep = 'sending';
      field.value = ''; submitContact();
    }
  };

  const cancelContact = () => {
    contactStep = null; field.value = ''; setFooter('msg');
    addMsg('bot', 'No problem. Pick a question, or reach us anytime at hi@eevsec.com.');
    addQuestionList(); focusMenu();
  };

  sendBtn.addEventListener('click', stepContact);
  field.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); stepContact(); } });
  cancelBtn.addEventListener('click', cancelContact);
  contactLink.addEventListener('click', (e) => { e.preventDefault(); startContact(); });

  /* ── open / close ── */
  const buildOnce = () => {
    if (built) return; built = true;
    const g = addMsg('bot', "Hi! I'm Byte, the EEVSEC CyberRange assistant. Ask me anything about the arena, just pick a question below or talk to the team.");
    g.classList.add('faqbot__banner');
    addQuestionList();
  };
  const open = () => {
    buildOnce();
    root.dataset.open = 'true';
    panel.classList.add('is-open'); panel.setAttribute('aria-hidden', 'false'); bubble.setAttribute('aria-expanded', 'true');
    requestSettle();
  };
  const close = () => {
    if (settleRAF) { cancelAnimationFrame(settleRAF); settleRAF = 0; }
    root.dataset.open = 'false';
    panel.classList.remove('is-open'); panel.setAttribute('aria-hidden', 'true'); bubble.setAttribute('aria-expanded', 'false');
    bubble.focus();
  };
  const toggle = () => { root.dataset.open === 'true' ? close() : open(); };

  bubble.addEventListener('click', toggle);
  closeBtn.addEventListener('click', close);
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape' || root.dataset.open !== 'true') return;
    if (contactStep) cancelContact(); else close();
  });

  /* any element with data-byte-contact (e.g. the site footer "Contact") opens Byte's contact flow */
  document.addEventListener('click', (e) => {
    const t = e.target.closest('[data-byte-contact]');
    if (!t) return;
    e.preventDefault(); open(); startContact();
  });
})();
