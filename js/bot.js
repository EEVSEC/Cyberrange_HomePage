/* CyberRange — floating guide bot "Byte"
   wanders the viewport, speaks on section change, no overlay panel */
(() => {
  'use strict';
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ── voice packs ── */
  const PACKS = {
    mild: {
      greet: "Hey! I'm Byte, I'll float around and tell you what's on screen.",
      sections: {
        top:       "Welcome to CyberRange. Real machines, real opponent, real AI coach watching every move.",
        what:      "Here's what makes us different. Not a course, not a CTF, an actual live-fire range.",
        versus:    "How we line up against other platforms. Pretty happy with these results, honestly.",
        how:       "Here's how a session flows, from briefing to debrief. Clean loop.",
        coach:     "Meet the AI Coach. Watches your match in real time and tells you exactly what to do next.",
        modes:     "Four ways to train: Battle, Practice, Learn, and Analyze. Start wherever feels right.",
        scenarios: "Six scenario worlds to fight in. Different threat environments, all of them real.",
        who:       "Who CyberRange is built for. Spoiler: if you're here, probably you.",
        why:       "Why this works where other training doesn't. Evidence-based, not vibes-based.",
        join:      "Ready? Drop your email and reserve your spot. See you on the range.",
      }
    },
    sarcastic: {
      greet: "Oh, a human arrived. I'm Byte. I wander. I comment. Scroll and we'll get along fine.",
      sections: {
        top:       "Hero section. Bold claims up top. Bold of us to have standards, I know.",
        what:      "Explaining what we actually are. Radical concept, being honest on page one.",
        versus:    "The comparison table. Yes, we win most rows. Try to act surprised.",
        how:       "How it works. Spoiler: you fight someone real. An AI watches. You get less bad.",
        coach:     "The AI Coach lives here. Think of it as the one that actually works, and me as the charming one.",
        modes:     "Four modes. You have to pick one. Decisions, hardest skill in cybersecurity, apparently.",
        scenarios: "Six scenarios. Each one harder than whatever you've been calling 'practice.' Cute setup though.",
        who:       "Who this is for. If you're reading this far, you already know the answer.",
        why:       "Why this approach works. Science-y section. I won't summarise it, you can read.",
        join:      "The waitlist. Put the email in before you talk yourself out of it. I'll wait.",
      }
    },
    savage: {
      greet: "Sup. Byte. I float around and rate your scroll speed. Ready? Let's go.",
      sections: {
        top:       "Hero section. Real machines, real opponent, real consequences. Not a drill. Literally.",
        what:      "Not a course. Not a CTF. A range. Wild idea, training that doesn't hold your hand.",
        versus:    "Comparison table. Look at the other column. Rough day to be our competition.",
        how:       "The loop: get in, fight, get coached, get better. No hand-holding built in.",
        coach:     "AI Coach right here. A pro in your ear instead of a 2019 YouTube tutorial. Upgrade complete.",
        modes:     "Battle mode if you've got a spine. Practice mode if you don't. No judgment. (Full judgment.)",
        scenarios: "Six environments that will humble you. That's kind of the point. You're welcome.",
        who:       "Built for people who want to actually get better. That's it. That's the vibe.",
        why:       "Why it works: you fight real threats instead of watching slides. Simple math.",
        join:      "Reserve your spot. Or keep scrolling and pretending you will. Your call, champ.",
      }
    }
  };

  const TONES = ['mild', 'sarcastic', 'savage'];
  let tone = localStorage.getItem('cr-bot-tone');
  if (!TONES.includes(tone)) {
    tone = TONES[Math.floor(Math.random() * TONES.length)];
    localStorage.setItem('cr-bot-tone', tone);
  }
  const pack = PACKS[tone];

  /* ── build DOM ── */
  const bot = document.createElement('div');
  bot.className = 'bot';
  bot.hidden = true;
  bot.innerHTML =
    '<div class="bot__figure" role="button" tabindex="0" aria-label="CyberRange guide Byte, click to toggle tip">' +
      '<div class="bot__speech" aria-live="polite">' +
        '<p class="bot__text"></p>' +
      '</div>' +
      '<div class="bot__antenna"></div>' +
      '<div class="bot__torso">' +
        '<div class="bot__arm bot__arm--l"><div class="bot__hand"></div></div>' +
        '<div class="bot__body">' +
          '<div class="bot__eyes"><span class="bot__eye"></span><span class="bot__eye"></span></div>' +
          '<div class="bot__mouth"></div>' +
        '</div>' +
        '<div class="bot__arm bot__arm--r"><div class="bot__hand"></div></div>' +
      '</div>' +
    '</div>';
  document.body.appendChild(bot);

  const figure = bot.querySelector('.bot__figure');
  const speech = bot.querySelector('.bot__speech');
  const textEl = bot.querySelector('.bot__text');

  /* ── wander positions ─────────────────────────────────────────── */
  const BW = 98, BH = 98; // bot visual footprint (body + arms + antenna)

  function spots() {
    const vw = window.innerWidth, vh = window.innerHeight;
    const navH = 80, m = 22;
    return [
      { x: m,               y: navH + m },                            // 0 top-left
      { x: vw - BW - m,     y: navH + m },                            // 1 top-right
      { x: m,               y: navH + (vh - navH) * 0.38 },           // 2 mid-left-high
      { x: vw - BW - m,     y: navH + (vh - navH) * 0.38 },           // 3 mid-right-high
      { x: m,               y: navH + (vh - navH) * 0.65 },           // 4 mid-left-low
      { x: vw - BW - m,     y: navH + (vh - navH) * 0.65 },           // 5 mid-right-low
      { x: (vw - BW) * 0.38, y: vh - BH - m },                        // 6 bottom-center-left
      { x: (vw - BW) * 0.62, y: vh - BH - m },                        // 7 bottom-center-right
      { x: m,               y: vh - BH - m },                         // 8 bottom-left
      { x: vw - BW - m,     y: vh - BH - m },                         // 9 bottom-right
    ];
  }

  let curIdx = 9;   // start bottom-right
  let prevIdx = -1;

  function applyEdgeClasses(x) {
    bot.classList.toggle('edge-left',  x < 110);
    bot.classList.toggle('edge-right', x > window.innerWidth - BW - 120);
  }

  function moveTo(idx) {
    const s = spots()[idx];
    bot.style.left = s.x + 'px';
    bot.style.top  = s.y + 'px';
    curIdx = idx;
    bot.classList.toggle('is-high', s.y < window.innerHeight * 0.4);
    applyEdgeClasses(s.x);
  }

  function wander() {
    const all = spots();
    let next;
    let attempts = 0;
    do {
      next = Math.floor(Math.random() * all.length);
      attempts++;
    } while ((next === curIdx || next === prevIdx) && attempts < 12);
    prevIdx = curIdx;
    moveTo(next);
  }

  /* ── speech ───────────────────────────────────────────────────── */
  let speechTimer = null;

  function say(text, ms = 4800) {
    clearTimeout(speechTimer);
    textEl.textContent = text;
    speech.classList.add('is-visible');
    bot.classList.add('is-speaking');
    if (ms > 0) speechTimer = setTimeout(hideSpeech, ms);
  }

  function hideSpeech() {
    clearTimeout(speechTimer);
    speech.classList.remove('is-visible');
    bot.classList.remove('is-speaking');
  }

  /* ── arm wave ─────────────────────────────────────────────────── */
  function wave() {
    bot.classList.remove('is-waving');
    void bot.offsetWidth;               // restart animation
    bot.classList.add('is-waving');
    setTimeout(() => bot.classList.remove('is-waving'), 1500);
  }

  /* ── section detection ────────────────────────────────────────── */
  const SECTION_KEYS = {
    top: 'top', what: 'what', versus: 'versus', how: 'how',
    coach: 'coach', modes: 'modes', scenarios: 'scenarios',
    who: 'who', why: 'why', join: 'join'
  };
  let curSection = null;
  const sectionEls = Object.keys(SECTION_KEYS)
    .map(id => document.getElementById(id))
    .filter(Boolean);

  if (sectionEls.length && 'IntersectionObserver' in window) {
    const io = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (!entry.isIntersecting) return;
        const key = SECTION_KEYS[entry.target.id];
        if (!key || key === curSection) return;
        curSection = key;
        const msg = pack.sections[key];
        if (!msg) return;
        if (!reduced) wander();
        setTimeout(() => { say(msg, 4800); if (!reduced) wave(); }, reduced ? 0 : 500);
      });
    }, {
      threshold: 0.25,
      rootMargin: '-8% 0px -42% 0px'
    });
    sectionEls.forEach(el => io.observe(el));
  }

  /* ── click — toggle speech or re-show current section tip ─────── */
  figure.addEventListener('click', () => {
    if (speech.classList.contains('is-visible')) {
      hideSpeech();
    } else {
      const msg = pack.sections[curSection || 'top'];
      if (msg) { say(msg, 4800); wave(); }
    }
  });
  figure.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); figure.click(); }
  });

  /* ── resize: re-anchor to current spot ───────────────────────── */
  window.addEventListener('resize', () => moveTo(curIdx), { passive: true });

  /* ── init after intro ─────────────────────────────────────────── */
  function init() {
    /* place without transition first so it snaps to start position */
    bot.style.transition = 'none';
    moveTo(9);
    bot.hidden = false;
    requestAnimationFrame(() => requestAnimationFrame(() => {
      /* re-enable wander transition */
      bot.style.transition = '';
      setTimeout(() => {
        wave();
        say(pack.greet, 5200);
        curSection = 'top';
      }, reduced ? 300 : 2800);
    }));
  }

  const html = document.documentElement;
  if (html.classList.contains('intro-done')) {
    init();
  } else {
    const obs = new MutationObserver(() => {
      if (html.classList.contains('intro-done')) { obs.disconnect(); init(); }
    });
    obs.observe(html, { attributes: true, attributeFilter: ['class'] });
    setTimeout(() => { obs.disconnect(); if (bot.hidden) init(); }, 5000);
  }
})();
