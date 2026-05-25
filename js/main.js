/* CyberRange — motion + intro + theme engine (vanilla, no deps) */
(() => {
  'use strict';
  const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const $  = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];

  /* always (re)load from the very top of the page */
  if ('scrollRestoration' in history) history.scrollRestoration = 'manual';
  window.scrollTo(0, 0);
  window.addEventListener('load', () => window.scrollTo(0, 0));
  // bfcache restores (mobile back/forward, some reloads) keep scroll — reset those too
  window.addEventListener('pageshow', () => window.scrollTo(0, 0));

  /* hero clip: load + play only once the typing is done AND the hero is on screen,
     and restart from frame 0 on every load / back-forward restore */
  (() => {
    const pic = $('.hmac-video');
    const img = pic && pic.querySelector('img');
    if (!img) return;
    let introDone = false, visible = false, loaded = false;

    const load = () => {                       // first activation → starts at frame 0
      pic.querySelectorAll('source[data-srcset]').forEach(s => { s.srcset = s.dataset.srcset; });
      img.src = img.dataset.src;
      loaded = true;
    };
    const tryLoad = () => { if (introDone && visible && !loaded) load(); };

    // start once the "CyberRange" intro loading animation finishes
    const markIntro = () => { introDone = true; tryLoad(); };
    if (document.documentElement.classList.contains('intro-done')) {
      markIntro();
    } else {
      const obs = new MutationObserver(() => {
        if (document.documentElement.classList.contains('intro-done')) { obs.disconnect(); markIntro(); }
      });
      obs.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
    }
    if ('IntersectionObserver' in window) {
      new IntersectionObserver((es) => {
        es.forEach(e => { visible = e.isIntersecting; });
        tryLoad();
      }, { threshold: 0.25 }).observe(pic);
    } else {
      visible = true; tryLoad();
    }

    // back/forward cache restore → replay from frame 0
    window.addEventListener('pageshow', (e) => {
      if (e.persisted && loaded) { const s = img.currentSrc || img.src; img.removeAttribute('src'); img.src = s; }
    });
  })();

  /* ── modes reel ──────────────────────────────────────────────────────────
     Two-stage so playback is smooth: (1) preload the iframe off-screen while
     the visitor is still up top, so React/Babel boot and the about:blank→dark
     paint all happen out of view; (2) only signal it to start animating once
     the FOUR MODES section is actually on screen. */
  (() => {
    const frame = $('.modes-reel__frame');
    if (!frame || !frame.dataset.src) return;
    let loaded = false, inView = false, ready = false, sent = false;

    const load = () => {
      if (loaded) return;
      loaded = true;
      frame.src = frame.dataset.src;
    };
    const play = () => {
      if (sent || !inView || !ready) return;
      try { frame.contentWindow.postMessage({ crPlay: true }, '*'); sent = true; } catch (e) {}
    };

    // the reel announces itself once its player has mounted (and is sitting on frame 0)
    window.addEventListener('message', (e) => {
      if (e.source === frame.contentWindow && e.data && e.data.crReady) { ready = true; play(); }
    });

    // preload as soon as the browser is idle — the reel lives several sections down,
    // so it has time to finish booting before the visitor scrolls to it
    const idle = window.requestIdleCallback || ((fn) => setTimeout(fn, 1200));
    window.addEventListener('load', () => idle(load));

    if ('IntersectionObserver' in window) {
      // safety net: if they reach it before idle-preload fired, load immediately
      new IntersectionObserver((es, o) => {
        if (es.some(e => e.isIntersecting)) { load(); o.disconnect(); }
      }, { rootMargin: '1200px 0px' }).observe(frame);
      // start the animation when the section is genuinely in view
      const playIO = new IntersectionObserver((es) => {
        if (es.some(e => e.isIntersecting)) { inView = true; play(); playIO.disconnect(); }
      }, { threshold: 0.35 });
      playIO.observe(frame);
    } else {
      load(); inView = true; play();
    }
  })();

  /* ── year ── */
  const yr = $('#year'); if (yr) yr.textContent = new Date().getFullYear();

  /* ── theme toggle ── */
  (() => {
    const btn  = $('#themeToggle');
    const html = document.documentElement;
    const meta = $('meta[name="color-scheme"]');
    if (!btn) return;
    const apply = (theme) => {
      html.dataset.theme = theme;
      localStorage.setItem('cr-theme', theme);
      if (meta) meta.content = theme === 'dark' ? 'dark light' : 'light dark';
      const reel = document.querySelector('.modes-reel__frame');
      if (reel && reel.contentWindow) reel.contentWindow.postMessage({ crTheme: theme }, '*');
    };
    btn.addEventListener('click', () => {
      apply(html.dataset.theme === 'dark' ? 'light' : 'dark');
    });
  })();

  /* ── modes reel CTA → scroll to waitlist ── */
  window.addEventListener('message', (e) => {
    if (e.data && e.data.crNav === 'join') {
      const t = document.getElementById('join');
      if (t) t.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });

  /* ════════════════════════════════════════════════════════════
     INTRO ANIMATION — "CyberRange" types in, flies to navbar
     ════════════════════════════════════════════════════════════ */
  (() => {
    const overlay  = $('#intro');
    const wordEl   = $('#introWord');
    const fillEl   = $('#introFill');
    const html     = document.documentElement;
    if (!overlay || !wordEl) { html.classList.add('intro-done'); return; }

    if (reduced) {
      overlay.style.display = 'none';
      html.classList.add('intro-done');
      return;
    }

    /* build character spans */
    const TEXT   = 'CyberRange';
    const ACCENT = 5; /* chars 5–9 get accent colour */
    wordEl.innerHTML = '';
    [...TEXT].forEach((ch, i) => {
      const s = document.createElement('span');
      s.className = 'ichar' + (i >= ACCENT ? ' ichar--accent' : '');
      s.textContent = ch;
      wordEl.appendChild(s);
    });
    const chars = $$('.ichar', wordEl);

    let idx = 0;

    const typeNext = () => {
      if (idx >= chars.length) {
        /* fill the loading bar then fly */
        if (fillEl) {
          fillEl.style.transition = 'width .44s var(--ease-in-out)';
          fillEl.style.width = '100%';
        }
        setTimeout(fly, 560);
        return;
      }
      chars[idx].classList.add('visible');
      idx++;
      setTimeout(typeNext, idx === 1 ? 55 : 42);
    };

    const fly = () => {
      const brand = $('.brand');
      if (!brand) { finish(); return; }

      const wRect = wordEl.getBoundingClientRect();
      const bRect = brand.getBoundingClientRect();
      const tx = bRect.left + bRect.width  / 2 - (wRect.left + wRect.width  / 2);
      const ty = bRect.top  + bRect.height / 2 - (wRect.top  + wRect.height / 2);
      const sc = Math.max(bRect.width / wRect.width * 0.9, 0.08);

      /* reveal brand at the same moment the word starts flying so they
       * cross-fade through the flight — eliminates the "pops up" gap */
      html.classList.add('intro-done');

      wordEl.style.cssText +=
        'transition:transform .68s var(--ease-in-out),opacity .42s var(--ease-in) .22s;' +
        `transform:translate(${tx}px,${ty}px) scale(${sc});opacity:0;`;

      /* fade overlay slightly behind the word */
      setTimeout(() => {
        overlay.style.cssText += 'transition:opacity .5s var(--ease-out);opacity:0;';
      }, 160);

      setTimeout(finish, 880);
    };

    const finish = () => {
      html.classList.add('intro-done');
      overlay.style.display = 'none';
    };

    setTimeout(typeNext, 260);
  })();

  /* ── nav stuck + hide-on-scroll-down ── */
  const nav = $('#nav');
  let lastY = window.scrollY;
  const onScroll = () => {
    if (!nav) return;
    const y = window.scrollY;
    nav.classList.toggle('is-stuck', y > 24);
    if (y > lastY && y > 80) {
      nav.classList.add('nav--hidden');
    } else {
      nav.classList.remove('nav--hidden');
    }
    lastY = y;
  };
  onScroll(); window.addEventListener('scroll', onScroll, { passive: true });

  /* ── mobile menu (hamburger) ── */
  (() => {
    const burger = $('#navBurger'), menu = $('#navMenu');
    if (!burger || !menu) return;
    const setOpen = (open) => {
      menu.classList.toggle('open', open);
      burger.setAttribute('aria-expanded', open ? 'true' : 'false');
      burger.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
    };
    burger.addEventListener('click', () => setOpen(!menu.classList.contains('open')));
    menu.querySelectorAll('a').forEach(a => a.addEventListener('click', () => setOpen(false)));
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') setOpen(false); });
    // a detached floating menu while the bar slides away looks broken — close it on scroll
    window.addEventListener('scroll', () => { if (menu.classList.contains('open')) setOpen(false); }, { passive: true });
    // returning to desktop width should clear any open state
    window.addEventListener('resize', () => { if (window.innerWidth > 760) setOpen(false); });
  })();

  /* ── scroll reveals (one-way — reveal once, then leave it; never re-blur) ──
     Reversing the reveal made elements re-apply their blur/fade whenever they
     crossed the observer boundary (e.g. a section leaving through the top, or
     tiny scrolls right at the edge) — that was the flicker. */
  const revs = $$('.reveal');
  if (reduced) {
    revs.forEach(el => el.classList.add('in'));
  } else if ('IntersectionObserver' in window) {
    const io = new IntersectionObserver((entries) => {
      entries.forEach(e => {
        if (!e.isIntersecting) return;
        e.target.classList.add('in');
        e.target.style.willChange = 'auto';   // drop compositing hint once settled
        io.unobserve(e.target);
      });
    }, { threshold: 0.12, rootMargin: '0px 0px -8% 0px' });
    revs.forEach(el => io.observe(el));
  } else {
    revs.forEach(el => el.classList.add('in'));
  }

  /* ── scroll engine: progress bar + hero scrub + parallax (rAF, cross-browser) ── */
  (() => {
    if (reduced) return;
    const bar = document.createElement('div');
    bar.className = 'scroll-progress';
    document.body.appendChild(bar);

    const hero      = $('.hero');
    const heroTitle = $('#heroTitle');
    const heroText  = $('.hero__text');
    const mockup    = $('#heroMockup');
    // elements that drift at their own speed: data-parallax = px moved per 100px scrolled
    const layers = $$('[data-parallax]').map(el => ({ el, speed: parseFloat(el.dataset.parallax) || 0 }));

    let ticking = false;
    const update = () => {
      ticking = false;
      const y   = window.scrollY;
      const vh  = window.innerHeight;
      const max = document.documentElement.scrollHeight - vh;

      bar.style.transform = `scaleX(${max > 0 ? Math.min(1, y / max) : 0})`;

      // hero scrub — desktop only; on mobile the content stays fixed in place
      if (hero) {
        if (window.innerWidth > 1024) {
          if (y < vh * 1.3) {
            const p = Math.min(1, y / vh);          // 0 → 1 across first viewport
            if (heroTitle) {
              heroTitle.style.transform = `translateY(${y * -0.06}px)`;
              heroTitle.style.opacity   = `${1 - p * 0.75}`;
            }
            if (heroText) {
              heroText.style.transform = `translateY(${y * -0.03}px)`;
              heroText.style.opacity   = `${1 - p * 0.9}`;
            }
            if (mockup) mockup.style.transform = `translateY(${y * 0.10}px) scale(${1 - p * 0.05})`;
          }
        } else {
          // clear any transforms/opacity left over from a wider layout
          if (heroTitle) { heroTitle.style.transform = ''; heroTitle.style.opacity = ''; }
          if (heroText)  { heroText.style.transform = '';  heroText.style.opacity = ''; }
          if (mockup)    { mockup.style.transform = ''; }
        }
      }

      // generic parallax layers throughout the page
      for (const { el, speed } of layers) {
        const r = el.getBoundingClientRect();
        const mid = r.top + r.height / 2 - vh / 2;   // distance of element centre from viewport centre
        el.style.transform = `translate3d(0, ${(-mid * speed) / 100}px, 0)`;
      }
    };
    const onScroll = () => { if (!ticking) { ticking = true; requestAnimationFrame(update); } };
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onScroll, { passive: true });
    update();
  })();

  /* ── hero headline word reveal ── */
  const words = $$('#heroTitle .word');
  if (!reduced) {
    words.forEach((w, i) => {
      w.style.opacity = '0';
      w.style.transform = 'translateY(0.5em)';
      w.style.display = 'inline-block';
      w.style.transition = 'opacity .7s var(--ease-out), transform .8s var(--ease-out)';
      w.style.transitionDelay = (0.12 + i * 0.07) + 's';
      requestAnimationFrame(() => requestAnimationFrame(() => {
        w.style.opacity = '1'; w.style.transform = 'none';
      }));
    });
  }

  /* ── hero sub typewriter ── */
  (() => {
    const el = $('#heroType'), caret = $('#heroCaret');
    if (!el) return;
    const segs = [
      { t: 'Not a course. Not a CTF. A ' },
      { t: 'live arena', c: 'k-atk' },
      { t: ' real machines, real opponent, ' },
      { t: 'AI coach', c: 'k-def' },
      { t: ' watching every move. ' },
      { t: 'Hunt or be hunted.', c: 'k-atk' }
    ];
    /* Reserve the final height up-front so typing never reflows the page:
       an invisible ghost holds the full sentence (wraps identically at any
       width), and the live text is overlaid absolutely on top of it. */
    const sub = el.closest('.hero__sub');
    if (sub) {
      const overlay = document.createElement('span');
      overlay.className = 'hero__sub-live';
      sub.insertBefore(overlay, el);
      overlay.appendChild(el);
      if (caret) overlay.appendChild(caret);
      const ghost = document.createElement('span');
      ghost.className = 'hero__sub-ghost';
      ghost.setAttribute('aria-hidden', 'true');
      segs.forEach(s => { const sp = document.createElement('span'); if (s.c) sp.className = s.c; sp.textContent = s.t; ghost.appendChild(sp); });
      sub.appendChild(ghost);
    }
    const fill = () => {
      el.innerHTML = '';
      segs.forEach(s => { const sp = document.createElement('span'); if (s.c) sp.className = s.c; sp.textContent = s.t; el.appendChild(sp); });
      if (caret) caret.classList.add('done');
    };
    if (reduced) { fill(); document.dispatchEvent(new Event('herotyped')); return; }
    let si = 0, ci = 0, cur = null;
    const tick = () => {
      if (si >= segs.length) { if (caret) setTimeout(() => caret.classList.add('done'), 700); document.dispatchEvent(new Event('herotyped')); return; }
      const s = segs[si];
      if (ci === 0) { cur = document.createElement('span'); if (s.c) cur.className = s.c; el.appendChild(cur); }
      cur.textContent = s.t.slice(0, ci + 1);
      const ch = s.t[ci]; ci++;
      if (ci >= s.t.length) { si++; ci = 0; }
      setTimeout(tick, ch === ',' || ch === '—' ? 110 : ch === '.' ? 130 : 16);
    };
    /* start typing after intro is done — uses MutationObserver + fallback */
    let started = false;
    const start = () => {
      if (started) return; started = true;
      setTimeout(tick, 900);
    };
    if ('IntersectionObserver' in window) {
      const obs = new MutationObserver(() => {
        if (document.documentElement.classList.contains('intro-done')) { obs.disconnect(); start(); }
      });
      obs.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
    }
    const fallback = setTimeout(start, 4000);
    if (document.documentElement.classList.contains('intro-done')) { clearTimeout(fallback); start(); }
  })();

  /* ── nav active link ── */
  const links = $$('.nav__links a');
  const secs  = links.map(a => $(a.getAttribute('href'))).filter(Boolean);
  if (secs.length && 'IntersectionObserver' in window) {
    const so = new IntersectionObserver((entries) => {
      entries.forEach(e => {
        if (e.isIntersecting)
          links.forEach(l => l.classList.toggle('active', l.getAttribute('href') === '#' + e.target.id));
      });
    }, { rootMargin: '-45% 0px -50% 0px' });
    secs.forEach(s => so.observe(s));
  }

  /* ── waitlist confetti ── */
  function launchConfetti() {
    const canvas = $('#confettiCanvas');
    if (!canvas || reduced) return;
    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    canvas.style.display = 'block';

    // CyberRange palette — greens, cyan, gold, white
    const colors = ['#3DD68C', '#1FA463', '#22B8CF', '#E3B341', '#FAFAFA', '#7CE7B0'];
    const pieces = [];
    for (let i = 0; i < 180; i++) {
      pieces.push({
        x: Math.random() * canvas.width,
        y: -20 - Math.random() * canvas.height * 0.4,
        vx: (Math.random() - 0.5) * 5,
        vy: 1.5 + Math.random() * 3.5,
        w: 6 + Math.random() * 9,
        h: 3 + Math.random() * 4,
        angle: Math.random() * Math.PI * 2,
        spin: (Math.random() - 0.5) * 0.25,
        color: colors[Math.floor(Math.random() * colors.length)],
        opacity: 1,
        gravity: 0.06 + Math.random() * 0.04,
      });
    }
    const start = performance.now();
    let raf;
    const draw = (now) => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const elapsed = now - start;
      pieces.forEach(p => {
        p.vy += p.gravity; p.vx *= 0.995;
        p.x += p.vx; p.y += p.vy; p.angle += p.spin;
        if (elapsed > 2600) p.opacity = Math.max(0, p.opacity - 0.018);
        if (p.opacity <= 0) return;
        ctx.save();
        ctx.globalAlpha = p.opacity;
        ctx.translate(p.x, p.y);
        ctx.rotate(p.angle);
        ctx.fillStyle = p.color;
        ctx.fillRect(-p.w / 2, -p.h / 2, p.w, p.h);
        ctx.restore();
      });
      const alive = pieces.filter(p => p.opacity > 0 && p.y < canvas.height + 30);
      if (alive.length > 0 && elapsed < 4200) {
        raf = requestAnimationFrame(draw);
      } else {
        cancelAnimationFrame(raf);
        canvas.style.display = 'none';
      }
    };
    raf = requestAnimationFrame(draw);
  }

  /* ── waitlist — Loops.so signup ── */
  (() => {
    const LOOPS_FORM = 'https://app.loops.so/api/newsletter-form/cmog6m7fn0i650h1tir5n4smw';
    const form = $('#waitForm');
    if (!form) return;
    const nameEl = $('#waitName'), emailEl = $('#waitEmail'), roleEl = $('#waitRole');
    const honeypot = $('#waitHoneypot'), btn = $('#waitBtn'), msg = $('#waitMsg');
    const success = $('#waitSuccess'), successName = $('#waitSuccessName');
    const label = btn.querySelector('.btn-label'), arrow = btn.querySelector('.arr');

    const validEmail = v => /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(v);

    const fieldError = (el, errId, text) => {
      el.setAttribute('aria-invalid', 'true');
      const e = $('#' + errId); if (e) e.textContent = text || '';
      setTimeout(() => { el.removeAttribute('aria-invalid'); if (e) e.textContent = ''; }, 3200);
    };
    const resetBtn = () => {
      btn.disabled = false; btn.classList.remove('loading');
      if (label) label.textContent = 'Request access';
      if (arrow) arrow.style.visibility = '';
    };

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (honeypot && honeypot.value) return;            // bot trap

      const name = nameEl.value.trim();
      const email = emailEl.value.trim();
      const role = roleEl.value;
      msg.textContent = ''; msg.classList.remove('ok');

      if (!name)  { fieldError(nameEl,  'waitNameErr',  'Name is required.');        nameEl.focus();  return; }
      if (!email) { fieldError(emailEl, 'waitEmailErr', 'Email is required.');       emailEl.focus(); return; }
      if (!validEmail(email)) { fieldError(emailEl, 'waitEmailErr', 'Enter a valid email address.'); emailEl.focus(); return; }
      if (!role)  { fieldError(roleEl,  'waitRoleErr',  'Please select an option.'); roleEl.focus();  return; }

      btn.disabled = true; btn.classList.add('loading');
      if (label) label.textContent = 'Sending…';
      if (arrow) arrow.style.visibility = 'hidden';

      const parts = name.split(' ');
      const firstName = parts[0];
      const lastName = parts.slice(1).join(' ') || '';

      try {
        const body = new URLSearchParams({ email, firstName, lastName, role }).toString();
        const res = await fetch(LOOPS_FORM, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body,
        });
        const data = await res.json();

        if (data.success) {
          if (successName) successName.textContent = firstName;
          form.hidden = true; form.style.display = 'none';
          if (success) { success.hidden = false; }
          launchConfetti();
        } else if (data.message && /duplicate|already/i.test(data.message)) {
          msg.textContent = "You're already on the list."; resetBtn();
        } else {
          msg.textContent = 'Something went wrong, please try again.'; resetBtn();
        }
      } catch (_) {
        msg.textContent = 'Something went wrong, please try again.'; resetBtn();
      }
    });
  })();

  /* ════════════════════════════════════════════════════════════
     AI COACH ENGINE
     ════════════════════════════════════════════════════════════ */
  const COACH = {
    atk: [
      {
        phase: 'Recon',
        state: [['Target', '10.10.14.7 · web-01'], ['Access', 'unauthenticated'], ['Last command', 'nmap -sV 10.10.14.7'], ['Result', '80/tcp http · 22/tcp ssh']],
        read: 'Port 80 is open and serving a website. Before you touch SSH, map what the site exposes.',
        cmd: 'gobuster dir -u http://10.10.14.7 -w common.txt',
        why: 'Lists hidden pages and folders. A forgotten admin or upload path is the most common way in.',
        chain: ['Enumerate the site', 'Find a login or upload', 'Test it for a weakness']
      },
      {
        phase: 'Foothold',
        state: [['Target', '10.10.14.7 · web-01'], ['Access', 'unauthenticated'], ['Last command', 'opened /upload'], ['Result', 'accepts .php, no checks', true]],
        read: "The upload form doesn't check file type. You can drop a small script and have the server run it.",
        cmd: "curl -F 'f=@shell.php' http://10.10.14.7/upload",
        why: 'Uploads a tiny PHP payload that gives you a foothold, you become the low-privilege web user.',
        chain: ['Upload the payload', 'Trigger it for a shell', 'Look for a way to escalate']
      },
      {
        phase: 'Escalate',
        state: [['Target', '10.10.14.7 · web-01'], ['Access', 'www-data (low)'], ['Last command', 'sudo -l'], ['Result', '(ALL) NOPASSWD: /usr/bin/find', true]],
        read: 'This account can run "find" as root without a password. That is a clean path to full control.',
        cmd: 'sudo find . -exec /bin/sh \\; -quit',
        why: 'Abuses the "find" permission to launch a root shell. Now you own the box, capture proof and log it.',
        chain: ['Use the misconfig', 'Get a root shell', 'Capture proof + log it']
      }
    ],
    def: [
      {
        phase: 'Detect',
        state: [['Monitoring', 'web-01 · edge'], ['Alerts', '1 new'], ['Last command', 'tail -f access.log'], ['Result', 'burst of 404s from .99', true]],
        read: 'Someone is scanning your site for hidden pages, a wave of failed requests from one address.',
        cmd: 'iptables -A INPUT -s 10.10.14.99 -j DROP',
        why: 'Blocks that address at the firewall so the scan stops while you investigate what they found.',
        chain: ['Spot the scan', 'Block the source', 'Check what they reached']
      },
      {
        phase: 'Contain',
        state: [['Monitoring', 'web-01'], ['Alerts', '2, upload + process'], ['Last command', 'ps aux | grep php'], ['Result', 'shell.php running as www-data', true]],
        read: 'An unknown script is running on your server. It was just uploaded, almost certainly a foothold.',
        cmd: 'kill -9 $(pgrep -f shell.php)',
        why: "Stops the malicious process immediately, cutting the attacker's access to the machine.",
        chain: ['Find the rogue process', 'Kill it', 'Remove the uploaded file']
      },
      {
        phase: 'Harden',
        state: [['Monitoring', 'web-01'], ['Alerts', '0'], ['Last command', 'reviewed /upload'], ['Result', 'no file-type validation', true]],
        read: 'The upload form let any file through. Fix the root cause so this can never happen again.',
        cmd: 'auditctl -w /var/www/upload -p wa -k uploads',
        why: 'Watches the upload folder and logs every change, so the next attempt is caught instantly.',
        chain: ['Patch the validation', 'Watch the folder', 'Confirm the alert fires']
      }
    ]
  };

  const panel    = $('#coachPanel');
  const stateBox = $('#stateRows');
  const readEl   = $('#coachRead');
  const cmdEl    = $('#coachCmd');
  const whyEl    = $('#coachWhy');
  const chainEl  = $('#coachChain');
  const phaseEl  = $('#coachPhase');
  const copyBtn  = $('#coachCopy');

  if (panel && stateBox && readEl) {
    let side = 'atk', idx = 0, runId = 0, timers = [], visible = !('IntersectionObserver' in window);

    const clearTimers = () => { timers.forEach(clearTimeout); timers = []; };
    const later = (fn, ms) => { const t = setTimeout(fn, ms); timers.push(t); return t; };

    const renderState = (rows) => {
      stateBox.innerHTML = rows.map(([k, v, warn]) =>
        `<div class="state__row"><span class="state__k">${k}</span><span class="state__v${warn ? ' warn' : ''}">${v}</span></div>`
      ).join('');
    };

    const typeText = (el, text, speed, done) => {
      if (reduced) { el.textContent = text; done && done(); return; }
      el.textContent = ''; let i = 0;
      const step = () => {
        if (runIdGuard !== runId) return;
        el.textContent = text.slice(0, i + 1); i++;
        if (i < text.length) later(step, speed); else done && done();
      };
      step();
    };
    let runIdGuard = 0;

    const renderChain = (steps) => {
      chainEl.innerHTML = steps.map((s, i) =>
        `<div class="chain__step" style="opacity:0"><span class="n">${i + 1}</span><span class="tx">${s}</span></div>`
      ).join('');
      const items = $$('.chain__step', chainEl);
      items.forEach((it, i) => {
        if (reduced) { it.style.opacity = '1'; return; }
        it.style.transition = 'opacity .4s var(--ease-out), transform .4s var(--ease-out)';
        it.style.transform = 'translateY(6px)';
        later(() => { if (runIdGuard !== runId) return; it.style.opacity = '1'; it.style.transform = 'none'; }, 120 * i);
      });
    };

    const fade = (el, on) => { el.style.transition = 'opacity .3s var(--ease-out)'; el.style.opacity = on ? '1' : '0'; };

    const playBeat = () => {
      runId++; runIdGuard = runId; clearTimers();
      const beat = COACH[side][idx];
      phaseEl.textContent = beat.phase;
      panel.classList.toggle('def', side === 'def');
      panel.classList.toggle('atk', side === 'atk');

      [readEl, whyEl].forEach(e => fade(e, false));
      fade(cmdEl.parentElement, false);
      chainEl.style.opacity = '0';

      later(() => {
        if (runIdGuard !== runId) return;
        renderState(beat.state);
        fade(readEl, true);
        typeText(readEl, beat.read, 14, () => {
          if (runIdGuard !== runId) return;
          fade(cmdEl.parentElement, true);
          typeText(cmdEl, beat.cmd, 18, () => {
            if (runIdGuard !== runId) return;
            fade(whyEl, true);
            typeText(whyEl, beat.why, 9, () => {
              if (runIdGuard !== runId) return;
              chainEl.style.opacity = '1';
              renderChain(beat.chain);
              later(() => { idx = (idx + 1) % COACH[side].length; playBeat(); }, reduced ? 5200 : 3400);
            });
          });
        });
      }, 320);
    };

    $$('.seg button', panel).forEach(b => {
      b.addEventListener('click', () => {
        const s = b.dataset.side; if (s === side) return;
        $$('.seg button', panel).forEach(x => x.setAttribute('aria-selected', x === b ? 'true' : 'false'));
        side = s; idx = 0; playBeat();
      });
    });

    if (copyBtn) copyBtn.addEventListener('click', () => {
      const txt = cmdEl.textContent;
      if (navigator.clipboard) navigator.clipboard.writeText(txt)
        .then(() => { copyBtn.textContent = 'copied'; later(() => copyBtn.textContent = 'copy', 1400); })
        .catch(() => {});
    });

    if ('IntersectionObserver' in window) {
      const co = new IntersectionObserver((entries) => {
        entries.forEach(e => {
          if (e.isIntersecting && !visible) { visible = true; playBeat(); }
        });
      }, { threshold: 0.25 });
      co.observe(panel);
    } else {
      playBeat();
    }
  }
})();
