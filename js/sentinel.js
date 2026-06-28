/* EEVSEC "Sentinel" — front-of-site AI assistant (frontend controller).
 *
 * Self-contained chat widget that talks to the Cloudflare Worker in /worker.
 * INERT by default: it does nothing unless `window.SENTINEL_ENDPOINT` is set
 * (e.g. window.SENTINEL_ENDPOINT = "/api/sentinel") before this script runs.
 *
 * Deploy: this is the LLM alternative to the static "Byte" widget. To use it,
 * deploy the Worker, set SENTINEL_ENDPOINT, load this file, and remove
 * js/faqbot.js (don't run both — two corner bubbles is bad UX). See worker/README.md.
 *
 * CSP: same-origin script + inline style (allowed) + connect-src 'self' (when the
 * Worker is routed to /api/sentinel). If the endpoint is a different origin, add it
 * to each page's connect-src.
 */
(() => {
  'use strict';
  // Deployed Cloudflare Worker (Groq backend). Override via window.SENTINEL_ENDPOINT.
  const ENDPOINT = window.SENTINEL_ENDPOINT || 'https://eevsec-sentinel.hi-e2a.workers.dev';
  if (!ENDPOINT) return;
  if (document.getElementById('sentinel-launcher')) return;

  const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const MAILTO = 'mailto:hi@eevsec.com';

  // ── styles (scoped, token-aware) ──────────────────────────────────────────
  const style = document.createElement('style');
  style.textContent = `
  .snt-panel,.snt-panel *,.snt-fab,.snt-fab *{box-sizing:border-box}
  .snt-fab{position:fixed;right:24px;bottom:24px;width:56px;height:56px;border-radius:50%;
    border:1px solid var(--line-2,rgba(255,255,255,.14));background:var(--bg-1,#161616);
    color:var(--violet,#5fe0a0);cursor:pointer;z-index:9000;display:grid;place-items:center;
    box-shadow:0 10px 26px -12px rgba(0,0,0,.6);transition:transform .2s,box-shadow .2s}
  .snt-fab:hover{transform:translateY(-2px);box-shadow:0 16px 34px -14px rgba(0,0,0,.7)}
  .snt-fab:focus-visible{outline:2px solid var(--violet,#5fe0a0);outline-offset:3px}
  .snt-fab svg{width:26px;height:26px}
  .snt-badge{position:absolute;top:-3px;right:-3px;width:13px;height:13px;border-radius:50%;
    background:var(--warn,#e0a24a);border:2px solid var(--bg,#0b0d0c);opacity:0;transform:scale(.4);
    transition:opacity .2s,transform .2s}
  .snt-badge.on{opacity:1;transform:scale(1)}
  .snt-panel{position:fixed;right:24px;bottom:92px;width:min(400px,calc(100vw - 32px));
    height:min(560px,calc(100vh - 120px));background:var(--bg-1,#161616);
    color:var(--ink,#f2f2f2);border:1px solid var(--line-2,rgba(255,255,255,.14));
    border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,.5);z-index:9001;overflow:hidden;
    font:400 14px/1.5 var(--font-body,system-ui);
    display:none;grid-template-rows:auto minmax(0,1fr) auto auto}
  .snt-panel.open{display:grid}
  .snt-head{padding:16px 18px;border-bottom:1px solid var(--line,rgba(255,255,255,.08));
    display:flex;justify-content:space-between;align-items:center;gap:12px}
  .snt-head h3{margin:0;font:600 16px/1.2 var(--font-body,system-ui)}
  .snt-head p{margin:2px 0 0;font:400 12px/1.4 var(--font-body,system-ui);color:var(--ink-3,#9a9a9a)}
  .snt-close{background:none;border:0;color:inherit;cursor:pointer;font-size:20px;line-height:1;padding:4px}
  .snt-log{min-height:0;overflow-y:auto;padding:16px 18px;margin:0;list-style:none;display:flex;flex-direction:column;gap:12px}
  .snt-msg{font:400 14px/1.55 var(--font-body,system-ui);max-width:85%}
  .snt-msg.snt-bot{color:var(--ink,#f2f2f2)}
  .snt-msg.snt-user{align-self:flex-end;background:var(--violet,#5fe0a0);color:var(--violet-ink,#06140c);
    padding:8px 12px;border-radius:14px 14px 4px 14px}
  .snt-src{margin-top:6px;font:400 12px/1.4 var(--font-mono,monospace)}
  .snt-src a{color:var(--violet,#5fe0a0)}
  .snt-sugg{display:flex;flex-wrap:wrap;gap:6px;margin-top:4px}
  .snt-sugg button{font:400 12px/1 var(--font-body,system-ui);color:var(--ink-2,#cfcfcf);
    background:var(--bg-2,#1e1e1e);border:1px solid var(--line-2,rgba(255,255,255,.14));
    border-radius:999px;padding:7px 12px;cursor:pointer}
  .snt-sugg button:hover{border-color:var(--violet,#5fe0a0);color:var(--ink,#fff)}
  .snt-faqlink{display:inline-block;margin-top:10px;font:400 12px/1 var(--font-body,system-ui);color:var(--violet,#5fe0a0);text-decoration:none}
  .snt-faqlink:hover{text-decoration:underline}
  .snt-form{display:flex;gap:8px;padding:12px 14px;border-top:1px solid var(--line,rgba(255,255,255,.08))}
  .snt-form input{flex:1;background:var(--bg-2,#1e1e1e);border:1px solid var(--line-2,rgba(255,255,255,.14));
    border-radius:10px;color:var(--ink,#f2f2f2);padding:10px 12px;font:400 14px var(--font-body,system-ui)}
  .snt-form input:focus{outline:none;border-color:var(--violet,#5fe0a0)}
  .snt-form button{background:var(--violet,#5fe0a0);color:var(--violet-ink,#06140c);border:0;
    border-radius:10px;padding:0 14px;cursor:pointer;font-weight:600}
  .snt-foot{padding:0 18px 12px;font:400 11px/1.4 var(--font-body,system-ui);color:var(--ink-4,#777)}
  .snt-foot a{color:var(--ink-3,#9a9a9a)}
  .snt-typing{display:inline-flex;gap:3px}
  .snt-typing i{width:5px;height:5px;border-radius:50%;background:var(--ink-3,#9a9a9a);animation:snt-b 1s infinite}
  .snt-typing i:nth-child(2){animation-delay:.15s}.snt-typing i:nth-child(3){animation-delay:.3s}
  @keyframes snt-b{0%,100%{opacity:.3}50%{opacity:1}}
  @media (prefers-reduced-motion:reduce){.snt-fab,.snt-typing i{transition:none;animation:none}}`;
  document.head.appendChild(style);

  // ── markup ────────────────────────────────────────────────────────────────
  const root = document.createElement('div');
  root.innerHTML =
    '<button id="sentinel-launcher" class="snt-fab" type="button" aria-label="Open Sentinel — ask about CyberRange" aria-expanded="false" aria-controls="sentinel-panel">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 11.5a8.5 8.5 0 0 1-12.6 7.4L3 21l2.1-5.4A8.5 8.5 0 1 1 21 11.5z"/><circle cx="8.5" cy="11.5" r="1" fill="currentColor" stroke="none"/><circle cx="12" cy="11.5" r="1" fill="currentColor" stroke="none"/><circle cx="15.5" cy="11.5" r="1" fill="currentColor" stroke="none"/></svg>' +
      '<span class="snt-badge" id="snt-badge" aria-hidden="true"></span>' +
    '</button>' +
    '<aside id="sentinel-panel" class="snt-panel" role="dialog" aria-modal="false" aria-labelledby="snt-title" hidden>' +
      '<header class="snt-head"><div><h3 id="snt-title">Ask about the range.</h3>' +
        '<p>I answer questions about CyberRange. For account help, I’ll hand you to a human.</p></div>' +
        '<button class="snt-close" type="button" aria-label="Close">×</button></header>' +
      '<ol class="snt-log" id="snt-log" aria-live="polite" style="list-style:none;margin:0"></ol>' +
      '<form class="snt-form" id="snt-form"><label class="sr-only" for="snt-input">Your question</label>' +
        '<input id="snt-input" type="text" autocomplete="off" placeholder="Type your question…" maxlength="500" required>' +
        '<button type="submit" aria-label="Send">→</button></form>' +
      '<div class="snt-foot">AI assistant · <a href="/faq.html">Common questions</a> · <a href="/privacy.html#section-12">Privacy</a> · <a href="' + MAILTO + '">Email a human</a></div>' +
    '</aside>';
  document.body.appendChild(root);

  const fab = root.querySelector('#sentinel-launcher');
  const panel = root.querySelector('#sentinel-panel');
  const closeBtn = root.querySelector('.snt-close');
  const log = root.querySelector('#snt-log');
  const form = root.querySelector('#snt-form');
  const input = root.querySelector('#snt-input');
  const badge = root.querySelector('#snt-badge');
  let greeted = false;

  // B-03: proactive nudge — a quiet unread dot after a delay (sooner on /pricing),
  // once per session, never an auto-open.
  let nudgeTimer = 0;
  const NUDGE_KEY = 'sentinel_nudged';
  const clearNudge = () => {
    if (nudgeTimer) { clearTimeout(nudgeTimer); nudgeTimer = 0; }
    if (badge) badge.classList.remove('on');
    try { sessionStorage.setItem(NUDGE_KEY, '1'); } catch (e) {}
  };
  (function scheduleNudge() {
    let seen = false;
    try { seen = sessionStorage.getItem(NUDGE_KEY) === '1'; } catch (e) {}
    if (seen || reduced) return;
    const onPricing = /\/pricing\.html$/.test(location.pathname);
    nudgeTimer = setTimeout(() => {
      if (fab.getAttribute('aria-expanded') === 'true') return;
      if (badge) badge.classList.add('on');
      fab.setAttribute('aria-label', 'Open Sentinel — questions about CyberRange? (1 new)');
    }, onPricing ? 8000 : 15000);
  })();

  const esc = (s) => { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; };

  function addMsg(role, text) {
    const li = document.createElement('li');
    li.className = 'snt-msg snt-' + role;
    li.textContent = text;
    log.appendChild(li);
    log.scrollTop = log.scrollHeight;
    return li;
  }
  function addBot(text, sources, handoff) {
    const li = addMsg('bot', text);
    if (Array.isArray(sources) && sources.length) {
      const p = document.createElement('p'); p.className = 'snt-src';
      p.innerHTML = 'See: ' + sources.map((s) => '<a href="' + esc(s) + '">' + esc(s) + '</a>').join(' · ');
      li.appendChild(p);
    }
    if (handoff) {
      const p = document.createElement('p'); p.className = 'snt-src';
      p.innerHTML = '<a href="' + MAILTO + '">Email a human →</a>';
      li.appendChild(p);
    }
  }
  function suggestions() {
    const qs = ['What is CyberRange?', 'How is it different from a CTF?', 'How much does it cost?', 'When does it open?', 'What are the three doctrine layers?'];
    const li = document.createElement('li'); li.className = 'snt-msg snt-bot';
    li.innerHTML = '<div class="snt-sugg">' + qs.map((q) => '<button type="button" data-q="' + esc(q) + '">' + esc(q) + '</button>').join('') + '</div><a class="snt-faqlink" href="/faq.html">See all common questions &rarr;</a>';
    log.appendChild(li);
  }

  function open() {
    panel.hidden = false; requestAnimationFrame(() => panel.classList.add('open'));
    fab.setAttribute('aria-expanded', 'true');
    clearNudge();
    if (!greeted) { greeted = true; addBot("Hi — I'm Sentinel. Ask me anything about CyberRange, or pick a common question:"); suggestions(); }
    input.focus();
    if (window.track) window.track('ai_bot_open');
  }
  function close() {
    panel.classList.remove('open'); fab.setAttribute('aria-expanded', 'false');
    setTimeout(() => { panel.hidden = true; }, reduced ? 0 : 200); fab.focus();
  }
  fab.addEventListener('click', () => (fab.getAttribute('aria-expanded') === 'true' ? close() : open()));
  closeBtn.addEventListener('click', close);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && fab.getAttribute('aria-expanded') === 'true') close(); });
  log.addEventListener('click', (e) => { const b = e.target.closest('button[data-q]'); if (b) { input.value = b.dataset.q; form.requestSubmit(); } });

  let busy = false;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const q = input.value.trim();
    if (!q || busy) return;
    busy = true; input.value = '';
    addMsg('user', q);
    if (window.track) window.track('ai_bot_message_sent', { length: q.length });
    const typing = document.createElement('li'); typing.className = 'snt-msg snt-bot';
    typing.innerHTML = '<span class="snt-typing"><i></i><i></i><i></i></span>';
    log.appendChild(typing); log.scrollTop = log.scrollHeight;
    try {
      const res = await fetch(ENDPOINT, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ q }),
      });
      const data = await res.json().catch(() => ({}));
      typing.remove();
      addBot(data.answer || "I didn't catch that — could you rephrase?", data.sources, data.handoff);
      if (data.handoff && window.track) window.track('ai_bot_handoff_to_human');
    } catch (err) {
      typing.remove();
      addBot("I'm having trouble reaching the brain right now. Email hi@eevsec.com and a human will pick up — usually within one business day.", null, true);
    } finally { busy = false; }
  });
})();
