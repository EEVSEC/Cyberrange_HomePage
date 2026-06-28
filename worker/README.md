# EEVSEC Sentinel — AI assistant Worker

Backend for the front-of-site AI assistant (audit Part 12 / `B-srv`, `B-04`,
`BIG-2`). A Cloudflare Worker that takes a visitor question and returns a short,
grounded answer from **Groq** (free tier). One constrained Q&A call per
request — not an agent. No SDK; it calls the Groq REST API with `fetch`.

The site is otherwise **static** (GitHub Pages); this is the one server piece.
Nothing on the live site calls it until you deploy it and point the frontend at it.

```
POST /api/sentinel   { "q": "How much does CyberRange cost?" }
→ { "answer": "...", "handoff": false }
```

## Files
- `src/index.js` — the Worker. System prompt, guardrails, safety-block + account
  handoff handling, CORS, optional rate limit. Talks to Groq over `fetch`.
- `wrangler.jsonc` — config (routing, optional rate-limit binding).
- `package.json` (no runtime deps), `.dev.vars.example`.

## Deploy
```bash
cd worker
npm install                              # installs wrangler (dev tool only)
npx wrangler login                       # one time
npx wrangler secret put GROQ_API_KEY   # paste your free Groq key
# Local test:
cp .dev.vars.example .dev.vars           # put the key in .dev.vars
npx wrangler dev                         # POST http://localhost:8787 with {"q":"..."}
# Ship it:
npx wrangler deploy
```
**Free Groq key:** create one at <https://console.groq.com/keys> (the Groq
console — free tier). Then make the Worker reachable at
**`https://eevsec.com/api/sentinel`** by putting eevsec.com behind Cloudflare and
adding the route in `wrangler.jsonc` (`routes`). Same-origin means no CORS and no
CSP change. (If instead you expose it on a `*.workers.dev` URL, add that origin to
each page's `connect-src` CSP.)

## Model
`src/index.js` defaults to **`llama-3.3-70b-versatile`** (fast, free-tier, good for an FAQ
bot). Change the one `MODEL` line for a newer/other model (e.g. `llama-3.1-8b-instant`)
— verify the exact id at <https://console.groq.com/docs/models>, since an unknown id 404s.

## Frontend — your call at deploy time
The static site currently ships **"Byte"** (`js/faqbot.js`), a terminal-style FAQ
widget with an in-chat contact flow and **no LLM**. This Worker powers the LLM
**"Sentinel"** widget (`js/sentinel.js`, already in the repo, deploy-ready).
Pick one — don't run both (two corner bubbles is bad UX):

- **Go LLM (this Worker):** on every page, set `window.SENTINEL_ENDPOINT = "/api/sentinel"`,
  load `/js/sentinel.js`, and **remove the `js/faqbot.js` script tag**. `sentinel.js`
  is inert until `SENTINEL_ENDPOINT` is set, so nothing changes until you flip it.
- **Stay static (no backend):** keep Byte as-is and don't deploy this Worker.

`sentinel.js` already wires the `ai_bot_open` / `ai_bot_message_sent` /
`ai_bot_handoff_to_human` analytics events.

## Safety / cost notes
- The system prompt constrains Sentinel to EEVSEC topics, refuses exploit-code
  requests, and hands off account/legal/security questions to `hi@eevsec.com`.
- Input is capped at 500 chars; method-checked; CORS-locked to eevsec.com.
- Groq's free tier has its own per-minute/day quotas — watch them in the Groq console;
  add a Cloudflare WAF rate-limit rule on `/api/sentinel` if abuse appears.
- The Worker degrades gracefully on a Groq error/quota/safety block (returns a
  "email a human" answer with `handoff: true`).
