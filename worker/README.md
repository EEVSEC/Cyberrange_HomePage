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
  handoff handling, CORS, and rate limiting. Talks to Groq over `fetch`.
- `wrangler.jsonc` configures routing and the rate-limit binding.
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
The Worker uses `openai/gpt-oss-120b` through the Groq Chat Completions API.
Check [Groq's supported models](https://console.groq.com/docs/models) before
changing the model ID.

## Frontend
The site loads Sentinel from `js/sentinel.js`. It calls the deployed Worker by
default. For a different route, set `window.SENTINEL_ENDPOINT` before the script
loads. For localhost, start `server.js` with `SENTINEL_DEV_ENDPOINT` set to the
HTTPS Worker version URL you want to test. If the Worker is unavailable, Sentinel uses the published answers in
`faq.html` or offers an email handoff.

## Safety / cost notes
- The system prompt constrains Sentinel to EEVSEC topics, refuses exploit-code
  requests, and hands off account/legal/security questions to `hi@eevsec.com`.
- Input is capped at 500 chars; method-checked; CORS-locked to eevsec.com.
- Sentinel limits requests to approximately 20 per minute per IP at each
  Cloudflare location. Groq applies its own per-minute and daily quotas.
- The Worker degrades gracefully on a Groq error/quota/safety block (returns a
  "email a human" answer with `handoff: true`).
