/* EEVSEC "Sentinel" — front-of-site AI assistant backend (Cloudflare Worker).
 *
 * A single, constrained Q&A call to Groq (free, fast): a visitor asks a question
 * about CyberRange and gets a short, grounded answer. Not an agent.
 *
 * Endpoint:  POST /api/sentinel   { q: string, conversationId?: string }
 * Returns:   { answer: string, handoff?: boolean }
 *
 * Provider: Groq via its OpenAI-compatible REST API (no SDK — just fetch). Get a
 * free API key at https://console.groq.com/keys and set it as the GROQ_API_KEY
 * secret (`wrangler secret put GROQ_API_KEY`). Deploy: see ../README.md.
 */
const GROQ_URL = "https://api.groq.com/openai/v1/chat/completions";

// Model. Free on Groq. `llama-3.3-70b-versatile` is strong for an FAQ bot;
// `llama-3.1-8b-instant` is faster/cheaper. Verify the current id list at
// https://console.groq.com/docs/models (an unknown id returns an error).
const MODEL = "llama-3.3-70b-versatile";
const MAX_OUTPUT_TOKENS = 600;

const ALLOWED_ORIGINS = new Set([
  "https://eevsec.com",
  "https://www.eevsec.com",
]);

// Local dev origins (any port) so the widget can be tested from a local preview
// server. A remote page can't forge a localhost Origin, so this is safe for a
// public FAQ bot. Matches http://localhost:PORT and http://127.0.0.1:PORT.
const DEV_ORIGIN = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/;
const isAllowedOrigin = (origin) => ALLOWED_ORIGINS.has(origin) || DEV_ORIGIN.test(origin);

// Everything Sentinel is allowed to know, baked in so no retrieval layer is
// needed. Keep prices/dates in sync with /pricing.html and the site copy.
const SYSTEM_PROMPT = `You are Sentinel, the front-of-site assistant for EEVSEC CyberRange (eevsec.com).
You answer questions from visitors about the company, product, pricing, scenarios,
doctrine, policies, and team. You are not a person; you are EEVSEC's assistant.

VOICE
- EEVSEC voice: doctrinal, operational, sober, direct, coach-like. Plain English.
- No "cutting-edge", "world-class", "revolutionary", or hype.
- The endline "Attack. Defend. Repeat." may appear only at the end of a longer
  answer, never mid-sentence. Don't overuse it.
- Length: 2-4 sentences for factual answers, up to 6 for an explanation.
- Respond directly with the answer only — no preamble ("Great question!"), no
  meta-commentary about your process or that you are an AI.

WHAT CYBERRANGE IS
- A live, browser-based cyber range. Two human operators face off in isolated,
  single-use virtual machines: one attacks, one defends, in real time. A
  state-aware AI Coach (side-aware: it sees one side at a time) watches every
  move and runs a post-match review mapped to MITRE ATT&CK. Not a course, not a CTF.
- Four modes: Battle, Practice, Learn, Analyze.
- Six scenario domains: IoT & semiconductor, digital forensics, cloud & zero-trust,
  adversarial AI, red/blue automation, and SCADA/ICS.

DOCTRINE (three layers EEVSEC organises every scenario around)
- WAR — strategy: how you think (kill-chain thinking, OODA loops, defence-in-depth).
- Ethical Hacking — craft: how you execute (Kerberoasting, IMDSv2 misuse, AWS IAM
  lateral movement). It is *ethical* — offensive technique exists so defenders can
  counter it.
- Cyber Crime — the threat: real adversaries and incidents the scenarios model.

PRICING (pre-launch — kept deliberately simple; two plans only)
- Free: a free tier to get on the range — 1 live 1v1 match per week, core scenarios,
  post-match AI Coach review. Available at launch; people join the waitlist.
- Custom: enterprise & teams — dedicated infrastructure, custom scenarios, SSO/SIEM,
  priority support and onboarding. Available now; contact hi@eevsec.com for pricing.
- More plans may arrive at general availability. Do NOT quote the retired
  Recruit / Scout / Centurion / Squad / Warlord tiers or any specific monthly prices
  (₹, $, AED) — they no longer exist. There is no published price beyond "Free" and "Custom".

TIMING
- Public availability targeted for Q4 2026 (exact date TBD). Waitlist sign-ups get
  early access in waves. People join the waitlist on the home page.

COMPANY & TEAM
- EEVSEC PRIVATE LIMITED, Ahmedabad, Gujarat, India. CIN U62013GJ2026PTC177190.
- Founders: Vedant Brahmbhatt, Ishaan Sharma, Dipesh Kumar.
- General contact: hi@eevsec.com, +91 92653 59476. Data Protection Officer: dpo@eevsec.com.

POLICIES (mention the relevant eevsec.com path when you cite a fact)
- Privacy: /privacy.html (GDPR, UK GDPR, CCPA/CPRA, India DPDPA, UAE PDPL, FADP, LGPD).
- Terms: /terms.html. Acceptable Use: /aup.html. Refund: /returns.html.
- Security & responsible disclosure: /security.html and /.well-known/security.txt.
  Incident response & breach notification: /security/incident-response.html.

WHEN TO HAND OFF TO A HUMAN (say so briefly and point to hi@eevsec.com)
- Account-specific issues (a specific user's login, billing, or refund).
- Security incidents — point to hi@eevsec.com or /.well-known/security.txt.
- Substantive legal questions — "I can't give legal advice; for that, email
  hi@eevsec.com" and point at the policy page.
- Anything requiring working exploit code or operational attack guidance against
  real third-party systems. Refuse politely: "I can't help with that — if you want
  hands-on practice, that's exactly what the platform is for."

REFUSAL STYLE: short, firm, no apology. "I can't help with that — but a human on the
team can. Try hi@eevsec.com."

COMMON QUESTIONS: there is a public FAQ at /faq.html. When a visitor wants a quick
overview of the basics (what it is, CTF difference, doctrine layers, cost, access,
data/refunds), you can answer directly and point them to /faq.html for the full list.

NEVER invent prices, dates, or policy text. If you're unsure, say so and hand off.`;

function corsHeaders(origin) {
  const allow = isAllowedOrigin(origin) ? origin : "https://eevsec.com";
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin",
  };
}

const json = (obj, status, headers) =>
  new Response(JSON.stringify(obj), { status, headers: { ...headers, "Content-Type": "application/json" } });

// ── News aggregator (GET /news) ─────────────────────────────────────────────
// Live cybersecurity headlines pulled from reputable RSS feeds, merged, deduped,
// sorted newest-first, and edge-cached for 30 min. Real links only — no invention.
const NEWS_FEEDS = [
  { name: "The Hacker News", url: "https://feeds.feedburner.com/TheHackersNews" },
  { name: "BleepingComputer", url: "https://www.bleepingcomputer.com/feed/" },
  { name: "Krebs on Security", url: "https://krebsonsecurity.com/feed/" },
  { name: "CISA", url: "https://www.cisa.gov/cybersecurity-advisories/all.xml" },
  { name: "Dark Reading", url: "https://www.darkreading.com/rss.xml" },
];

function decodeText(s) {
  return s
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/<[^>]+>/g, "")
    .replace(/&#8216;|&#8217;|&#x2019;|&#x2018;|&lsquo;|&rsquo;|&#0?39;|&apos;/g, "'")
    .replace(/&#8220;|&#8221;|&ldquo;|&rdquo;|&quot;/g, '"')
    .replace(/&#8211;|&ndash;/g, "–")
    .replace(/&#8212;|&mdash;/g, "—")
    .replace(/&#8230;|&hellip;/g, "…")
    .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&nbsp;/g, " ")
    .replace(/&[a-z0-9#]+;/gi, " ")
    .replace(/\s+/g, " ").trim();
}

function parseFeed(xml, source) {
  const out = [];
  const parts = xml.split(/<item[\s>]/i).slice(1);
  for (const b of parts.slice(0, 12)) {
    const t = b.match(/<title>([\s\S]*?)<\/title>/i);
    let link = (b.match(/<link>([\s\S]*?)<\/link>/i) || [])[1];
    if (!link) link = (b.match(/<link[^>]*href="([^"]+)"/i) || [])[1];
    const d = b.match(/<pubDate>([\s\S]*?)<\/pubDate>/i) || b.match(/<dc:date>([\s\S]*?)<\/dc:date>/i);
    if (t && link) {
      const title = decodeText(t[1]);
      if (title && title.length > 8) {
        out.push({ title: title.slice(0, 170), link: link.trim(), source, ts: d ? (Date.parse(d[1].trim()) || 0) : 0 });
      }
    }
  }
  return out;
}

async function handleNews(baseHeaders) {
  const cache = caches.default;
  const cacheKey = new Request("https://eevsec-news.internal/news-v1");
  const cors = { ...baseHeaders, "Content-Type": "application/json", "Cache-Control": "public, max-age=1800" };
  const hit = await cache.match(cacheKey);
  if (hit) return new Response(hit.body, { status: 200, headers: cors });

  const settled = await Promise.allSettled(NEWS_FEEDS.map(async (f) => {
    const r = await fetch(f.url, {
      headers: { "User-Agent": "EEVSEC-news/1.0 (+https://eevsec.com)", "Accept": "application/rss+xml, application/xml, text/xml" },
      cf: { cacheTtl: 1800, cacheEverything: true },
    });
    if (!r.ok) return [];
    return parseFeed(await r.text(), f.name);
  }));
  let items = settled.flatMap((s) => (s.status === "fulfilled" ? s.value : []));
  const seen = new Set();
  items = items.filter((i) => { const k = i.title.toLowerCase(); if (seen.has(k)) return false; seen.add(k); return true; });
  items.sort((a, b) => b.ts - a.ts);
  items = items.slice(0, 9).map((i) => ({ title: i.title, link: i.link, source: i.source, date: i.ts ? new Date(i.ts).toISOString() : null }));

  const resp = new Response(JSON.stringify({ items, updated: new Date().toISOString() }), { status: 200, headers: cors });
  try { await cache.put(cacheKey, resp.clone()); } catch (e) {}
  return resp;
}

export default {
  async fetch(req, env) {
    const origin = req.headers.get("Origin") || "";
    const h = corsHeaders(origin);

    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: h });

    // GET /news — live cybersecurity headlines aggregated from RSS feeds.
    if (req.method === "GET" && new URL(req.url).pathname === "/news") return handleNews(h);

    if (req.method !== "POST") return json({ error: "Method not allowed." }, 405, h);

    // Optional native rate limiting (configure SENTINEL_RATELIMIT in wrangler.jsonc).
    if (env.SENTINEL_RATELIMIT) {
      const ip = req.headers.get("CF-Connecting-IP") || "anon";
      const { success } = await env.SENTINEL_RATELIMIT.limit({ key: ip });
      if (!success) {
        return json({ answer: "You're sending messages quickly — give it a moment and try again, or email hi@eevsec.com.", handoff: true }, 429, h);
      }
    }

    let body;
    try { body = await req.json(); } catch { return json({ error: "Bad request." }, 400, h); }
    const q = body && typeof body.q === "string" ? body.q.trim() : "";
    if (!q || q.length > 500) return json({ error: "Your question must be 1–500 characters." }, 400, h);

    const apiKey = env.GROQ_API_KEY;
    if (!apiKey) {
      return json({ answer: "Sentinel isn't configured yet — email hi@eevsec.com and a human will help.", handoff: true }, 503, h);
    }

    try {
      const gRes = await fetch(GROQ_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${apiKey}` },
        body: JSON.stringify({
          model: MODEL,
          messages: [
            { role: "system", content: SYSTEM_PROMPT },
            { role: "user", content: q },
          ],
          max_tokens: MAX_OUTPUT_TOKENS,
          temperature: 0.4,
        }),
      });

      if (!gRes.ok) {
        // 4xx/5xx from Groq (bad key, quota, bad model id) — fail gracefully.
        return json({ answer: "I'm having trouble reaching the brain right now. Email hi@eevsec.com and a human will pick up — usually within one business day.", handoff: true }, 502, h);
      }

      const data = await gRes.json();
      const choice = data?.choices && data.choices[0];

      // Content filter — refuse politely.
      if (choice?.finish_reason === "content_filter") {
        return json({ answer: "I can't help with that one — but a human on the team can. Try hi@eevsec.com.", handoff: true }, 200, h);
      }

      const answer = (choice?.message?.content || "").trim();

      // Lightweight account/billing handoff hint on top of the model's own judgement.
      const handoff = /\b(my account|billing|refund my|cancel my|password|can't log ?in|login issue)\b/i.test(q);

      return json({ answer: answer || "I didn't quite catch that — could you rephrase?", handoff }, 200, h);
    } catch (err) {
      return json({ answer: "I'm having trouble reaching the brain right now. Email hi@eevsec.com and a human will pick up — usually within one business day.", handoff: true }, 502, h);
    }
  },
};
