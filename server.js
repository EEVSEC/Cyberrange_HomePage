const http  = require("http");
const https = require("https");
const fs    = require("fs");
const path  = require("path");
const { URL: NodeURL } = require("url");

const root = process.cwd();
const port = 8000;
// Google's public reCAPTCHA v2 test site key, served only by the loopback preview.
const RECAPTCHA_DEV_SITE_KEY = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI";
const sentinelEndpoint = process.env.SENTINEL_DEV_ENDPOINT
  ? new NodeURL(process.env.SENTINEL_DEV_ENDPOINT)
  : null;
if (sentinelEndpoint && (sentinelEndpoint.protocol !== "https:" || sentinelEndpoint.username || sentinelEndpoint.password)) {
  throw new Error("SENTINEL_DEV_ENDPOINT must be an HTTPS URL without credentials.");
}

const HCAPTCHA_SECRET = process.env.HCAPTCHA_SECRET || "";
const LOOPS_FORM_ID   = "cmog6m7fn0i650h1tir5n4smw";

const mime = {
  ".html": "text/html",
  ".css":  "text/css",
  ".js":   "application/javascript",
  ".png":  "image/png",
  ".jpg":  "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif":  "image/gif",
  ".webp": "image/webp",
  ".svg":  "image/svg+xml",
  ".mp4":  "video/mp4",
  ".ico":  "image/x-icon",
  ".xml":  "application/xml",
  ".txt":  "text/plain",
  ".woff2": "font/woff2",
  ".ttf":  "font/ttf",
};

const cacheControl = {
  ".html": "no-cache",
  ".css":  "public, max-age=31536000, immutable",
  ".js":   "public, max-age=31536000, immutable",
  ".png":  "public, max-age=31536000, immutable",
  ".jpg":  "public, max-age=31536000, immutable",
  ".jpeg": "public, max-age=31536000, immutable",
  ".gif":  "public, max-age=31536000, immutable",
  ".webp": "public, max-age=31536000, immutable",
  ".svg":  "public, max-age=31536000, immutable",
  ".mp4":  "public, max-age=86400",
  ".ico":  "public, max-age=31536000, immutable",
};

/* ── IP-based rate limiting: max 3 submissions per 10 minutes ── */
const ipSubmits      = new Map();
const RATE_WINDOW_MS = 10 * 60 * 1000;
const RATE_MAX       = 3;

function checkRateLimit(ip) {
  const now = Date.now();
  let e = ipSubmits.get(ip);
  if (!e || now > e.resetAt) e = { count: 0, resetAt: now + RATE_WINDOW_MS };
  if (e.count >= RATE_MAX) { ipSubmits.set(ip, e); return false; }
  e.count++;
  ipSubmits.set(ip, e);
  return true;
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, e] of ipSubmits) if (now > e.resetAt) ipSubmits.delete(ip);
}, 5 * 60 * 1000).unref();

/* ── Outbound HTTPS POST helper ── */
function httpsPost(url, bodyStr) {
  return new Promise((resolve, reject) => {
    const u = new NodeURL(url);
    const req = https.request({
      hostname: u.hostname,
      path: u.pathname + (u.search || ""),
      method: "POST",
      headers: {
        "Content-Type":   "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(bodyStr),
      },
    }, (res) => {
      let data = "";
      res.on("data", c => data += c);
      res.on("end",  () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", reject);
    req.write(bodyStr);
    req.end();
  });
}

/* ── Read and size-limit request body ── */
function readBody(req, maxBytes = 4096) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", c => {
      body += c;
      if (body.length > maxBytes) { req.destroy(); reject(new Error("body too large")); }
    });
    req.on("end",   () => resolve(body));
    req.on("error", reject);
  });
}

/* ── POST /api/join — verify captcha → proxy to Loops ── */
async function handleJoin(req, res) {
  if (req.method !== "POST") {
    res.writeHead(405, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ success: false, message: "Method not allowed." }));
  }

  const ip = ((req.headers["x-forwarded-for"] || "") + "," + (req.socket.remoteAddress || ""))
    .split(",")[0].trim() || "unknown";

  if (!checkRateLimit(ip)) {
    res.writeHead(429, { "Content-Type": "application/json", "Retry-After": "600" });
    return res.end(JSON.stringify({ success: false, message: "Too many attempts. Please wait 10 minutes." }));
  }

  let rawBody;
  try { rawBody = await readBody(req); }
  catch { res.writeHead(400); return res.end("Bad Request"); }

  const params = new URLSearchParams(rawBody);
  const captchaToken = params.get("h-captcha-response") || "";

  if (!captchaToken) {
    res.writeHead(400, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ success: false, message: "CAPTCHA response missing." }));
  }

  /* Verify with hCaptcha */
  let verifData;
  try {
    const verifBody = new URLSearchParams({
      secret:   HCAPTCHA_SECRET,
      response: captchaToken,
      remoteip: ip,
    }).toString();
    const r = await httpsPost("https://hcaptcha.com/siteverify", verifBody);
    verifData = JSON.parse(r.body);
  } catch (err) {
    console.error("hCaptcha verify error:", err.message);
    res.writeHead(502, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ success: false, message: "Captcha verification unavailable. Try again." }));
  }

  if (!verifData.success) {
    res.writeHead(400, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ success: false, message: "Captcha check failed. Please try again." }));
  }

  /* Forward to Loops.so */
  let loopsRes;
  try {
    const loopsBody = new URLSearchParams({
      email:     params.get("email")     || "",
      firstName: params.get("firstName") || "",
      lastName:  params.get("lastName")  || "",
      role:      params.get("role")      || "",
    }).toString();
    loopsRes = await httpsPost(
      `https://app.loops.so/api/newsletter-form/${LOOPS_FORM_ID}`,
      loopsBody
    );
  } catch (err) {
    console.error("Loops.so error:", err.message);
    res.writeHead(502, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ success: false, message: "Submission failed. Please try again." }));
  }

  res.writeHead(loopsRes.status, { "Content-Type": "application/json" });
  res.end(loopsRes.body);
}

/* ── Main HTTP server ── */
http.createServer(async (req, res) => {
  res.setHeader("X-Content-Type-Options", "nosniff");

  if (req.url === "/api/join" || req.url.startsWith("/api/join?")) {
    return handleJoin(req, res);
  }

  if (req.method !== "GET" && req.method !== "HEAD") {
    res.writeHead(405, { Allow: "GET, HEAD" });
    return res.end("Method not allowed");
  }

  let filePath;
  try {
    filePath = decodeURIComponent(req.url.split("?")[0]);
  } catch {
    res.writeHead(400);
    return res.end("Invalid path");
  }
  if (filePath.split("/").some(part => part.startsWith(".") && part !== ".well-known")) {
    res.writeHead(404);
    return res.end("Not found");
  }
  if (filePath === "/") filePath = "/index.html";

  const fullPath = path.join(root, filePath);
  const rootWithSep = root + path.sep;
  if (!fullPath.startsWith(rootWithSep) && fullPath !== root) {
    res.writeHead(403); return res.end("Forbidden");
  }

  fs.stat(fullPath, (err, stat) => {
    if (err || !stat.isFile()) {
      res.writeHead(404); return res.end("Not found");
    }

    const ext         = path.extname(fullPath).toLowerCase();
    const contentType = mime[ext] || "application/octet-stream";
    const cc          = cacheControl[ext] || "public, max-age=86400";

    if (ext === ".mp4") {
      const headers = { "Content-Type": contentType, "Accept-Ranges": "bytes", "Cache-Control": cc };
      const range = req.method === "GET" && req.headers.range;
      if (!range) {
        res.writeHead(200, { ...headers, "Content-Length": stat.size });
        if (req.method === "HEAD") return res.end();
        return fs.createReadStream(fullPath).pipe(res);
      }

      const match = /^bytes=(\d*)-(\d*)$/.exec(range);
      let start;
      let end;
      if (match?.[1]) {
        start = Number(match[1]);
        end = Math.min(match[2] ? Number(match[2]) : stat.size - 1, stat.size - 1);
      } else if (match?.[2]) {
        start = Math.max(stat.size - Number(match[2]), 0);
        end = stat.size - 1;
      }
      if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start > end) {
        res.writeHead(416, { "Content-Range": `bytes */${stat.size}` });
        return res.end();
      }
      res.writeHead(206, {
        ...headers,
        "Content-Range": `bytes ${start}-${end}/${stat.size}`,
        "Content-Length": end - start + 1,
      });
      return fs.createReadStream(fullPath, { start, end }).pipe(res);
    }

    if (ext === ".html") {
      // Local dev over plain HTTP: the inline CSP's `upgrade-insecure-requests`
      // forces subresources to https (no TLS here) → strip it so CSS/JS load.
      let html = fs.readFileSync(fullPath, "utf8")
        .replace(/\s*;?\s*upgrade-insecure-requests/g, "");
      if (html.includes("js/recaptcha.js")) {
        html = html.replace("</head>", `<script>window.CR_DEV_RECAPTCHA_SITE_KEY = ${JSON.stringify(RECAPTCHA_DEV_SITE_KEY)};</script>\n</head>`);
      }
      if (sentinelEndpoint && html.includes("js/sentinel.js")) {
        const endpoint = JSON.stringify(sentinelEndpoint.href).replace(/</g, "\\u003c");
        html = html
          .replace("connect-src 'self'", `connect-src 'self' ${sentinelEndpoint.origin}`)
          .replace("</head>", `<script>window.SENTINEL_ENDPOINT = ${endpoint};</script>\n</head>`);
      }
      const buf = Buffer.from(html, "utf8");
      res.writeHead(200, { "Content-Type": contentType, "Content-Length": buf.length, "Cache-Control": cc });
      return res.end(buf);
    }

    res.writeHead(200, { "Content-Type": contentType, "Content-Length": stat.size, "Cache-Control": cc });
    fs.createReadStream(fullPath).pipe(res);
  });
}).listen(port, "127.0.0.1", () => {
  console.log(`Server running at http://127.0.0.1:${port}`);
});
