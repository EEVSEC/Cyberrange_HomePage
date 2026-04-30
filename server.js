const http  = require("http");
const https = require("https");
const fs    = require("fs");
const path  = require("path");
const { URL: NodeURL } = require("url");

const root = process.cwd();
const port = 8000;

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

  let filePath = decodeURIComponent(req.url.split("?")[0]);
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
      const range = req.headers.range;
      if (!range) {
        res.writeHead(200, { "Content-Type": contentType, "Content-Length": stat.size, "Accept-Ranges": "bytes", "Cache-Control": cc });
        return fs.createReadStream(fullPath).pipe(res);
      }
      const parts     = range.replace(/bytes=/, "").split("-");
      const start     = parseInt(parts[0], 10);
      const end       = parts[1] ? parseInt(parts[1], 10) : stat.size - 1;
      const chunkSize = end - start + 1;
      res.writeHead(206, { "Content-Range": `bytes ${start}-${end}/${stat.size}`, "Accept-Ranges": "bytes", "Content-Length": chunkSize, "Content-Type": contentType, "Cache-Control": cc });
      return fs.createReadStream(fullPath, { start, end }).pipe(res);
    }

    res.writeHead(200, { "Content-Type": contentType, "Content-Length": stat.size, "Cache-Control": cc });
    fs.createReadStream(fullPath).pipe(res);
  });
}).listen(port, "0.0.0.0", () => {
  console.log(`Server running at http://127.0.0.1:${port}`);
});
