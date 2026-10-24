#!/usr/bin/env python3
"""Generate per-page Open Graph images (1200x630) for EEVSEC CyberRange (T-13/S-03).

Follows the EEVSEC brand kit: paper ground with a pearl-silver wash, the EEVSEC.
lockup, EEVSEC Serif headlines (weight 400) with navy italic emphasis, hairline rules.
Mark a phrase as emphasis with *asterisks* in a title.
Re-run after copy changes: `python3 make_og.py [slug ...]` from the repo root.
Build-excluded (see _config.yml). Outputs media/og/<slug>.png (and media/og-eev.png).
"""
import os
from PIL import Image, ImageDraw, ImageFilter, ImageFont

W, H, M = 1200, 630, 72
PAPER = (246, 244, 239)
NAVY = (27, 53, 87)
INK = (0, 0, 0)
MUTED = (81, 91, 103)
LINE = (186, 196, 209)           # brand hairline (navy @ 20%) pre-blended over the pearl wash
PEARL = [(203, 212, 219), (229, 234, 240), (248, 250, 252), (255, 255, 255)]

SERIF = "fonts/EEVSECSerif.ttf"
ICON = "brand/eevsec-icon-512.png"
# the wordmark is set in Times New Roman in the brand kit; fall back to the brand serif
TIMES = [
    "/System/Library/Fonts/Supplemental/Times New Roman.ttf",
    "/usr/share/fonts/truetype/msttcorefonts/Times_New_Roman.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSerif-Regular.ttf",
]
# EEVSEC Serif has no glyph for these; draw them from a system serif instead
FALLBACK_FONTS = [
    "/System/Library/Fonts/Supplemental/Georgia.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf",
]
MISSING = set("+<=>^_`|—–·’‘“”…→")


def load(paths, size):
    for p in paths:
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.truetype(SERIF, size)


def serif(size):
    return ImageFont.truetype(SERIF, size)


def fallback(size):
    return load(FALLBACK_FONTS, size)


def text_len(d, s, size, tracking=0):
    f, fb = serif(size), fallback(size)
    return sum(d.textlength(c, font=fb if c in MISSING else f) + tracking for c in s)


def draw_text(img, xy, s, size, fill, tracking=0, italic=False):
    """Draw s at xy (top-left). italic = the browser-style synthetic slant the site uses."""
    f, fb = serif(size), fallback(size)
    d0 = ImageDraw.Draw(img)
    width = int(text_len(d0, s, size, tracking)) + size
    layer = Image.new("RGBA", (width, int(size * 1.5)), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    x = 0
    for c in s:
        fnt = fb if c in MISSING else f
        ld.text((x, 0), c, font=fnt, fill=fill)
        x += ld.textlength(c, font=fnt) + tracking
    if italic:
        k, base = 0.2, size * 1.0
        layer = layer.transform(layer.size, Image.AFFINE, (1, k, -k * base, 0, 1, 0), Image.BICUBIC)
    img.alpha_composite(layer, (int(xy[0]), int(xy[1])))
    return x


def parse(title):
    """'Free to start. *Custom to scale.*' -> [(word, italic), ...]"""
    words, em = [], False
    for chunk in title.split("*"):
        for w in chunk.split():
            words.append((w, em))
        em = not em
    return words


def layout(d, words, size, maxw):
    lines, cur, curw = [], [], 0
    space = text_len(d, " ", size)
    for w, it in words:
        wl = text_len(d, w, size) + (size * 0.12 if it else 0)
        if cur and curw + space + wl > maxw:
            lines.append(cur)
            cur, curw = [], 0
        curw += (space if cur else 0) + wl
        cur.append((w, it))
    if cur:
        lines.append(cur)
    return lines


def wrap(d, s, size, maxw):
    out, cur = [], ""
    for w in s.split():
        t = (cur + " " + w).strip()
        if text_len(d, t, size) <= maxw:
            cur = t
        else:
            out.append(cur)
            cur = w
    if cur:
        out.append(cur)
    return out


def silk():
    """Pearl-silver wash: soft diagonal folds, fading into the paper at the bottom."""
    g = Image.new("RGB", (W, H), PEARL[2])
    gd = ImageDraw.Draw(g)
    for y in range(H):  # diagonal base gradient
        t = y / H
        c = tuple(int(PEARL[0][i] * (1 - t) + PEARL[3][i] * t) for i in range(3))
        gd.line([(0, y), (W, y)], fill=c)
    folds = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    fd = ImageDraw.Draw(folds)
    for box, col in [((-200, -260, 560, 380), (203, 212, 219, 200)), ((520, -180, 1380, 300), (229, 234, 240, 230)),
                     ((300, 120, 1300, 720), (255, 255, 255, 220)), ((-300, 250, 500, 800), (248, 250, 252, 200)),
                     ((760, -60, 1500, 520), (203, 212, 219, 150))]:
        fd.ellipse(box, fill=col)
    folds = folds.filter(ImageFilter.GaussianBlur(70))
    g = g.convert("RGBA")
    g.alpha_composite(folds)
    mask = Image.new("L", (W, H), 255)  # fade the wash out toward the bottom edge
    md = ImageDraw.Draw(mask)
    for y in range(H):
        md.line([(0, y), (W, y)], fill=int(255 * max(0, min(1, (H - y) / 260))) if y > H - 260 else 255)
    base = Image.new("RGBA", (W, H), PAPER + (255,))
    base.paste(g, (0, 0), mask)
    return base


def lockup(img, x, y):
    """The header lockup from the kit: black rounded square with the symbol, then EEVSEC."""
    s = 56
    sq = Image.new("RGBA", (s * 4, s * 4), (0, 0, 0, 0))
    ImageDraw.Draw(sq).rounded_rectangle([0, 0, s * 4 - 1, s * 4 - 1], radius=int(s * 4 * 0.185), fill=(0, 0, 0, 255))
    sq = sq.resize((s, s), Image.LANCZOS)
    sym = Image.open(ICON).convert("RGBA").resize((s, s), Image.LANCZOS)
    sq.alpha_composite(sym)
    img.alpha_composite(sq, (x, y))
    ft = load(TIMES, 46)
    ImageDraw.Draw(img).text((x + s + 16, y + s / 2 + 1), "EEVSEC.", font=ft, fill=INK, anchor="lm")


def make(slug, eyebrow, title, subtitle, out=None):
    img = silk()
    d = ImageDraw.Draw(img)

    lockup(img, M, M - 6)
    lab = "CyberRange"
    lw = text_len(d, lab, 28)
    draw_text(img, (W - M - lw, M + 4), lab, 28, MUTED)
    d.line([(M, M + 66), (W - M, M + 66)], fill=LINE, width=1)

    # eyebrow: small uppercase, tracked
    draw_text(img, (M, 196), eyebrow.upper(), 20, NAVY, tracking=3.2)

    # title: shrink until title + subtitle fit above the footer rule
    maxw = W - 2 * M
    bottom = H - M - 52
    fsub = 30
    slines = wrap(d, subtitle, fsub, maxw)[:2] if subtitle else []
    sh = int(fsub * 1.4) * len(slines)
    gap = 34 if slines else 0
    words = parse(title)
    top = 236
    for size in range(96, 51, -4):
        lines = layout(d, words, size, maxw)
        lead = int(size * 1.02)
        if len(lines) <= 3 and top + lead * len(lines) + gap + sh <= bottom:
            break
    y = top
    for ln in lines:
        x = M
        for w, it in ln:
            adv = draw_text(img, (x, y), w, size, NAVY if it else INK, italic=it)
            x += text_len(d, w, size) + (size * 0.12 if it else 0) + text_len(d, " ", size)
        y += lead
    y += gap
    for ln in slines:
        draw_text(img, (M, y), ln, fsub, MUTED)
        y += int(fsub * 1.4)

    # footer
    d.line([(M, H - M - 14), (W - M, H - M - 14)], fill=LINE, width=1)
    draw_text(img, (M, H - M - 2), "eevsec.com", 24, MUTED)
    tag = "Security, made visible."
    tw = text_len(d, tag, 26)
    draw_text(img, (W - M - tw - 4, H - M - 4), tag, 26, NAVY, italic=True)

    path = out or f"media/og/{slug}.png"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    img.convert("RGB").save(path, optimize=True)
    return path


PAGES = {
    "home":      ("Live-fire cyber range", "Still practicing on *fake boxes?*", "Attack, defend, and decide under pressure on real machines, with an AI coach that explains every move."),
    "pricing":   ("Pricing", "Free to start. *Custom to scale.*", "A free tier to get on the range, and custom terms for teams and organisations."),
    "doctrine":  ("Doctrine", "Three layers. *One engagement.*", "WAR, Ethical Hacking, Cyber Crime: every scenario runs on all three."),
    "news":      ("Newsroom", "Why hands-on training *wins.*", "The external research that explains adversarial training, read through the doctrine."),
    "faq":       ("FAQ", "Questions, *answered.*", "What CyberRange is, how live matches work, and how to get in."),
    "contact":   ("Contact", "Reach the *right human.*", "Sales, security, press, or support: one inbox, clear paths."),
    "careers":   ("Careers", "Build the *arena.*", "Platform, scenario design, AI coaching, and security research."),
    "security":  ("Security", "Responsible *disclosure.*", "Report a vulnerability. Safe harbour for good-faith research."),
    "for-corporate":      ("For corporate", "Sharpen the *whole org.*", "Live-fire reps for teams that defend real infrastructure."),
    "for-security-teams": ("For security teams", "Drill *incident response.*", "Blue-team reps against a live adversary, scored by an AI coach."),
    "for-universities":   ("For universities", "Hands-on labs that *scale.*", "Real machines, real opponents, and no lab to rack and maintain."),
    "iot-semiconductor":  ("Scenario · Device-layer", "IoT & *Semiconductor*", "Firmware, hardware, and chip-level attack surfaces."),
    "digital-forensics":  ("Scenario · Post-breach", "Digital *Forensics*", "Memory, network, and disk evidence under live pressure."),
    "cloud-zero-trust":   ("Scenario · Enterprise", "Cloud & *Zero Trust*", "Misconfigs and lateral movement across AWS, Azure, and GCP."),
    "adversarial-ai":     ("Scenario · AI vs AI", "Adversarial *AI*", "AI agents attack and defend, the richest signal."),
    "red-blue-automation":("Scenario · Generative", "Red & Blue *Automation*", "Novel attack and defense chains from real sessions."),
    "scada-ics":          ("Scenario · Nation-state", "SCADA / *ICS*", "Power grids, water, and industrial controls."),
}
# shared card used by the legal pages (terms, cookies, ...)
EEV = ("EEVSEC", "Security, *made visible.*", "Security platforms for the people who need to learn, investigate, operate, and act.")

if __name__ == "__main__":
    import sys
    only = sys.argv[1:] if len(sys.argv) > 1 else None
    for slug, (e, t, s) in PAGES.items():
        if only and slug not in only:
            continue
        print("wrote", make(slug, e, t, s))
    if not only or "eev" in only:
        print("wrote", make("eev", *EEV, out="media/og-eev.png"))
