#!/usr/bin/env python3
"""Generate per-page Open Graph images (1200x630) for EEVSEC CyberRange (T-13/S-03).

On-brand template: dark #0b0d0c background, Noto Sans (no brand fonts locally),
emerald accent. Re-run after copy changes. Build-excluded (see _config.yml).
Outputs to media/og/<slug>.png.
"""
import os
from PIL import Image, ImageDraw, ImageFont

W, H, M = 1200, 630, 84
BG    = (11, 13, 12)
PANEL = (26, 29, 27)
INK   = (242, 242, 242)
MUTED = (150, 150, 150)
EMER  = (95, 224, 160)

FONT    = "/usr/share/fonts/google-noto-vf/NotoSans[wght].ttf"
FONT_IT = "/usr/share/fonts/google-noto-vf/NotoSans-Italic[wght].ttf"

def font(size, weight="Bold", italic=False):
    f = ImageFont.truetype(FONT_IT if italic else FONT, size)
    try: f.set_variation_by_name(weight)
    except Exception: pass
    return f

def wrap(d, text, fnt, maxw):
    out, cur = [], ""
    for w in text.split():
        t = (cur + " " + w).strip()
        if d.textlength(t, font=fnt) <= maxw: cur = t
        else:
            if cur: out.append(cur)
            cur = w
    if cur: out.append(cur)
    return out

def make(slug, eyebrow, title, subtitle):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    # frame + faint inner border
    d.rectangle([0, 0, W - 1, H - 1], outline=PANEL, width=2)
    # soft emerald accent: a thin bar down the left margin
    d.rectangle([M, M, M + 5, H - M], fill=EMER)
    cx = M + 34  # content x (clears the bar)
    maxw = W - cx - M

    # brand lock-up (top): ईव mark + wordmark
    wx = cx
    try:
        mark = Image.open("logo-light.png").convert("RGBA")
        mh = 50
        mw = int(mark.width * mh / mark.height)
        mark = mark.resize((mw, mh), Image.LANCZOS)
        img.paste(mark, (cx, M - 16), mark)
        wx = cx + mw + 20
    except Exception:
        pass
    fwm = font(36, "Bold")
    d.text((wx, M - 4), "Cyber", font=fwm, fill=INK)
    w1 = d.textlength("Cyber", font=fwm)
    d.text((wx + w1, M - 4), "Range", font=fwm, fill=EMER)
    # top-right label
    flab = font(20, "SemiBold")
    lab = "EEVSEC"
    d.text((W - M - d.textlength(lab, font=flab), M + 2), lab, font=flab, fill=MUTED)

    # eyebrow
    fey = font(23, "SemiBold")
    ey = eyebrow.upper()
    ey_y = 196
    d.text((cx, ey_y), ey, font=fey, fill=EMER)

    # title + subtitle, budget-aware: shrink the title until the whole block
    # (title lines + gap + up to 2 subtitle lines) fits above the footer.
    title_start = ey_y + 52
    BOTTOM = H - M - 58              # subtitle must end by here
    fsub = font(27, "Medium")
    slines = wrap(d, subtitle, fsub, maxw)[:2] if subtitle else []
    sh = 37 * len(slines)
    gap = 20 if slines else 0
    size = 80
    while size >= 48:
        ft = font(size, "Bold")
        lines = wrap(d, title, ft, maxw)
        lead = int(size * 1.06)
        if len(lines) <= 3 and title_start + lead * len(lines) + gap + sh <= BOTTOM:
            break
        size -= 4
    ty = title_start
    for ln in lines:
        d.text((cx, ty), ln, font=ft, fill=INK)
        ty += lead

    # subtitle
    sy = ty + gap
    for ln in slines:
        d.text((cx, sy), ln, font=fsub, fill=MUTED)
        sy += 37

    # footer
    ffoot = font(22, "SemiBold")
    d.line([(cx, H - M - 30), (W - M, H - M - 30)], fill=PANEL, width=2)
    d.text((cx, H - M - 12), "eevsec.com", font=ffoot, fill=MUTED)
    tag = "Attack. Defend. Repeat."
    d.text((W - M - d.textlength(tag, font=ffoot), H - M - 12), tag, font=ffoot, fill=EMER)

    os.makedirs("media/og", exist_ok=True)
    path = f"media/og/{slug}.png"
    img.save(path, optimize=True)
    return path


PAGES = {
    "home":      ("Live-fire cyber range", "Still practicing on fake boxes?", "Attack, defend, and decide under pressure on real machines — with an AI coach that explains every move."),
    "pricing":   ("Pricing", "Five tiers. One arena.", "From a free Recruit pass to enterprise Warlord — in USD, INR, and AED."),
    "doctrine":  ("Doctrine", "Three layers. One engagement.", "WAR · Ethical Hacking · Cyber Crime — every scenario runs on all three."),
    "news":      ("Newsroom", "Why hands-on training wins.", "The external research that explains adversarial training — read through the doctrine."),
    "faq":       ("FAQ", "Questions, answered.", "What CyberRange is, how live matches work, and how to get in."),
    "about":     ("Team", "The operators behind EEVSEC.", "Built by people who train the way they fight."),
    "contact":   ("Contact", "Talk to the team.", "Sales, security, press, or support — one inbox, clear paths."),
    "careers":   ("Careers", "Build the arena.", "Platform, scenario design, AI coaching, and security research."),
    "security":  ("Security", "Responsible disclosure.", "Report a vulnerability — safe harbour for good-faith research."),
    "for-corporate":      ("For corporate", "Sharpen the whole org.", "Live-fire reps for teams that defend real infrastructure."),
    "for-security-teams": ("For security teams", "Drill incident response.", "Blue-team reps against a live adversary, scored by an AI coach."),
    "for-universities":   ("For universities", "Hands-on labs that scale.", "Real machines, real opponents — no lab to rack and maintain."),
    "iot-semiconductor":  ("Scenario · Device-layer", "IoT & Semiconductor", "Firmware, hardware, and chip-level attack surfaces."),
    "digital-forensics":  ("Scenario · Post-breach", "Digital Forensics", "Memory, network, and disk evidence under live pressure."),
    "cloud-zero-trust":   ("Scenario · Enterprise", "Cloud & Zero Trust", "Misconfigs and lateral movement across AWS, Azure, and GCP."),
    "adversarial-ai":     ("Scenario · AI vs AI", "Adversarial AI", "AI agents attack and defend — the richest signal."),
    "red-blue-automation":("Scenario · Generative", "Red & Blue Automation", "Novel attack and defense chains from real sessions."),
    "scada-ics":          ("Scenario · Nation-state", "SCADA / ICS", "Power grids, water, and industrial controls."),
}

if __name__ == "__main__":
    import sys
    only = sys.argv[1:] if len(sys.argv) > 1 else None
    for slug, (e, t, s) in PAGES.items():
        if only and slug not in only: continue
        print("wrote", make(slug, e, t, s))
