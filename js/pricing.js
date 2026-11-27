(async () => {
  'use strict';
  const script = document.currentScript;
  const header = document.getElementById('siteHeader');
  const price = document.getElementById('individual-price');
  if (!header || !script) return;
  // Hide region-dependent numbers until we know the visitor's country, so India never flashes the USD offer.
  document.documentElement.classList.add('promo-pending');

  const banner = document.createElement('a');
  banner.className = 'promo-banner';
  banner.href = new URL('../pricing', script.src).href;
  banner.innerHTML = `
    <span class="promo-banner__glitter" aria-hidden="true">
      <span style="--x:4%;--y:24%;--delay:0.1s">✦</span>
      <span style="--x:9%;--y:65%;--delay:0.4s">✧</span>
      <span style="--x:14%;--y:18%;--delay:0.6s">✦</span>
      <span style="--x:21%;--y:79%;--delay:0.3s">✧</span>
      <span style="--x:35%;--y:82%;--delay:0.7s">✦</span>
      <span style="--x:57%;--y:76%;--delay:0.2s">✧</span>
      <span style="--x:73%;--y:83%;--delay:0.5s">✦</span>
      <span style="--x:86%;--y:20%;--delay:0.7s">✧</span>
      <span style="--x:91%;--y:64%;--delay:0.3s">✦</span>
      <span style="--x:96%;--y:24%;--delay:0.5s">✧</span>
      <img class="promo-banner__alien" alt="" width="32" height="32">
    </span>
    <span class="promo-banner__inner">
      <span class="promo-banner__copy">
        <strong>Black Friday Access? Granted.</strong>
        <span>Unlock <b><span data-promo="discount">25%</span> off CyberRange</b></span>
        <span class="promo-banner__redemption">
          <span>with code <code><b>ROOTACCESS</b></code>.</span>
          <span class="promo-banner__action">Claim offer <span aria-hidden="true">→</span></span>
        </span>
      </span>
    </span>`;
  // Alien monster: Microsoft Fluent Emoji 3D, MIT License, (c) Microsoft Corporation.
  banner.querySelector('img').src = new URL('../media/promo-alien.webp', script.src).href;
  header.before(banner);

  // Let the strip scroll away while the shared navbar stays fixed.
  const positionHeader = () => {
    header.style.top = `${Math.max(0, banner.offsetHeight - window.scrollY)}px`;
  };
  positionHeader();
  window.addEventListener('scroll', positionHeader, { passive: true });
  window.addEventListener('resize', positionHeader);
  if ('ResizeObserver' in window) new ResizeObserver(positionHeader).observe(banner);

  // The alien roams one side, fades out at that end of the copy, and fades back in at the other end,
  // so it never crosses the text. Positions are measured, so re-run on resize.
  const alien = banner.querySelector('.promo-banner__alien');
  const copy = banner.querySelector('.promo-banner__copy');
  let flight;
  const startFlight = () => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const box = banner.getBoundingClientRect();
    const text = copy.getBoundingClientRect();
    const half = alien.offsetWidth / 2;
    const edgeL = half + 4, edgeR = box.width - half - 4;
    const lp = Math.max(edgeL, text.left - box.left - 14);
    const rp = Math.min(edgeR, text.right - box.left + 14);
    const bob = Math.max(0, Math.min(8, box.height / 2 - half));
    const at = (offset, x, y, turn, opacity = 1) => ({
      offset, easing: 'ease-in-out', opacity,
      transform: `translate(${Math.min(edgeR, Math.max(edgeL, x)) - half}px, ${y}px) rotate(${turn}deg)`,
    });
    const alienPath = [
      at(0, lp, 0, 0, 0), // fade in on the left
      at(0.05, lp - 22, 0, -6),
      at(0.17, edgeL, -bob, -12),
      at(0.29, (edgeL + lp) / 2, bob, 10),
      at(0.4, lp - 26, 0, 0),
      at(0.46, lp, 0, 0, 0), // fade out on the left…
      at(0.5, rp, 0, 0, 0), // …and back in on the right
      at(0.55, rp + 22, 0, 6),
      at(0.67, edgeR, bob, 12),
      at(0.79, (rp + edgeR) / 2, -bob, -10),
      at(0.9, rp + 26, 0, 0),
      at(0.96, rp, 0, 0, 0), // fade out on the right
      at(1, lp, 0, 0, 0),
    ];
    const time = flight?.currentTime ?? 0;
    flight?.cancel();
    flight = alien.animate(alienPath, { duration: 16000, iterations: Infinity });
    flight.currentTime = time;
  };
  startFlight();
  window.addEventListener('resize', startFlight);
  document.fonts?.ready.then(startFlight);
  if ('ResizeObserver' in window) new ResizeObserver(startFlight).observe(copy);

  window.crIndividualPrice = (async () => {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 3000);
    try {
      const response = await fetch('/cdn-cgi/trace', {
        cache: 'no-store',
        credentials: 'omit',
        redirect: 'error',
        signal: controller.signal,
      });
      if (response.ok && response.headers.get('content-type')?.startsWith('text/plain') &&
          /^loc=IN\r?$/m.test(await response.text())) return '₹1599';
    } catch {
      // Fall back to USD if country detection is unavailable.
    } finally {
      window.clearTimeout(timeout);
    }
    return '$20';
  })();

  const regularPrice = await window.crIndividualPrice;
  if (price) price.textContent = regularPrice;
  if (regularPrice === '₹1599') {
    document.querySelectorAll('[data-promo="discount"]').forEach(el => { el.textContent = '50%'; });
    document.querySelectorAll('[data-promo="price"]').forEach(el => { el.textContent = '₹799'; });
  }
  document.documentElement.classList.remove('promo-pending');
})();
