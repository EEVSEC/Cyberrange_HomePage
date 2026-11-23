(async () => {
  'use strict';
  const price = document.getElementById('individual-price');
  if (!price) return;

  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 3000);

  try {
    const response = await fetch('/cdn-cgi/trace', {
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      signal: controller.signal,
    });

    if (response.ok && response.headers.get('content-type')?.startsWith('text/plain')) {
      if (/^loc=IN\r?$/m.test(await response.text())) price.textContent = '₹1499';
    }
  } catch {
    // Keep the USD price if country detection is unavailable.
  } finally {
    window.clearTimeout(timeout);
  }
})();
