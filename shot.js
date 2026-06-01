const { chromium } = require('/home/dk5288/.npm/_npx/4de92097080e5d0d/node_modules/playwright');
const EXE = '/scratch/dk5288/tmp/pw-browsers/chromium_headless_shell-1155/chrome-linux/headless_shell';

(async () => {
  const browser = await chromium.launch({ executablePath: EXE });

  // 1) Standalone reel — sample each scene at its midpoint (real-time).
  const moments = { intro: 1.4, battle: 5.0, practice: 8.6, learn: 11.9, analyze: 15.4, coach: 18.8, outro: 22.8 };
  const reErr = [];
  for (const [name, t] of Object.entries(moments)) {
    const page = await browser.newPage({ viewport: { width: 1000, height: 1250 }, deviceScaleFactor: 1 });
    page.on('pageerror', e => reErr.push(name + ': ' + e.message));
    await page.goto('http://localhost:8765/modes-reel.html', { waitUntil: 'load' });
    await page.waitForTimeout(1600 + t * 1000); // CDN/babel warmup + scene time
    await page.screenshot({ path: `/scratch/dk5288/v4/_shot_reel_${name}.png`, animations: 'disabled' });
    await page.close();
  }
  console.log('reel pageerrors:', JSON.stringify([...new Set(reErr)].slice(0, 8)));

  // 2) Index modes section, dark theme.
  const p2 = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const e2 = [];
  p2.on('pageerror', err => e2.push('PAGEERR: ' + err.message));
  await p2.goto('http://localhost:8765/index.html', { waitUntil: 'load' });
  await p2.addStyleTag({ content: 'html{scroll-behavior:auto!important}' });
  await p2.evaluate(() => {
    const i = document.getElementById('intro'); if (i) i.style.display = 'none';
    document.documentElement.classList.add('intro-done');
    document.querySelectorAll('.reveal').forEach(e => e.classList.add('in'));
  });
  await p2.evaluate(() => document.getElementById('modes').scrollIntoView());
  await p2.waitForTimeout(4000);
  await p2.screenshot({ path: '/scratch/dk5288/v4/_shot_index_modes.png', animations: 'disabled' });
  console.log('index pageerrors:', JSON.stringify(e2.slice(0, 8)));

  await browser.close();
})();
