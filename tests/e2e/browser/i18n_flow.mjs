// 영어 화면 시험: 브라우저 언어가 영어면 주요 화면에 한국어가 남지 않아야 한다 (edge_flow.sh가 띄운 Hub)
import { chromium } from 'playwright';

const { BASE, SESSION } = process.env;
let failed = 0;
const ok = (m) => console.log(`  ok   ${m}`);
const bad = (m) => { console.log(`  FAIL ${m}`); failed++; };

const browser = await chromium.launch();
try {
  const ctx = await browser.newContext({ locale: 'en-US', viewport: { width: 1100, height: 800 } });
  const [name, value] = SESSION.split('=');
  await ctx.addCookies([{ name, value, domain: 'localhost', path: '/' }]);
  const errs = [];
  const left = {};
  for (const path of ['/', '/dashboard', '/node?id=1', '/services', '/security', '/settings', '/account', '/privacy']) {
    const page = await ctx.newPage();
    page.on('pageerror', (e) => errs.push(`${path} ${e}`));
    await page.goto(`${BASE}${path}`);
    await page.waitForTimeout(800);
    const ko = await page.evaluate(() => {
      const out = [];
      const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      while (w.nextNode()) {
        const n = w.currentNode;
        if (/[가-힣]/.test(n.nodeValue) && !n.parentElement.closest('[data-no-i18n],option,.only-ko,code,pre,script')) out.push(n.nodeValue.trim());
      }
      for (const e of document.querySelectorAll('[placeholder],[title],[aria-label]'))
        for (const a of ['placeholder', 'title', 'aria-label']) {
          const v = e.getAttribute(a);
          if (v && /[가-힣]/.test(v)) out.push(`@${a}: ${v}`);
        }
      if (/[가-힣]/.test(document.title)) out.push(`title: ${document.title}`);
      return out;
    });
    if (ko.length) left[path] = ko;
    await page.close();
  }
  Object.keys(left).length === 0 ? ok('영어 화면에 한국어 없음 (8개 화면)') : bad(`남은 한국어: ${JSON.stringify(left)}`);
  errs.length === 0 ? ok('영어 화면 스크립트 오류 없음') : bad(errs.join(' | '));

  // 메뉴 이름 (사전 값이 다른 곳에서 덮어써지지 않았는지)
  const nav = await ctx.newPage();
  await nav.goto(`${BASE}/`);
  const labels = (await nav.locator('.side .nav-item span:not(.count)').allInnerTexts()).map((s) => s.trim());
  JSON.stringify(labels) === JSON.stringify(['Home', 'Servers', 'Services', 'Security', 'Settings', 'Account'])
    ? ok('영어 메뉴 이름') : bad(`메뉴 이름 ${JSON.stringify(labels)}`);
  await nav.close();

  // 언어 바꾸기 → 한국어
  const page = await ctx.newPage();
  await page.goto(`${BASE}/services`);
  await page.locator('.lang-switch').click();
  await page.waitForLoadState('load');
  await page.waitForTimeout(500);
  (await page.locator('h1').first().innerText()) === '서비스' ? ok('언어 바꾸기 → 한국어 (저장됨)') : bad(`언어 바꾸기 (${await page.locator('h1').first().innerText()})`);
} finally {
  await browser.close();
}
process.exit(failed ? 1 : 0);
