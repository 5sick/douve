// 역할별 화면 시험 (rbac_flow.sh가 띄운 Hub): 메뉴는 역할대로 보이고, 권한 밖 화면은 홈으로,
// 관리자 설정 화면에서 사용자 목록·권한 고르기가 동작하고 영어로도 한국어가 남지 않는다.
import { chromium } from 'playwright';

const { BASE, ADMIN, OP, APP } = process.env;
let failed = 0;
const ok = (m) => console.log(`  ok   ${m}`);
const bad = (m) => { console.log(`  FAIL ${m}`); failed++; };

const browser = await chromium.launch();
const ctxFor = async (token, locale = 'ko-KR') => {
  const ctx = await browser.newContext({ locale, viewport: { width: 1100, height: 800 } });
  await ctx.addCookies([{ name: 'douve_session', value: token, domain: 'localhost', path: '/' }]);
  return ctx;
};
// 메뉴 이름만 (옆의 숫자 배지는 빼고)
const navLabels = (page) => page.$$eval('nav.side a.nav-item', (as) => as.filter((a) => !a.hidden).map((a) => a.querySelector('span').textContent.trim()));
try {
  const errs = [];
  // 앱 사용자: 홈·계정만, 서버 화면으로 가면 홈으로
  let ctx = await ctxFor(APP);
  let page = await ctx.newPage();
  page.on('pageerror', (e) => errs.push(`app ${e}`));
  await page.goto(`${BASE}/`);
  await page.waitForTimeout(800);
  const appNav = await navLabels(page);
  JSON.stringify(appNav) === JSON.stringify(['홈', '계정']) ? ok('앱 사용자 메뉴: 홈·계정만') : bad(`앱 사용자 메뉴 ${appNav}`);
  await page.goto(`${BASE}/settings`);
  await page.waitForURL(`${BASE}/`, { timeout: 5000 }).then(() => ok('앱 사용자: 설정 화면 → 홈으로'), () => bad(`설정 화면에 머묾 ${page.url()}`));
  await ctx.close();

  // 운영자: 서버·서비스는 보이고 보안·설정은 안 보임
  ctx = await ctxFor(OP);
  page = await ctx.newPage();
  page.on('pageerror', (e) => errs.push(`op ${e}`));
  await page.goto(`${BASE}/dashboard`);
  await page.waitForTimeout(800);
  const opNav = await navLabels(page);
  JSON.stringify(opNav) === JSON.stringify(['홈', '서버', '서비스', '계정']) ? ok('운영자 메뉴: 보안·설정 없음') : bad(`운영자 메뉴 ${opNav}`);
  const cards = await page.$$eval('#nodes li, #nodes .node, [data-node-id]', (e) => e.length).catch(() => -1);
  const text = await page.textContent('body');
  text.includes('web1') && !text.includes('db1') ? ok('운영자 서버 화면: 허락된 서버만') : bad(`운영자 서버 화면 (${cards})`);
  await ctx.close();

  // 관리자 설정: 사용자 목록과 권한 고르기 (영어 화면으로 번역도 확인)
  ctx = await ctxFor(ADMIN, 'en-US');
  page = await ctx.newPage();
  page.on('pageerror', (e) => errs.push(`admin ${e}`));
  await page.goto(`${BASE}/settings`);
  await page.waitForTimeout(1000);
  const users = await page.$$eval('#users > li', (l) => l.length);
  users >= 3 ? ok(`관리자: 사용자 목록 ${users}명`) : bad(`사용자 목록 ${users}`);
  await page.selectOption('#invite-role', 'operator');
  await page.waitForTimeout(400);
  const nodeBoxes = await page.$$eval('#invite-access input[type=checkbox]', (l) => l.length);
  nodeBoxes >= 2 ? ok('초대: 운영자를 고르면 서버·앱 선택') : bad(`초대 권한 고르기 ${nodeBoxes}`);
  await page.click('#users > li button.small'); // 첫 사용자 "권한" 펼치기
  await page.waitForTimeout(300);
  if (process.env.SHOT) await page.screenshot({ path: process.env.SHOT, fullPage: true });
  const ko = await page.evaluate(() => {
    const out = [];
    const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    while (w.nextNode()) {
      const n = w.currentNode;
      if (/[가-힣]/.test(n.nodeValue) && !n.parentElement.closest('[data-no-i18n],option,.only-ko,code,pre,script')) out.push(`${n.nodeValue.trim()} @ ${n.parentElement.outerHTML.slice(0, 120)}`);
    }
    return out;
  });
  ko.length === 0 ? ok('영어 설정 화면(사용자·권한)에 한국어 없음') : bad(`남은 한국어: ${JSON.stringify(ko)}`);
  await ctx.close();
  errs.length === 0 ? ok('스크립트 오류 없음') : bad(errs.join(' | '));
} finally {
  await browser.close();
}
console.log(failed ? `${failed} failed` : 'browser ok');
process.exit(failed ? 1 : 0);
