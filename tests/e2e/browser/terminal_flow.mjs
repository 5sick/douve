// 웹 터미널 브라우저 시험 (terminal_flow.sh가 Hub·Agent를 띄운 뒤 실행)
import { chromium } from 'playwright';

const { BASE, SESSION, NODE, ME } = process.env;
let failed = 0;
const ok = (m) => console.log(`  ok   ${m}`);
const bad = (m) => { console.log(`  FAIL ${m}`); failed++; };

const browser = await chromium.launch();
try {
  const ctx = await browser.newContext({ locale: 'ko-KR', viewport: { width: 1100, height: 700 } });
  await ctx.addCookies([{ name: 'douve_session', value: SESSION, domain: 'localhost', path: '/' }]);
  const page = await ctx.newPage();
  const errs = [];
  page.on('pageerror', (e) => errs.push(String(e)));
  page.on('console', (m) => { if (m.type() === 'error') errs.push(m.text()); });

  await page.goto(`${BASE}/terminal?node=${NODE}`);
  await page.waitForFunction(() => document.getElementById('term-status').textContent.includes('연결됨'), null, { timeout: 10000 })
    .then(() => ok('터미널 연결'), () => bad(`연결 (${errs.join(' | ')})`));
  await page.locator('.xterm').click();
  await page.keyboard.type('echo douve-$((40+2)); whoami\n');
  const rows = () => page.locator('.xterm-rows').innerText();
  await page.waitForFunction(() => document.querySelector('.xterm-rows').innerText.includes('douve-42'), null, { timeout: 5000 })
    .then(() => ok('명령 실행·출력'), async () => bad(`출력 (${await rows()})`));
  (await rows()).includes(ME) ? ok(`계정 ${ME}`) : bad('whoami');
  await page.keyboard.type('stty size\n');
  await page.waitForTimeout(500);
  /\d+ \d+/.test(await rows()) ? ok('터미널 크기 전달') : bad('stty size');
  await page.keyboard.type('read -s s; echo got-${#s}\n');
  await page.waitForTimeout(200);
  await page.keyboard.type('secret-input-xyz\n');
  await page.waitForFunction(() => document.querySelector('.xterm-rows').innerText.includes('got-16'), null, { timeout: 5000 })
    .then(() => ok('숨김 입력(read -s)'), () => bad('read -s'));
  await page.keyboard.type('exit\n');
  await page.waitForFunction(() => document.querySelector('.xterm-rows').innerText.includes('연결 종료'), null, { timeout: 5000 })
    .then(() => ok('exit → 연결 종료 표시'), async () => bad(`종료 (${await rows()})`));
  errs.filter((e) => !e.includes('favicon')).length === 0 ? ok('콘솔·CSP 오류 없음') : bad(`콘솔 오류: ${errs.join(' | ')}`);

  // 녹화 재생
  const list = await (await ctx.request.get(`${BASE}/api/terminal/recordings`)).json();
  const name = list.recordings[0]?.name;
  name ? ok('녹화 목록') : bad('녹화 목록');
  const replay = await ctx.newPage();
  await replay.goto(`${BASE}/terminal?replay=${encodeURIComponent(name)}`);
  await replay.waitForFunction(() => document.querySelector('.xterm-rows')?.innerText.includes('douve-42'), null, { timeout: 15000 })
    .then(() => ok('녹화 재생'), () => bad('녹화 재생'));
} finally {
  await browser.close();
}
process.exit(failed ? 1 : 0);
