// 초대 E2E: Google 없이(설정 자체가 없음) `douve-hub invite` 링크 → 패스키 등록 → 대시보드 →
// 로그아웃 → 패스키 로그인. 링크 재사용·만료·위조 거부도 확인한다.
// 사용: node invite_flow.mjs [douve-hub 경로]
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const here = dirname(fileURLToPath(import.meta.url));
const hubBin = resolve(process.argv[2] || join(here, '../../../build/hub/douve-hub'));
const dir = mkdtempSync(join(tmpdir(), 'douve-invite-'));
const db = join(dir, 'hub.db');
const cfgPath = join(dir, 'hub.json');
const PORT = 18910;
const BASE = `http://localhost:${PORT}`;
let pass = 0, fail = 0;
const ok = (n) => { console.log(`  ok   ${n}`); pass++; };
const bad = (n, why) => { console.log(`  FAIL ${n}${why ? ` (${why})` : ''}`); fail++; };
const check = (c, n, why) => (c ? ok(n) : bad(n, why));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sql = (q) => execFileSync('sqlite3', [db, q]).toString().trim();
const invite = (email, hours = 24) =>
  execFileSync(hubBin, ['invite', '--config', cfgPath, '--email', email, '--hours', String(hours)], { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();

if (execFileSync('ss', ['-Htln', `sport = :${PORT}`]).toString().trim()) {
  console.error(`포트 ${PORT} 사용 중`);
  process.exit(2);
}
// Google 설정도 allowed_emails도 없는 "처음 설치" 상태
writeFileSync(cfgPath, JSON.stringify({ public_url: BASE, cookie_domain: 'localhost', database_path: db, listen_port: PORT }));
const hub = spawn(hubBin, ['--config', cfgPath], { stdio: 'ignore' });
await sleep(1000);

let browser;
try {
  console.log('[invite_flow]');
  const link = invite('Owner@Example.com');
  check(link.startsWith(`${BASE}/invite#`) && link.length > BASE.length + 40, 'invite CLI가 # 토큰 링크 출력', link);

  browser = await chromium.launch();
  const ctx = await browser.newContext({ locale: 'ko-KR' });
  const page = await ctx.newPage();
  const cdp = await ctx.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
               isUserVerified: true, automaticPresenceSimulation: true },
  });

  // 로그인 화면: Google이 설정되지 않았으면 버튼을 숨김
  await page.goto(`${BASE}/login`);
  await page.waitForTimeout(300);
  check(!(await page.isVisible('#google-login')), 'Google 미설정 시 Google 버튼 숨김');

  await page.goto(link);
  check(page.url() === `${BASE}/invite`, '주소창에서 토큰 제거', page.url());
  await page.fill('#invite-name', '노트북');
  await page.click('#invite-accept');
  await page.waitForURL(`${BASE}/dashboard`, { timeout: 10000 }).then(() => ok('패스키 등록 → 대시보드'), async () => bad('초대 수락', await page.textContent('#msg')));
  check(sql("SELECT allowed FROM users WHERE email='owner@example.com'") === '1', '초대 수락 사용자 허용');
  check(sql("SELECT name FROM passkeys") === '노트북', '패스키 이름 저장');

  // 같은 링크 재사용 → 거부
  const page2 = await (await browser.newContext({ locale: 'ko-KR' })).newPage();
  const cdp2 = await page2.context().newCDPSession(page2);
  await cdp2.send('WebAuthn.enable');
  await cdp2.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
               isUserVerified: true, automaticPresenceSimulation: true },
  });
  await page2.goto(link);
  await page2.click('#invite-accept');
  await page2.waitForFunction(() => document.getElementById('msg').textContent.length > 0);
  check((await page2.textContent('#msg')).includes('초대'), '사용한 초대 링크 재사용 거부', await page2.textContent('#msg'));

  // 위조 토큰·만료 토큰
  await page2.goto(`${BASE}/invite#${'A'.repeat(43)}`);
  await page2.click('#invite-accept');
  await page2.waitForFunction(() => document.getElementById('msg').textContent.length > 0);
  check((await page2.textContent('#msg')).includes('초대'), '위조 초대 토큰 거부');
  const expired = invite('late@example.com', 1);
  sql("UPDATE invites SET expires_at = 1 WHERE email = 'late@example.com'");
  await page2.goto(expired);
  await page2.click('#invite-accept');
  await page2.waitForFunction(() => document.getElementById('msg').textContent.length > 0);
  check((await page2.textContent('#msg')).includes('만료'), '만료된 초대 거부');
  check(sql("SELECT count(*) FROM users WHERE email='late@example.com'") === '0', '만료 초대로 사용자 생성 안 됨');

  // 로그아웃 → 패스키 로그인 (allowed_emails 없이도 초대 사용자는 로그인 가능)
  await page.goto(`${BASE}/account`);
  await page.click('#logout');
  await page.waitForURL(/\/login/);
  await page.click('#passkey-login');
  await page.waitForURL((u) => !u.pathname.startsWith('/login'), { timeout: 10000 })
    .then(() => ok('초대 사용자 패스키 로그인'), async () => bad('패스키 로그인', await page.textContent('#msg')));

  const ev = sql("SELECT group_concat(event, ',') FROM (SELECT event FROM audit_log ORDER BY id)");
  check(ev.includes('invite_created') && ev.includes('invite_accepted') && ev.includes('invite_invalid'), '감사 로그', ev);
} catch (e) {
  bad('예외', e.message);
} finally {
  await browser?.close();
  hub.kill();
}
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
