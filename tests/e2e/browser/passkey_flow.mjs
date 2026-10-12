// 실제 Chromium + 가상 인증기(CDP WebAuthn)로 패스키 전체 흐름을 검증한다.
// Google 로그인(가짜 서버) → 패스키 등록 → 로그아웃 → 패스키 로그인 → 재인증 후 패스키 삭제
// 사용: node passkey_flow.mjs [douve-hub 경로]
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const here = dirname(fileURLToPath(import.meta.url));
const hubBin = resolve(process.argv[2] || join(here, '../../../build/hub/douve-hub'));
const dir = mkdtempSync(join(tmpdir(), 'douve-e2e-'));
const db = join(dir, 'hub.db');
const BASE = 'http://localhost:18900';
const procs = [];
let pass = 0, fail = 0;

const ok = (name) => { console.log(`  ok   ${name}`); pass++; };
const bad = (name, why) => { console.log(`  FAIL ${name}${why ? ` (${why})` : ''}`); fail++; };
const check = (cond, name, why) => (cond ? ok(name) : bad(name, why));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// SHOT_DIR 환경변수가 있으면 주요 화면을 캡처한다
const shot = async (page, name) => process.env.SHOT_DIR && page.screenshot({ path: join(process.env.SHOT_DIR, `${name}.png`), fullPage: true });
const sql = (q) => execFileSync('sqlite3', [db, q]).toString().trim();

writeFileSync(join(dir, 'hub.json'), JSON.stringify({
  public_url: BASE, cookie_domain: 'localhost', database_path: db, listen_port: 18900,
  allowed_emails: ['test@example.com'],
  google: { client_id: 'mock-client', client_secret: 's', auth_url: 'http://127.0.0.1:18901/auth',
            token_url: 'http://127.0.0.1:18901/token', jwks_url: 'http://127.0.0.1:18901/certs' },
}));
// 이전 실행의 잔여 프로세스가 포트를 잡고 있으면 엉뚱한 서버를 테스트하게 되므로 먼저 확인
for (const port of [18900, 18901]) {
  if (execFileSync('ss', ['-Htln', `sport = :${port}`]).toString().trim()) {
    console.error(`포트 ${port}가 이미 사용 중입니다. 이전 테스트 프로세스를 종료하세요.`);
    process.exit(2);
  }
}
procs.push(spawn('python3', [join(here, '../mock_google.py'), '18901'], { stdio: 'ignore', env: { ...process.env, MOCK_EMAIL: 'test@example.com' } }));
procs.push(spawn(hubBin, ['--config', join(dir, 'hub.json')], { stdio: 'ignore' }));
await sleep(1200);

let browser;
try {
  browser = await chromium.launch();
  const context = await browser.newContext({ locale: 'ko-KR' });
  const page = await context.newPage();
  page.on('dialog', (d) => (d.type() === 'prompt' ? d.accept('테스트 키') : d.accept()));
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
               isUserVerified: true, automaticPresenceSimulation: true },
  });

  console.log('[passkey_flow]');
  // 1. Google 로그인 → 패스키 등록 안내
  await page.goto(`${BASE}/login`);
  await shot(page, '1-login');
  await page.click('#google-login');
  await page.waitForURL(/\/account\?setup=passkey/);
  check(await page.isVisible('#setup-banner'), 'Google 로그인 후 패스키 등록 안내 표시');
  check((await page.textContent('#email')) === 'test@example.com', '계정 이메일 표시');

  // 2. 패스키 등록
  await page.click('#add-passkey');
  await page.waitForFunction(() => document.querySelectorAll('#passkeys li .row').length === 1, null, { timeout: 10000 });
  check((await page.textContent('#passkeys')).includes('테스트 키'), '패스키 등록 → 목록에 표시', await page.textContent('#msg'));
  await page.waitForFunction(() => document.querySelectorAll('#sessions li').length >= 1);
  await shot(page, '2-account');
  const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  check(credentials.length === 1 && credentials[0].isResidentCredential, '인증기에 discoverable 자격증명 생성');
  check(sql('SELECT count(*) FROM passkeys') === '1', 'DB에 패스키 저장', JSON.stringify(sql('SELECT count(*) FROM passkeys')));

  // 3. 로그아웃
  await page.click('#logout');
  await page.waitForURL(/\/login/);
  const me = await page.evaluate(async () => (await fetch('/api/me')).status);
  check(me === 401, '로그아웃 후 세션 없음');

  // 4. 패스키로 로그인 (아이디 입력 없음)
  await page.click('#passkey-login');
  await page.waitForURL(/\/account$/, { timeout: 10000 }).catch(() => {});
  check(page.url().endsWith('/account'), '패스키 로그인 → 계정 화면', await page.textContent('#msg').catch(() => ''));
  const method = await page.evaluate(async () => (await (await fetch('/api/me')).json()).auth_method);
  check(method === 'passkey', '세션 인증 방식 = passkey', method);
  check(Number(sql('SELECT sign_count FROM passkeys')) >= 1, '서명 카운터 갱신', JSON.stringify(sql('SELECT id, sign_count, last_used_at FROM passkeys')));
  await page.waitForFunction(() => document.querySelectorAll('#sessions li').length >= 1);
  check((await page.textContent('#sessions')).includes('현재 기기'), '로그인된 기기 목록에 현재 기기 표시');

  // 5. 재인증 시간이 지난 상태에서 패스키 삭제 → 자동 재인증 후 삭제
  sql('UPDATE sessions SET reauth_at = reauth_at - 3600');
  const before = Number(sql("SELECT count(*) FROM audit_log WHERE event = 'reauth'"));
  await page.click('#passkeys button.danger');
  await page.waitForFunction(() => document.querySelector('#passkeys').textContent.includes('등록된 패스키가 없습니다'), null, { timeout: 10000 }).catch(() => {});
  check(sql('SELECT count(*) FROM passkeys') === '0', '재인증 후 패스키 삭제', await page.textContent('#msg'));
  check(Number(sql("SELECT count(*) FROM audit_log WHERE event = 'reauth'")) === before + 1, '재인증 감사 로그');

  // 6. 삭제된 패스키로는 로그인 불가
  await page.click('#logout');
  await page.waitForURL(/\/login/);
  await page.click('#passkey-login');
  await page.waitForFunction(() => document.querySelector('#msg').textContent.length > 0, null, { timeout: 10000 }).catch(() => {});
  check((await page.textContent('#msg')).includes('등록되지 않은'), '삭제된 패스키 로그인 거부', await page.textContent('#msg'));

  const events = sql("SELECT group_concat(event, ',') FROM (SELECT event FROM audit_log ORDER BY id)");
  check(/login.*passkey_registered.*logout.*login.*reauth.*passkey_deleted.*login_failed/.test(events), '감사 로그 순서', events);
} catch (e) {
  bad('예외 발생', e.message.split('\n')[0]);
} finally {
  await browser?.close();
  for (const p of procs) p.kill();
  rmSync(dir, { recursive: true, force: true });
}
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
