// 웹 터미널 브라우저 시험 (terminal_flow.sh가 Hub·Agent를 띄운 뒤 실행)
// 가상 인증기(CDP WebAuthn)로 패스키를 등록하고, 터미널을 열 때마다 패스키 서명 → Agent가 직접 확인.
import { execFileSync } from 'node:child_process';
import { chromium } from 'playwright';

const { BASE, SESSION, NODE, ME, DB, TMPD } = process.env;
let failed = 0;
const ok = (m) => console.log(`  ok   ${m}`);
const bad = (m) => { console.log(`  FAIL ${m}`); failed++; };
const sql = (q) => execFileSync('sqlite3', [DB, q]).toString().trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const browser = await chromium.launch();
try {
  const ctx = await browser.newContext({ locale: 'ko-KR', viewport: { width: 1100, height: 700 } });
  await ctx.addCookies([{ name: 'douve_session', value: SESSION, domain: 'localhost', path: '/' }]);
  const page = await ctx.newPage();
  page.on('dialog', (d) => (d.type() === 'prompt' ? d.accept(`키${sql('SELECT count(*) FROM passkeys') + 1}`) : d.accept()));
  const errs = [];
  page.on('pageerror', (e) => errs.push(String(e)));
  page.on('console', (m) => { if (m.type() === 'error') errs.push(m.text()); });
  const cdp = await ctx.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
               isUserVerified: true, automaticPresenceSimulation: true },
  });
  const trust = async () => (await ctx.request.get(`${BASE}/api/terminal/trust`)).json();

  // 패스키가 없으면 터미널을 열 수 없다 (서버가 믿는 패스키 없음)
  await page.goto(`${BASE}/account`);
  const noKey = await page.evaluate(async (node) => {
    const r = await fetch('/api/terminal/options', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ node_id: Number(node), user: 'x' }) });
    return r.status;
  }, NODE);
  noKey === 403 || noKey === 409 ? ok(`패스키 없으면 터미널 거부 (${noKey})`) : bad(`패스키 없음 ${noKey}`);
  errs.length = 0; // 위 거부(403)는 일부러 낸 것

  // 첫 패스키 등록 (관리자 키가 아직 없으니 신뢰 목록은 승인 없이 바로 반영)
  await page.goto(`${BASE}/account`);
  await page.click('#add-passkey');
  await page.waitForFunction(() => document.querySelectorAll('#passkeys li .row').length === 1, null, { timeout: 10000 })
    .then(() => ok('패스키 등록'), async () => bad(`패스키 등록 (${await page.textContent('#msg')})`));
  let st = await trust();
  !st.pending && st.keys.length === 1 && st.keys[0].admin ? ok(`첫 관리자 키는 바로 신뢰 목록에 (v${st.version})`) : bad(`첫 키 ${JSON.stringify(st)}`);
  const firstKeyId = st.keys[0]?.id;

  await page.goto(`${BASE}/terminal?node=${NODE}`);
  await page.waitForFunction(() => document.getElementById('term-status').textContent.includes('연결됨'), null, { timeout: 10000 })
    .then(() => ok('패스키 서명으로 터미널 연결 (Agent가 서명 확인)'), async () => bad(`연결 (${await page.textContent('#msg')} | ${errs.join(' | ')})`));
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

  // 녹화 재생
  const list = await (await ctx.request.get(`${BASE}/api/terminal/recordings`)).json();
  const name = list.recordings[0]?.name;
  name ? ok('녹화 목록') : bad('녹화 목록');
  const replay = await ctx.newPage();
  await replay.goto(`${BASE}/terminal?replay=${encodeURIComponent(name)}`);
  await replay.waitForFunction(() => document.querySelector('.xterm-rows')?.innerText.includes('douve-42'), null, { timeout: 15000 })
    .then(() => ok('녹화 재생'), () => bad('녹화 재생'));
  await replay.close();

  // Hub가 장악된 경우 흉내: 서명 없는 티켓을 DB에 직접 넣어 터미널을 열려고 한다 → Agent가 거부
  const forged = `forged-ticket-${Date.now()}`;
  sql(`INSERT INTO pending VALUES ('${forged}', 'term', '{"node_id":${NODE},"node_name":"term1","user":"${ME}","user_id":1,"cols":80,"rows":24}', strftime('%s','now') + 60)`);
  const forgedOut = await page.evaluate((t) => new Promise((resolve) => {
    const ws = new WebSocket(`ws://${location.host}/api/terminal/ws?ticket=${t}`);
    const got = [];
    ws.onmessage = (ev) => got.push(JSON.parse(ev.data));
    ws.onclose = () => resolve(got);
    setTimeout(() => resolve(got), 5000);
  }), forged);
  const exit = forgedOut.find((m) => m.t === 'exit');
  !forgedOut.some((m) => m.t === 'opened' || m.t === 'out') && exit && exit.error.includes('패스키 서명')
    ? ok(`서명 없는 터미널 열기는 Agent가 거부 ("${exit.error}")`) : bad(`위조 티켓 ${JSON.stringify(forgedOut)}`);
  // 진짜 서명을 다른 계정(root)에 쓰려고 바꿔치기 → 서명한 내용과 달라 거부
  // (티켓 발급 API를 거쳐 서명을 받은 뒤 DB의 티켓에서 계정만 바꾼다)
  const swapped = await page.evaluate(async ({ node, me }) => {
    const opts = await api('/api/terminal/options', { node_id: Number(node), user: me });
    const cred = await navigator.credentials.get({ publicKey: toRequestOptions(opts.publicKey) });
    return (await api('/api/terminal/ticket', { pending: opts.pending, credential: assertionJson(cred) })).ticket;
  }, { node: NODE, me: ME });
  sql(`UPDATE pending SET payload = replace(payload, '"user":"${ME}"', '"user":"root"') WHERE id = '${swapped}'`);
  const swappedOut = await page.evaluate((t) => new Promise((resolve) => {
    const ws = new WebSocket(`ws://${location.host}/api/terminal/ws?ticket=${t}`);
    const got = [];
    ws.onmessage = (ev) => got.push(JSON.parse(ev.data));
    ws.onclose = () => resolve(got);
    setTimeout(() => resolve(got), 5000);
  }), swapped);
  const exit2 = swappedOut.find((m) => m.t === 'exit');
  !swappedOut.some((m) => m.t === 'opened') && exit2 && /요청과 다릅니다|허용되지 않은/.test(exit2.error)
    ? ok(`서명을 다른 계정에 쓰면 거부 ("${exit2.error}")`) : bad(`계정 바꿔치기 ${JSON.stringify(swappedOut)}`);

  // 두 번째 패스키: 관리자가 승인하기 전에는 서버가 모른다
  // (같은 인증기에 같은 계정 키를 두 개 만들 수 없어서, 첫 키를 잠시 빼 두었다가 다시 넣는다)
  const toUrl = (c) => Buffer.from(c.credentialId, 'base64').toString('base64url');
  const first = (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials.find((c) => toUrl(c) === firstKeyId);
  await cdp.send('WebAuthn.removeCredential', { authenticatorId, credentialId: first.credentialId });
  await page.goto(`${BASE}/account`);
  await page.click('#add-passkey');
  await page.waitForFunction(() => document.querySelectorAll('#passkeys li .row').length === 2, null, { timeout: 10000 })
    .then(() => ok('두 번째 패스키 등록'), async () => bad(`두 번째 패스키 (${await page.textContent('#msg')})`));
  // 첫 키는 다른 인증기(다른 기기)로 옮긴다
  const { authenticatorId: other } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: true,
               isUserVerified: true, automaticPresenceSimulation: true },
  });
  await cdp.send('WebAuthn.addCredential', { authenticatorId: other, credential: first });
  st = await trust();
  st.pending && st.desired.length === 2 && st.keys.length === 1 ? ok('두 번째 키는 승인 대기') : bad(`승인 대기 ${JSON.stringify(st)}`);
  const before = st.version;

  await page.goto(`${BASE}/dashboard`);
  await page.waitForSelector('#trust-banner:not([hidden])', { timeout: 10000 })
    .then(() => ok('서버 화면에 승인 배너'), () => bad('승인 배너'));
  (await page.textContent('#trust-banner')).includes('추가됨') ? ok('배너에 추가될 키 표시') : bad(`배너 내용 ${await page.textContent('#trust-banner')}`);
  await page.click('#trust-banner button');
  await page.waitForSelector('#trust-banner', { state: 'hidden', timeout: 15000 })
    .then(() => ok('패스키로 승인 → 배너 사라짐'), async () => bad(`승인 (${await page.textContent('#msg')} | ${await page.textContent('#trust-banner')})`));
  await sleep(500);
  st = await trust();
  const node = st.nodes.find((n) => String(n.id) === NODE);
  !st.pending && st.version === before + 1 && node?.version === st.version && !node.error
    ? ok(`서명된 새 판 v${st.version}을 Agent가 받음`) : bad(`승인 후 ${JSON.stringify(st)}`);
  sql("SELECT count(*) FROM audit_log WHERE event='terminal_trust_signed'") === '1' ? ok('승인 감사 로그') : bad('승인 감사 로그');

  // 첫 패스키를 인증기에서 지우면 두 번째(승인된) 키로 터미널이 열린다
  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: other });
  await page.goto(`${BASE}/terminal?node=${NODE}`);
  await page.waitForFunction(() => document.getElementById('term-status').textContent.includes('연결됨'), null, { timeout: 10000 })
    .then(() => ok('승인된 두 번째 키로 터미널 연결'), async () => bad(`두 번째 키 연결 (${await page.textContent('#msg')})`));
  await page.locator('.xterm').click();
  await page.keyboard.type('exit\n');
  await sleep(500);

  // 파일 올리기·내려받기 (파일마다 패스키 서명, Agent가 서명·내용 확인)
  const fs = await import('node:fs');
  const upPath = `${TMPD}/올린 파일.txt`;
  const content = `douve-파일-${Date.now()}\n`.repeat(30000); // 약 0.8MB (여러 조각·ack)
  await page.click('#term-files');
  await page.setInputFiles('#up-file', { name: 'a.txt', mimeType: 'text/plain', buffer: Buffer.from(content) });
  await page.fill('#up-path', upPath);
  await page.click('#up-go');
  await page.waitForFunction(() => /올렸습니다|uploaded/i.test(document.getElementById('files-status').textContent) || /실패|다릅니다|없습니다/.test(document.getElementById('files-status').textContent), null, { timeout: 20000 })
    .catch(() => {});
  fs.existsSync(upPath) && fs.readFileSync(upPath, 'utf8') === content ? ok('파일 올리기 (패스키 서명 → 서버가 내용 확인)') : bad(`올리기 (${await page.textContent('#files-status')})`);
  fs.readdirSync(TMPD).some((f) => f.includes('.douve-')) ? bad('임시 파일 남음') : ok('임시 파일 정리');
  await page.fill('#down-path', upPath);
  const [dl] = await Promise.all([page.waitForEvent('download', { timeout: 20000 }).catch(() => null), page.click('#down-go')]);
  const dlPath = dl && await dl.path();
  dlPath && fs.readFileSync(dlPath, 'utf8') === content ? ok('파일 내려받기 (SHA-256 확인)') : bad(`내려받기 (${await page.textContent('#files-status')})`);
  await page.click('#files-close');
  // 다른 계정은 안 된다
  const otherUser = await page.evaluate(async (node) => (await fetch('/api/files/options', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ node_id: Number(node), user: 'root', op: 'get', path: '/etc/shadow' }) })).status, NODE);
  otherUser === 403 ? ok('허용되지 않은 계정(root) 파일 거부') : bad(`root 파일 ${otherUser}`);

  // Hub 장악 흉내 1: 서명 없는 파일 티켓 → Agent가 거부
  const wsRun = (t, send = []) => page.evaluate(({ t, send }) => new Promise((resolve) => {
    const ws = new WebSocket(`ws://${location.host}/api/files/ws?ticket=${t}`);
    const got = [];
    ws.onmessage = (ev) => { const m = JSON.parse(ev.data); got.push(m); if (m.t === 'ready') { for (const x of send) ws.send(JSON.stringify(x)); } };
    ws.onclose = () => resolve(got);
    setTimeout(() => resolve(got), 5000);
  }), { t, send });
  const forgedFile = `forged-file-${Date.now()}`;
  sql(`INSERT INTO pending VALUES ('${forgedFile}', 'file', '{"node_id":${NODE},"node_name":"term1","op":"get","user":"${ME}","path":"${upPath}","user_id":1}', strftime('%s','now') + 60)`);
  let got = await wsRun(forgedFile);
  got.some((m) => m.t === 'data') || !got.some((m) => m.t === 'error' && m.error.includes('패스키 서명'))
    ? bad(`서명 없는 파일 티켓 ${JSON.stringify(got).slice(0, 300)}`) : ok('서명 없는 파일 내려받기는 Agent가 거부');
  // Hub 장악 흉내 2: 진짜 서명을 받은 뒤 경로를 바꿔치기 → 서명한 내용과 달라 거부
  const realTicket = async (body) => page.evaluate(async (body) => {
    const opts = await api('/api/files/options', body);
    const cred = await navigator.credentials.get({ publicKey: toRequestOptions(opts.publicKey) });
    return (await api('/api/files/ticket', { pending: opts.pending, credential: assertionJson(cred) })).ticket;
  }, body);
  let tk = await realTicket({ node_id: Number(NODE), user: ME, op: 'get', path: upPath });
  sql(`UPDATE pending SET payload = replace(payload, '${TMPD}', '/etc') WHERE id = '${tk}'`); // 경로의 ASCII 부분 (한글은 \u로 저장됨)
  got = await wsRun(tk);
  got.some((m) => m.t === 'data') || !got.some((m) => m.t === 'error') ? bad(`경로 바꿔치기 ${JSON.stringify(got).slice(0, 300)}`) : ok('서명 뒤 경로 바꿔치기는 거부');
  // Hub 장악 흉내 3: 서명한 SHA-256과 다른 내용을 보냄 → 원래 파일 그대로
  const shaHex = (await import('node:crypto')).createHash('sha256').update('서명한 내용').digest('hex');
  tk = await realTicket({ node_id: Number(NODE), user: ME, op: 'put', path: upPath, size: Buffer.byteLength('서명한 내용'), sha256: shaHex });
  const evil = Buffer.from('공격자 내용!!!').subarray(0, Buffer.byteLength('서명한 내용')).toString('base64');
  got = await wsRun(tk, [{ t: 'chunk', d: evil }, { t: 'end' }]);
  got.some((m) => m.t === 'error' && m.error.includes('다릅니다')) && fs.readFileSync(upPath, 'utf8') === content
    ? ok('서명과 다른 내용은 거부, 원래 파일 그대로') : bad(`내용 바꿔치기 ${JSON.stringify(got).slice(0, 300)}`);
  const fev = sql("SELECT group_concat(event, ',') FROM (SELECT event FROM audit_log WHERE event LIKE 'file%' ORDER BY id)");
  /file_uploaded,file_downloaded/.test(fev) ? ok(`파일 감사 로그 (${fev})`) : bad(`파일 감사 로그 (${fev})`);

  errs.filter((e) => !e.includes('favicon') && !e.includes('WebSocket') && !e.includes('403')).length === 0 ? ok('콘솔·CSP 오류 없음') : bad(`콘솔 오류: ${errs.join(' | ')}`);
} catch (e) {
  bad(`예외: ${e.message.split('\n')[0]}`);
} finally {
  await browser.close();
}
process.exit(failed ? 1 : 0);
