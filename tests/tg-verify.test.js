// Бот верификации: подпись Telegram, вход без почты и заявка из формы бота.
// Боевая база не затрагивается: путь подменяется через DB_FILE. В Telegram
// тест не ходит — без https-адреса сайта бот вебхук не ставит.

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { validateInitData, signInitData, webhookSecret } = require('../tg-verify');

const PORT = 3992;
const BASE = `http://127.0.0.1:${PORT}`;
const DB_FILE = path.join(os.tmpdir(), `kometa-tgverify-${crypto.randomBytes(6).toString('hex')}.db`);
const UPLOADS_DIR = path.join(os.tmpdir(), `kometa-tgverify-up-${crypto.randomBytes(6).toString('hex')}`);
const ADMIN_EMAIL = 'tgverify-test@example.invalid';
const ADMIN_PASSWORD = crypto.randomBytes(18).toString('hex');
// Токен-выдумка: подпись проверяется им же, к настоящему Telegram он не относится
const BOT_TOKEN = '123456:' + crypto.randomBytes(16).toString('hex');

let server;
let adminCookie = '';

function launch(user, extra = {}) {
  return signInitData({ auth_date: String(Math.floor(Date.now() / 1000)), user: JSON.stringify(user), ...extra }, BOT_TOKEN);
}

function request(url, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body) headers['Content-Type'] = 'application/json';
  return fetch(BASE + url, { ...options, headers, redirect: 'manual' });
}

async function json(url, options = {}) {
  const res = await request(url, options);
  return { status: res.status, data: await res.json().catch(() => ({})), res };
}

const asTg = (initData, url, options = {}) =>
  json(url, { ...options, headers: { 'X-Tg-Init-Data': initData, ...(options.headers || {}) } });

function pngDataUrl(bytes = 4000) {
  const head = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  return 'data:image/png;base64,' + Buffer.concat([head, crypto.randomBytes(bytes)]).toString('base64');
}

before(async () => {
  server = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env, UPLOADS_DIR, PORT: String(PORT), DB_FILE, ADMIN_EMAIL, ADMIN_PASSWORD,
      PUBLIC_URL: 'http://127.0.0.1:' + PORT, TG_VERIFY_BOT_TOKEN: BOT_TOKEN, NODE_ENV: 'test',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  server.stderr.on('data', chunk => {
    const line = String(chunk);
    if (!/ExperimentalWarning/.test(line)) process.stderr.write(`[server] ${line}`);
  });
  for (let i = 0; i < 60; i++) {
    try { if ((await request('/api/site')).ok) break; } catch (_) { /* ещё не слушает */ }
    await new Promise(r => setTimeout(r, 250));
  }
  const login = await json('/api/login', { method: 'POST', body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD }) });
  assert.equal(login.status, 200, 'администратор должен входить');
  adminCookie = (login.res.headers.getSetCookie?.() || []).map(c => c.split(';')[0]).join('; ');
});

after(() => {
  server?.kill();
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(DB_FILE + suffix); } catch (_) { /* уже нет */ }
  }
  try { fs.rmSync(UPLOADS_DIR, { recursive: true, force: true }); } catch (_) { /* её могло и не быть */ }
});

// ---------- Подпись Telegram ----------

test('настоящая подпись Telegram принимается', () => {
  const check = validateInitData(launch({ id: 777, username: 'ivan' }), BOT_TOKEN);
  assert.equal(check.ok, true);
  assert.equal(check.user.id, 777);
});

test('подменённый пользователь не проходит: подпись перестаёт сходиться', () => {
  const params = new URLSearchParams(launch({ id: 777 }));
  params.set('user', JSON.stringify({ id: 1 }));
  assert.equal(validateInitData(params.toString(), BOT_TOKEN).ok, false);
});

test('подпись чужим токеном не проходит', () => {
  const forged = signInitData({ auth_date: String(Math.floor(Date.now() / 1000)), user: JSON.stringify({ id: 5 }) }, '1:other');
  assert.equal(validateInitData(forged, BOT_TOKEN).ok, false);
});

test('старые данные запуска не принимаются', () => {
  const old = signInitData({ auth_date: String(Math.floor(Date.now() / 1000) - 2 * 24 * 3600), user: JSON.stringify({ id: 5 }) }, BOT_TOKEN);
  const check = validateInitData(old, BOT_TOKEN);
  assert.equal(check.ok, false);
  assert.match(check.reason, /устарели/);
});

test('без пользователя и без подписи — отказ', () => {
  assert.equal(validateInitData(signInitData({ auth_date: String(Math.floor(Date.now() / 1000)) }, BOT_TOKEN), BOT_TOKEN).ok, false);
  assert.equal(validateInitData('user=%7B%22id%22%3A5%7D', BOT_TOKEN).ok, false);
  assert.equal(validateInitData('', BOT_TOKEN).ok, false);
});

// ---------- Форма из бота ----------

test('без подписи Telegram форма ничего не отдаёт', async () => {
  const { status } = await json('/api/tg/verification');
  assert.equal(status, 401);
});

test('из бота клиент заходит без почты и видит пустую верификацию', async () => {
  const { status, data } = await asTg(launch({ id: 100001, username: 'shady_client', first_name: 'Пётр' }), '/api/tg/verification');
  assert.equal(status, 200);
  assert.equal(data.status, 'none');
  assert.equal(data.tg_username, 'shady_client');
});

test('повторный заход того же Telegram не плодит учёток', async () => {
  const init = launch({ id: 100002, username: 'twice' });
  await asTg(init, '/api/tg/verification');
  await asTg(init, '/api/tg/verification');
  const { data } = await json('/api/admin/clients', { headers: { Cookie: adminCookie } });
  const mine = (data.clients || []).filter(c => c.email === 'tg-100002@telegram.local');
  assert.equal(mine.length, 1);
});

test('заявка из бота ложится в админку с подтверждённым Telegram', async () => {
  const init = launch({ id: 100003, username: 'real_tg' });
  const sent = await asTg(init, '/api/tg/verification', {
    method: 'POST',
    // Вписанный в форму Telegram не важен: берётся тот, что подписал Telegram
    body: JSON.stringify({ full_name: 'Петров Пётр', phone: '+7 900 111-22-33', telegram: '@someone_else', passport: pngDataUrl(), selfie: pngDataUrl() }),
  });
  assert.equal(sent.status, 200, JSON.stringify(sent.data));

  const status = await asTg(init, '/api/tg/verification');
  assert.equal(status.data.status, 'pending');

  const { data } = await json('/api/admin/verifications', { headers: { Cookie: adminCookie } });
  const row = data.users.find(u => u.tg_id === 100003);
  assert.ok(row, 'заявка должна быть видна в админке');
  assert.equal(row.tg_username, 'real_tg');
  assert.equal(row.telegram, 'real_tg', 'Telegram берётся из подписи, а не из формы');
  assert.equal(row.verify_status, 'pending');
});

test('без username в Telegram берётся то, что клиент вписал сам', async () => {
  const init = launch({ id: 100004, first_name: 'Без ника' });
  const sent = await asTg(init, '/api/tg/verification', {
    method: 'POST',
    body: JSON.stringify({ full_name: 'Сидоров Сидор', phone: '+7 900 444-55-66', telegram: '@typed_by_hand', passport: pngDataUrl(), selfie: pngDataUrl() }),
  });
  assert.equal(sent.status, 200, JSON.stringify(sent.data));
  const { data } = await json('/api/admin/verifications', { headers: { Cookie: adminCookie } });
  assert.equal(data.users.find(u => u.tg_id === 100004).telegram, 'typed_by_hand');
});

test('подписью Telegram в кабинет по почте не войти', async () => {
  // Заголовок Telegram не заменяет куку: обычные адреса кабинета его не знают
  const { status } = await asTg(launch({ id: 100005 }), '/api/verification');
  assert.equal(status, 401);
});

// ---------- Заголовки и вебхук ----------

test('форму бота можно показать в окне web.telegram.org, остальной сайт — нигде', async () => {
  const form = await request('/tg-verify.html');
  assert.match(form.headers.get('content-security-policy'), /frame-ancestors https:\/\/web\.telegram\.org/);
  assert.equal(form.headers.get('x-frame-options'), null);

  const home = await request('/');
  assert.match(home.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal(home.headers.get('x-frame-options'), 'DENY');
});

test('вебхук бота без секрета Telegram отклоняется', async () => {
  const res = await request('/tg/verify-webhook', { method: 'POST', body: JSON.stringify({ update_id: 1 }) });
  // Без https бот вебхук не ставит, а адрес на сервере всё равно закрыт секретом
  assert.ok([401, 404].includes(res.status), String(res.status));
});

test('секрет вебхука выводится из токена и не совпадает у разных ботов', () => {
  const saved = process.env.TG_VERIFY_BOT_TOKEN;
  process.env.TG_VERIFY_BOT_TOKEN = 'a';
  const first = webhookSecret();
  process.env.TG_VERIFY_BOT_TOKEN = 'b';
  const second = webhookSecret();
  process.env.TG_VERIFY_BOT_TOKEN = saved;
  assert.notEqual(first, second);
});
