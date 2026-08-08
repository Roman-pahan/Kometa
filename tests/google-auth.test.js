// Проверка входа через Google. К самому Google тесты не ходят: проверяется
// то, что зависит от нас — видимость кнопки, одноразовое состояние, отказ
// на чужой ответ и закрытость ключей. Боевая база не затрагивается: путь
// подменяется через DB_FILE.

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const PORT = 3988;
const BASE = `http://127.0.0.1:${PORT}`;
const DB_FILE = path.join(os.tmpdir(), `kometa-google-${crypto.randomBytes(6).toString('hex')}.db`);
const ADMIN_EMAIL = 'google-test@example.invalid';
const ADMIN_PASSWORD = crypto.randomBytes(18).toString('hex');
const BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126 Safari/537.36';

// Значения ненастоящие: обмен кода на токен в тестах не выполняется
const CLIENT_ID = 'test-client.apps.googleusercontent.com';
const CLIENT_SECRET = 'test-secret-' + crypto.randomBytes(8).toString('hex');

let server;
let adminCookie = '';

function request(url, options = {}) {
  const headers = { 'User-Agent': BROWSER, ...(options.headers || {}) };
  if (options.body) headers['Content-Type'] = 'application/json';
  return fetch(BASE + url, { ...options, headers, redirect: 'manual' });
}

async function json(url, options = {}) {
  const res = await request(url, options);
  return { status: res.status, data: await res.json().catch(() => ({})) };
}

function asAdmin(url, options = {}) {
  return json(url, { ...options, headers: { Cookie: adminCookie, ...(options.headers || {}) } });
}

before(async () => {
  server = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, PORT: String(PORT), DB_FILE, ADMIN_EMAIL, ADMIN_PASSWORD, NODE_ENV: 'test' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('сервер не запустился за 15 секунд')), 15000);
    server.stdout.on('data', chunk => {
      if (String(chunk).includes('http://localhost')) { clearTimeout(timer); resolve(); }
    });
    server.on('exit', code => { clearTimeout(timer); reject(new Error('сервер завершился с кодом ' + code)); });
  });

  const login = await request('/api/login', {
    method: 'POST', body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD }),
  });
  assert.equal(login.status, 200, 'администратор должен войти');
  adminCookie = (login.headers.getSetCookie?.() || []).map(raw => raw.split(';')[0]).join('; ');
});

after(() => {
  if (server) server.kill();
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(DB_FILE + suffix); } catch (_) { /* файла может не быть */ }
  }
});

test('без заведённых ключей кнопки Google нет, а адрес входа отвечает отказом', async () => {
  const site = await json('/api/site');
  assert.equal(site.data.google_auth, false, 'страница входа не должна показывать кнопку');

  const res = await request('/api/auth/google');
  assert.equal(res.status, 503, 'входить некуда, пока ключи не заведены');
});

test('ключи Google заводит только администратор', async () => {
  const stranger = await json('/api/admin/settings', {
    method: 'PATCH', body: JSON.stringify({ google_client_id: 'чужой', google_client_secret: 'чужой' }),
  });
  assert.equal(stranger.status, 403, 'без входа настройки не меняются');

  const saved = await asAdmin('/api/admin/settings', {
    method: 'PATCH', body: JSON.stringify({ google_client_id: CLIENT_ID, google_client_secret: CLIENT_SECRET }),
  });
  assert.equal(saved.status, 200);
});

test('секрет Google наружу не отдаётся', async () => {
  const settings = await asAdmin('/api/admin/settings');
  assert.equal(settings.data.google_client_id, CLIENT_ID, 'открытый идентификатор виден админу');
  assert.equal(settings.data.google_secret_set, true, 'о секрете известно только то, что он заполнен');
  assert.equal(settings.data.google_client_secret, undefined, 'сам секрет не отдаётся никогда');
  assert.ok(!JSON.stringify(settings.data).includes(CLIENT_SECRET), 'секрета нет нигде в ответе');

  // И тем более он не виден на общедоступном адресе
  const site = await json('/api/site');
  assert.equal(site.data.google_auth, true, 'кнопка входа появляется после настройки');
  assert.ok(!JSON.stringify(site.data).includes(CLIENT_SECRET));
  assert.ok(!JSON.stringify(site.data).includes(CLIENT_ID), 'публичной странице ключи не нужны');
});

test('пустой секрет при сохранении не затирает уже заведённый', async () => {
  const saved = await asAdmin('/api/admin/settings', {
    method: 'PATCH', body: JSON.stringify({ google_client_id: CLIENT_ID, google_client_secret: '' }),
  });
  assert.equal(saved.status, 200);
  const settings = await asAdmin('/api/admin/settings');
  assert.equal(settings.data.google_secret_set, true, 'секрет остался на месте');
});

test('вход уводит на страницу согласия Google с одноразовым состоянием', async () => {
  const res = await request('/api/auth/google?next=%2Fcabinet.html');
  assert.equal(res.status, 302);

  const url = new URL(res.headers.get('location'));
  assert.equal(url.origin + url.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
  assert.equal(url.searchParams.get('client_id'), CLIENT_ID);
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.match(url.searchParams.get('redirect_uri'), /\/api\/auth\/google\/callback$/);
  const state = url.searchParams.get('state');
  assert.match(state, /^[a-f0-9]{32}$/, 'состояние случайное');

  // То же состояние сохранено в куке и недоступно скриптам страницы
  const cookie = (res.headers.getSetCookie?.() || []).find(c => c.startsWith('gstate='));
  assert.ok(cookie, 'состояние кладётся в куку');
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Lax/);
  const saved = JSON.parse(Buffer.from(cookie.split('=')[1].split(';')[0], 'base64url').toString('utf8'));
  assert.equal(saved.state, state, 'кука и адрес несут одно и то же состояние');
  assert.equal(saved.next, '/cabinet.html', 'куда вернуть человека — запомнено');

  // Два входа подряд дают разные состояния
  const again = await request('/api/auth/google');
  const other = new URL(again.headers.get('location')).searchParams.get('state');
  assert.notEqual(other, state, 'состояние одноразовое');
});

test('возврат с чужим состоянием отклоняется и в аккаунт не пускает', async () => {
  const cases = [
    { name: 'без куки', headers: {}, query: '?code=abc&state=deadbeef' },
    { name: 'состояние не совпало', headers: { Cookie: 'gstate=' + Buffer.from(JSON.stringify({ state: 'aaaa', next: '/' })).toString('base64url') }, query: '?code=abc&state=bbbb' },
    { name: 'без кода', headers: { Cookie: 'gstate=' + Buffer.from(JSON.stringify({ state: 'cccc', next: '/' })).toString('base64url') }, query: '?state=cccc' },
  ];
  for (const c of cases) {
    const res = await request('/api/auth/google/callback' + c.query, { headers: c.headers });
    assert.equal(res.status, 302, c.name + ': ответ должен быть перенаправлением');
    assert.equal(res.headers.get('location'), '/auth.html?google_error=1', c.name + ': человек возвращается на вход с ошибкой');
    const cookies = res.headers.getSetCookie?.() || [];
    assert.ok(!cookies.some(x => x.startsWith('sid=') && !x.includes('Max-Age=0')), c.name + ': сессия не выдаётся');
  }
});
