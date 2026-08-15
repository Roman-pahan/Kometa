// Проверка защит, которые не видны на странице, но держат сайт на ногах:
// счёт попыток входа, срок жизни сессии, предел на размер запроса, проверка
// картинок по содержимому, секреты в базе и адрес ссылок из письма.
// Боевая база не затрагивается: путь подменяется через DB_FILE.

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Database = require('better-sqlite3');

const PORT = 3991;
const BASE = `http://127.0.0.1:${PORT}`;
const DB_FILE = path.join(os.tmpdir(), `kometa-security-${crypto.randomBytes(6).toString('hex')}.db`);
const ADMIN_EMAIL = 'security-test@example.invalid';
const ADMIN_PASSWORD = crypto.randomBytes(18).toString('hex');
const PUBLIC_URL = 'https://kometa.test';
const BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126 Safari/537.36';

let server;
let adminCookie = '';

function request(url, options = {}) {
  const headers = { 'User-Agent': BROWSER, ...(options.headers || {}) };
  if (options.body) headers['Content-Type'] = 'application/json';
  return fetch(BASE + url, { ...options, headers, redirect: 'manual' });
}

async function json(url, options = {}) {
  const res = await request(url, options);
  return { status: res.status, data: await res.json().catch(() => ({})), res };
}

function asAdmin(url, options = {}) {
  return json(url, { ...options, headers: { Cookie: adminCookie, ...(options.headers || {}) } });
}

// Картинка-заглушка нужного формата и размера: настоящий PNG с длинным хвостом
function pngDataUrl(bytes = 4000) {
  const head = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  return 'data:image/png;base64,' + Buffer.concat([head, crypto.randomBytes(bytes)]).toString('base64');
}

before(async () => {
  server = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, PORT: String(PORT), DB_FILE, ADMIN_EMAIL, ADMIN_PASSWORD, PUBLIC_URL, NODE_ENV: 'test' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  server.stderr.on('data', chunk => {
    const line = String(chunk);
    if (!/ExperimentalWarning/.test(line)) process.stderr.write(`[server] ${line}`);
  });
  // Ждём, пока сервер поднимется
  for (let i = 0; i < 60; i++) {
    try {
      if ((await request('/api/site')).ok) break;
    } catch (_) { /* ещё не слушает */ }
    await new Promise(r => setTimeout(r, 250));
  }
  const login = await json('/api/login', {
    method: 'POST', body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD }),
  });
  assert.equal(login.status, 200, 'администратор должен входить');
  adminCookie = (login.res.headers.getSetCookie?.() || []).map(c => c.split(';')[0]).join('; ');
});

after(() => {
  server?.kill();
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(DB_FILE + suffix); } catch (_) { /* уже нет */ }
  }
});

test('версия сервера наружу не сообщается', async () => {
  const res = await request('/api/site');
  assert.equal(res.headers.get('x-powered-by'), null);
});

test('обычный адрес не принимает многомегабайтное тело', async () => {
  const { status } = await json('/api/track', {
    method: 'POST',
    body: JSON.stringify({ event: 'visit', path: 'x'.repeat(400 * 1024) }),
  });
  assert.equal(status, 413, 'тело больше предела должно отклоняться');
});

test('документы верификации по-прежнему принимают настоящее фото', async () => {
  const email = `client-${crypto.randomBytes(4).toString('hex')}@example.invalid`;
  const reg = await json('/api/register', {
    method: 'POST', body: JSON.stringify({ email, password: 'parol123' }),
  });
  assert.equal(reg.status, 200);
  const cookie = (reg.res.headers.getSetCookie?.() || []).map(c => c.split(';')[0]).join('; ');

  const ok = await json('/api/verification', {
    method: 'POST',
    headers: { Cookie: cookie },
    body: JSON.stringify({
      full_name: 'Иванов Иван', phone: '+79001234567', telegram: 'ivanov',
      passport: pngDataUrl(), selfie: pngDataUrl(),
    }),
  });
  assert.equal(ok.status, 200, ok.data.error);
});

test('файл, который только назвался картинкой, не сохраняется', async () => {
  const email = `client-${crypto.randomBytes(4).toString('hex')}@example.invalid`;
  const reg = await json('/api/register', {
    method: 'POST', body: JSON.stringify({ email, password: 'parol123' }),
  });
  const cookie = (reg.res.headers.getSetCookie?.() || []).map(c => c.split(';')[0]).join('; ');

  // Заголовок говорит «png», а внутри разметка страницы
  const fake = 'data:image/png;base64,' + Buffer.from('<html><script>alert(1)</script>'.repeat(80)).toString('base64');
  const { status, data } = await json('/api/verification', {
    method: 'POST',
    headers: { Cookie: cookie },
    body: JSON.stringify({
      full_name: 'Петров Пётр', phone: '+79001234567', telegram: 'petrov',
      passport: fake, selfie: pngDataUrl(),
    }),
  });
  assert.equal(status, 400);
  assert.match(data.error, /не картинка/i);
});

test('ссылка из письма ведёт на свой домен, а не на присланный в заголовке', async () => {
  const email = `staff-${crypto.randomBytes(4).toString('hex')}@example.invalid`;
  const { status, data } = await asAdmin('/api/admin/staff', {
    method: 'POST',
    headers: { Host: 'zloy-sayt.example' },
    body: JSON.stringify({ email }),
  });
  assert.equal(status, 200, data.error);
  assert.ok(data.link.startsWith(PUBLIC_URL + '/reset.html?token='),
    `ссылка должна вести на ${PUBLIC_URL}, а ведёт на ${data.link}`);
});

test('секреты лежат в базе зашифрованными', async () => {
  // Читаем файл базы так же, как его прочёл бы тот, кто её унёс
  const raw = new Database(DB_FILE, { readonly: true });
  const stored = raw.prepare("SELECT value FROM settings WHERE key = 'agent_token'").get().value;
  raw.close();

  const { data } = await asAdmin('/api/admin/settings');
  assert.ok(data.agent_env.includes('AGENT_API_TOKEN='), 'админка отдаёт готовые строки .env');
  const token = data.agent_env.split('AGENT_API_TOKEN=')[1].trim();

  assert.ok(token.length > 20, 'токен агента должен быть заполнен');
  assert.ok(stored.startsWith('enc:v1:'), 'в базе должно лежать зашифрованное значение');
  assert.ok(!stored.includes(token), 'открытого токена в базе быть не должно');
});

test('просроченная сессия перестаёт работать', async () => {
  const email = `stale-${crypto.randomBytes(4).toString('hex')}@example.invalid`;
  const reg = await json('/api/register', {
    method: 'POST', body: JSON.stringify({ email, password: 'parol123' }),
  });
  const cookie = (reg.res.headers.getSetCookie?.() || []).map(c => c.split(';')[0]).join('; ');

  const alive = await json('/api/me', { headers: { Cookie: cookie } });
  assert.equal(alive.data.user.email, email, 'свежая сессия работает');

  // Отматываем срок назад — как будто кукой не пользовались больше месяца
  const raw = new Database(DB_FILE);
  raw.prepare("UPDATE sessions SET expires_at = datetime('now', '-1 day') WHERE user_id = (SELECT id FROM users WHERE email = ?)").run(email);
  raw.close();

  const dead = await json('/api/me', { headers: { Cookie: cookie } });
  assert.equal(dead.data.user, null, 'просроченная сессия не должна пускать');
});

test('выход со всех устройств закрывает и другие входы', async () => {
  const email = `multi-${crypto.randomBytes(4).toString('hex')}@example.invalid`;
  const password = 'parol123';
  await json('/api/register', { method: 'POST', body: JSON.stringify({ email, password }) });

  const first = await json('/api/login', { method: 'POST', body: JSON.stringify({ email, password }) });
  const firstCookie = (first.res.headers.getSetCookie?.() || []).map(c => c.split(';')[0]).join('; ');
  const second = await json('/api/login', { method: 'POST', body: JSON.stringify({ email, password }) });
  const secondCookie = (second.res.headers.getSetCookie?.() || []).map(c => c.split(';')[0]).join('; ');

  const closed = await json('/api/logout-everywhere', { method: 'POST', headers: { Cookie: secondCookie } });
  assert.equal(closed.status, 200);

  const check = await json('/api/me', { headers: { Cookie: firstCookie } });
  assert.equal(check.data.user, null, 'первый вход тоже должен закрыться');
});

// Этот случай идёт последним: он намеренно упирается в предел попыток по адресу,
// и после него вход с этого же адреса будет отвечать отказом.
test('подбор пароля упирается в предел', async () => {
  const email = `brute-${crypto.randomBytes(4).toString('hex')}@example.invalid`;
  await json('/api/register', { method: 'POST', body: JSON.stringify({ email, password: 'parol123' }) });

  let sawLimit = false;
  let wrongAnswers = 0;
  for (let i = 0; i < 25; i++) {
    const { status } = await json('/api/login', {
      method: 'POST', body: JSON.stringify({ email, password: 'ne-tot-parol-' + i }),
    });
    if (status === 400) { wrongAnswers++; continue; }
    if (status === 429) { sawLimit = true; break; }
    assert.fail(`неожиданный ответ ${status}`);
  }
  assert.ok(sawLimit, 'после серии неудачных попыток должен наступать отказ');
  assert.ok(wrongAnswers <= 20, `до отказа прошло ${wrongAnswers} попыток — предел не сработал`);

  // Правильный пароль в это окно тоже не принимается: иначе предел ничего не значит
  const withRightPassword = await json('/api/login', {
    method: 'POST', body: JSON.stringify({ email, password: 'parol123' }),
  });
  assert.equal(withRightPassword.status, 429);
});
