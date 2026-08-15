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
const UPLOADS_DIR = path.join(os.tmpdir(), `kometa-uploads-${crypto.randomBytes(6).toString('hex')}`);
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
    env: { ...process.env, UPLOADS_DIR, PORT: String(PORT), DB_FILE, ADMIN_EMAIL, ADMIN_PASSWORD, PUBLIC_URL, NODE_ENV: 'test' },
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
  try { fs.rmSync(UPLOADS_DIR, { recursive: true, force: true }); } catch (_) { /* её могло и не быть */ }
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

test('удаление верификации стирает фото с диска и присланные данные', async () => {
  // Пользователя заводим прямо в базе: счётчик регистраций к этому месту уже
  // исчерпан другими проверками, а предмет этого теста — не он
  const { hashPasswordSync } = require('../security');
  const email = `verif-${crypto.randomBytes(4).toString('hex')}@example.invalid`;
  const password = crypto.randomBytes(12).toString('hex');
  const salt = crypto.randomBytes(16).toString('hex');
  const seed = new Database(DB_FILE);
  seed.prepare("INSERT INTO users (email, name, pass_hash, pass_salt) VALUES (?, '', ?, ?)")
    .run(email, hashPasswordSync(password, salt), salt);
  seed.close();

  const login = await json('/api/login', { method: 'POST', body: JSON.stringify({ email, password }) });
  assert.equal(login.status, 200, 'заведённый клиент входит');
  const cookie = (login.res.headers.getSetCookie?.() || []).map(c => c.split(';')[0]).join('; ');

  const before = fs.readdirSync(UPLOADS_DIR).length;
  const sent = await json('/api/verification', {
    method: 'POST',
    headers: { Cookie: cookie },
    body: JSON.stringify({
      full_name: 'Сидоров Сидор', phone: '+79005554433', telegram: 'sidorov',
      passport: pngDataUrl(), selfie: pngDataUrl(),
    }),
  });
  assert.equal(sent.status, 200, sent.data.error);
  assert.equal(fs.readdirSync(UPLOADS_DIR).length, before + 2, 'оба фото легли на диск');

  const list = await asAdmin('/api/admin/verifications');
  const target = list.data.users.find(u => u.email === email);
  assert.equal(target.verify_status, 'pending');
  assert.equal(target.has_passport, 1);

  const removed = await asAdmin('/api/admin/verifications/' + target.id, { method: 'DELETE' });
  assert.equal(removed.status, 200, removed.data.error);
  assert.equal(removed.data.deleted_photos, 2);
  assert.equal(fs.readdirSync(UPLOADS_DIR).length, before, 'фото исчезли с диска');

  // Учётка осталась, но всё присланное на проверку ушло
  const own = await json('/api/verification', { headers: { Cookie: cookie } });
  assert.equal(own.data.status, 'none', 'клиент может подать документы заново');
  assert.equal(own.data.full_name, '');
  assert.equal(own.data.phone, '');
  assert.equal(own.data.telegram, '');
});

test('удаление заявки убирает её насовсем', async () => {
  const raw = new Database(DB_FILE);
  const dir = raw.prepare('SELECT id FROM directions LIMIT 1').get();
  const user = raw.prepare('SELECT id FROM users WHERE is_admin = 0 LIMIT 1').get();
  const id = raw.prepare(`INSERT INTO orders (user_id, direction_id, amount_from, amount_to, rate, status, contact)
    VALUES (?, ?, 5000, 50, 0.01, 'new', 'udalyaem')`).run(user.id, dir.id).lastInsertRowid;
  raw.close();

  const listed = await asAdmin('/api/admin/orders');
  assert.ok(listed.data.orders.some(o => o.id === id), 'заявка видна до удаления');

  const removed = await asAdmin('/api/admin/orders/' + id, { method: 'DELETE' });
  assert.equal(removed.status, 200, removed.data.error);

  const after = await asAdmin('/api/admin/orders');
  assert.ok(!after.data.orders.some(o => o.id === id), 'и пропала после');

  const again = await asAdmin('/api/admin/orders/' + id, { method: 'DELETE' });
  assert.equal(again.status, 404, 'повторное удаление отвечает, что заявки нет');
});

test('заявки и верификации удаляет только администратор', async () => {
  for (const url of ['/api/admin/orders/1', '/api/admin/verifications/1']) {
    const res = await request(url, { method: 'DELETE' });
    assert.equal(res.status, 403, url + ' закрыт для посторонних');
  }
});

// Заводит клиента напрямую в базе: счётчик регистраций к этому месту исчерпан
function makeClient() {
  const { hashPasswordSync } = require('../security');
  const email = `blok-${crypto.randomBytes(4).toString('hex')}@example.invalid`;
  const password = crypto.randomBytes(12).toString('hex');
  const salt = crypto.randomBytes(16).toString('hex');
  const raw = new Database(DB_FILE);
  const id = raw.prepare("INSERT INTO users (email, name, pass_hash, pass_salt) VALUES (?, '', ?, ?)")
    .run(email, hashPasswordSync(password, salt), salt).lastInsertRowid;
  raw.close();
  return { id, email, password };
}

test('заблокированный клиент не входит и теряет открытые входы', async () => {
  const client = makeClient();
  const first = await json('/api/login', { method: 'POST', body: JSON.stringify(client) });
  assert.equal(first.status, 200);
  const cookie = (first.res.headers.getSetCookie?.() || []).map(c => c.split(';')[0]).join('; ');
  assert.equal((await json('/api/me', { headers: { Cookie: cookie } })).data.user.email, client.email);

  const blocked = await asAdmin('/api/admin/clients/' + client.id, { method: 'PATCH', body: JSON.stringify({ blocked: true }) });
  assert.equal(blocked.status, 200, blocked.data.error);

  // Открытый вход закрылся сразу
  assert.equal((await json('/api/me', { headers: { Cookie: cookie } })).data.user, null);
  // И заново не войти
  const again = await json('/api/login', { method: 'POST', body: JSON.stringify(client) });
  assert.equal(again.status, 403, 'вход закрытой учётки не проходит');
  assert.match(again.data.error, /закрыт/i);

  // Данные на месте, доступ возвращается
  const listed = (await asAdmin('/api/admin/clients')).data.clients.find(c => c.id === client.id);
  assert.equal(listed.blocked, 1, 'в списке видно, что доступ закрыт');
  await asAdmin('/api/admin/clients/' + client.id, { method: 'PATCH', body: JSON.stringify({ blocked: false }) });
  assert.equal((await json('/api/login', { method: 'POST', body: JSON.stringify(client) })).status, 200, 'после разблокировки входит');
});

test('удаление клиента уносит заявки, переписку и документы', async () => {
  const client = makeClient();
  const login = await json('/api/login', { method: 'POST', body: JSON.stringify(client) });
  const cookie = (login.res.headers.getSetCookie?.() || []).map(c => c.split(';')[0]).join('; ');

  const filesBefore = fs.readdirSync(UPLOADS_DIR).length;
  await json('/api/verification', {
    method: 'POST', headers: { Cookie: cookie },
    body: JSON.stringify({ full_name: 'Удаляев Удал', phone: '+79007776655', telegram: 'udalyaev', passport: pngDataUrl(), selfie: pngDataUrl() }),
  });
  await json('/api/chat/messages', { method: 'POST', headers: { Cookie: cookie }, body: JSON.stringify({ iv: 'aaa', ciphertext: 'bbb' }) });

  const raw = new Database(DB_FILE);
  const dir = raw.prepare('SELECT id FROM directions LIMIT 1').get();
  raw.prepare(`INSERT INTO orders (user_id, direction_id, amount_from, amount_to, rate, status, contact)
    VALUES (?, ?, 1000, 10, 0.01, 'new', 'udal')`).run(client.id, dir.id);
  raw.close();

  assert.equal(fs.readdirSync(UPLOADS_DIR).length, filesBefore + 2, 'документы легли на диск');

  const removed = await asAdmin('/api/admin/clients/' + client.id, { method: 'DELETE' });
  assert.equal(removed.status, 200, removed.data.error);
  assert.equal(removed.data.deleted_orders, 1);
  assert.equal(removed.data.deleted_messages, 1);
  assert.equal(removed.data.deleted_files, 2);
  assert.equal(fs.readdirSync(UPLOADS_DIR).length, filesBefore, 'файлы стёрты с диска');

  const check = new Database(DB_FILE, { readonly: true });
  assert.equal(check.prepare('SELECT id FROM users WHERE id = ?').get(client.id), undefined, 'учётки нет');
  assert.equal(check.prepare('SELECT COUNT(*) c FROM orders WHERE user_id = ?').get(client.id).c, 0);
  assert.equal(check.prepare('SELECT COUNT(*) c FROM messages WHERE user_id = ?').get(client.id).c, 0);
  assert.equal(check.prepare('SELECT COUNT(*) c FROM sessions WHERE user_id = ?').get(client.id).c, 0);
  check.close();

  assert.equal((await json('/api/login', { method: 'POST', body: JSON.stringify(client) })).status, 400, 'войти больше нечем');
});

test('администратора не заблокировать и не удалить', async () => {
  const raw = new Database(DB_FILE, { readonly: true });
  const admin = raw.prepare('SELECT id FROM users WHERE is_admin = 1').get();
  raw.close();
  const blocked = await asAdmin('/api/admin/clients/' + admin.id, { method: 'PATCH', body: JSON.stringify({ blocked: true }) });
  assert.equal(blocked.status, 400);
  const removed = await asAdmin('/api/admin/clients/' + admin.id, { method: 'DELETE' });
  assert.equal(removed.status, 400);
});

test('клиент убирает из кабинета свою отработавшую заявку, но не чужую и не рабочую', async () => {
  const mine = makeClient();
  const other = makeClient();
  const login = await json('/api/login', { method: 'POST', body: JSON.stringify(mine) });
  const cookie = (login.res.headers.getSetCookie?.() || []).map(c => c.split(';')[0]).join('; ');

  const raw = new Database(DB_FILE);
  const dir = raw.prepare('SELECT id FROM directions LIMIT 1').get();
  const add = (userId, status) => raw.prepare(`INSERT INTO orders (user_id, direction_id, amount_from, amount_to, rate, status, contact)
    VALUES (?, ?, 1000, 10, 0.01, ?, 'kabinet')`).run(userId, dir.id, status).lastInsertRowid;
  const doneId = add(mine.id, 'done');
  const workingId = add(mine.id, 'processing');
  const strangerId = add(other.id, 'done');
  raw.close();

  const asMine = (url, options = {}) => json(url, { ...options, headers: { Cookie: cookie, ...(options.headers || {}) } });

  // Заявка в работе не удаляется: по ней ещё ведут сделку
  const working = await asMine('/api/orders/' + workingId, { method: 'DELETE' });
  assert.equal(working.status, 400);
  assert.match(working.data.error, /в работе/i);

  // Чужая — как будто её не существует
  const stranger = await asMine('/api/orders/' + strangerId, { method: 'DELETE' });
  assert.equal(stranger.status, 404, 'чужая заявка недоступна даже для просмотра ошибки');

  // Своя выполненная убирается
  const done = await asMine('/api/orders/' + doneId, { method: 'DELETE' });
  assert.equal(done.status, 200, done.data.error);

  const left = (await asMine('/api/orders')).data.orders.map(o => o.id);
  assert.deepEqual(left, [workingId], 'в кабинете осталась только рабочая заявка');

  const check = new Database(DB_FILE, { readonly: true });
  assert.ok(check.prepare('SELECT id FROM orders WHERE id = ?').get(strangerId), 'чужая заявка цела');
  check.close();
});
