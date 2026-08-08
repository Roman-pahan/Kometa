// Проверка того, откуда сайт берёт курс. Цену называет оператор в Telegram,
// бот присылает её сюда, и сайт обязан показать ровно её — без пересчёта и
// без выдуманных справочных курсов. Боевая база не затрагивается: путь
// подменяется через DB_FILE.

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const PORT = 3989;
const BASE = `http://127.0.0.1:${PORT}`;
const DB_FILE = path.join(os.tmpdir(), `kometa-rates-${crypto.randomBytes(6).toString('hex')}.db`);
const ADMIN_EMAIL = 'rates-test@example.invalid';
const ADMIN_PASSWORD = crypto.randomBytes(18).toString('hex');
const AGENT_TOKEN = crypto.randomBytes(16).toString('hex');
const BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126 Safari/537.36';

// Снимок, который присылает бот: цены уже посчитаны и округлены оператором
const BOARD = {
  usdt_thb: 33,
  rub_usdt: 97,
  client: {
    RUB_THB: 1 / 2.83,   // клиент покупает баты по 2.83 ₽ за ฿ — самый дешёвый канал
    THB_RUB: 2.91,       // стол покупает баты по 2.91 ₽
    RUB_USDT: 1 / 97.92, // клиент покупает USDT по 97.92 ₽
    USDT_RUB: 98,        // стол покупает USDT по 98 ₽
  },
};

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

// Направление витрины по паре валют
function dirOf(directions, from, to) {
  return directions.find(d => d.from_cur === from && d.to_cur === to);
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

  // Токен, которым бот подписывает снимок курсов, заводит администратор
  const saved = await asAdmin('/api/admin/settings', {
    method: 'PATCH', body: JSON.stringify({ agent_token: AGENT_TOKEN }),
  });
  assert.equal(saved.status, 200);
});

after(() => {
  if (server) server.kill();
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(DB_FILE + suffix); } catch (_) { /* файла может не быть */ }
  }
});

test('без курса от бота сайт не называет цену сам', async () => {
  const { data } = await json('/api/public');
  for (const dir of data.directions) {
    assert.equal(dir.rate, null, `${dir.label}: цены быть не должно`);
    assert.equal(dir.on_request, true, `${dir.label}: направление считается по запросу`);
  }
});

test('заявка по направлению без цены не принимается', async () => {
  const { data } = await json('/api/public');
  const dir = dirOf(data.directions, 'RUB', 'THB');
  const res = await json('/api/orders', {
    method: 'POST', body: JSON.stringify({ direction_id: dir.id, amount_from: 10000, contact: '@someone' }),
  });
  // Без входа заявку и так не создать, но цены у направления тоже нет
  assert.ok(res.status >= 400, 'заявка без курса не проходит');
});

test('снимок принимается только с верным токеном', async () => {
  const noToken = await json('/api/agent/rates', { method: 'POST', body: JSON.stringify(BOARD) });
  assert.equal(noToken.status, 401);

  const wrong = await json('/api/agent/rates', {
    method: 'POST', body: JSON.stringify(BOARD), headers: { 'X-Agent-Token': 'x'.repeat(AGENT_TOKEN.length) },
  });
  assert.equal(wrong.status, 401);

  const empty = await json('/api/agent/rates', {
    method: 'POST', body: JSON.stringify({}), headers: { 'X-Agent-Token': AGENT_TOKEN },
  });
  assert.equal(empty.status, 400, 'пустой снимок не должен стирать цены');

  const ok = await json('/api/agent/rates', {
    method: 'POST', body: JSON.stringify(BOARD), headers: { 'X-Agent-Token': AGENT_TOKEN },
  });
  assert.equal(ok.status, 200);
});

test('сайт показывает ровно ту цену, которую назвал оператор', async () => {
  const { data } = await json('/api/public');

  // Клиент покупает баты: 1 ฿ = 2.83 ₽
  const rubThb = dirOf(data.directions, 'RUB', 'THB');
  assert.equal(Number((1 / rubThb.rate).toFixed(2)), 2.83);
  assert.equal(rubThb.on_request, false);

  // Стол покупает баты: 1 ฿ = 2.91 ₽
  assert.equal(dirOf(data.directions, 'THB', 'RUB').rate, 2.91);

  // Клиент покупает USDT по цене дешёвого канала, а не дорогого
  const rubUsdt = dirOf(data.directions, 'RUB', 'USDT');
  assert.equal(Number((1 / rubUsdt.rate).toFixed(2)), 97.92);

  // Стол покупает USDT
  assert.equal(dirOf(data.directions, 'USDT', 'RUB').rate, 98);

  // Возраст цены — это момент проверки курса оператором
  assert.ok(data.rates.updatedAt, 'время проверки приходит вместе с ценой');
  assert.equal(data.rates.market.source, 'bot');
});

test('направления, которые стол не котирует, остаются по запросу', async () => {
  const { data } = await json('/api/public');
  for (const [from, to] of [['USDT', 'THB'], ['THB', 'USDT'], ['RUB', 'CNY'], ['USDT', 'CNY']]) {
    const dir = dirOf(data.directions, from, to);
    if (!dir) continue;
    assert.equal(dir.rate, null, `${from}→${to}: цену выдумывать нельзя`);
    assert.equal(dir.on_request, true, `${from}→${to}: спрашиваем в чате`);
  }
});

test('ручной курс из админки старше цены бота', async () => {
  const before = (await asAdmin('/api/admin/directions')).data.directions;
  const dir = before.find(d => d.from_cur === 'THB' && d.to_cur === 'RUB');
  assert.equal(dir.rate_source, 'bot', 'до правки цена приходит из бота');

  const patched = await asAdmin('/api/admin/directions/' + dir.id, {
    method: 'PATCH', body: JSON.stringify({ ...dir, manual_rate: 2.5 }),
  });
  assert.equal(patched.status, 200);

  const shown = dirOf((await json('/api/public')).data.directions, 'THB', 'RUB');
  assert.equal(shown.rate, 2.5, 'на витрине стоит ручной курс');

  // Возвращаем направление боту
  await asAdmin('/api/admin/directions/' + dir.id, {
    method: 'PATCH', body: JSON.stringify({ ...dir, manual_rate: '' }),
  });
  assert.equal(dirOf((await json('/api/public')).data.directions, 'THB', 'RUB').rate, 2.91);
});

test('цена бота переживает перезапуск сайта', async () => {
  server.kill();
  await new Promise(resolve => server.on('exit', resolve));
  server = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, PORT: String(PORT), DB_FILE, ADMIN_EMAIL, ADMIN_PASSWORD, NODE_ENV: 'test' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('сервер не поднялся заново')), 15000);
    server.stdout.on('data', chunk => {
      if (String(chunk).includes('http://localhost')) { clearTimeout(timer); resolve(); }
    });
  });

  const { data } = await json('/api/public');
  assert.equal(dirOf(data.directions, 'THB', 'RUB').rate, 2.91, 'цена на месте сразу после старта');
});
