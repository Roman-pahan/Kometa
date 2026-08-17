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
const UPLOADS_DIR = path.join(os.tmpdir(), `kometa-uploads-${crypto.randomBytes(6).toString('hex')}`);
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
    env: { ...process.env, UPLOADS_DIR, PORT: String(PORT), DB_FILE, ADMIN_EMAIL, ADMIN_PASSWORD, NODE_ENV: 'test' },
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

  // Токен для бота сайт заводит сам при первом запуске: придумывать нечего
  const fresh = await asAdmin('/api/admin/settings');
  assert.equal(fresh.data.agent_token_set, true, 'токен создаётся без участия человека');
  assert.match(fresh.data.agent_env, /^SITE_URL=http.+\nAGENT_API_TOKEN=[a-f0-9]{48}$/,
    'в админке лежат готовые строки для .env бота');

  // Дальше тесты работают со своим токеном
  const saved = await asAdmin('/api/admin/settings', {
    method: 'PATCH', body: JSON.stringify({ agent_token: AGENT_TOKEN }),
  });
  assert.equal(saved.status, 200);
  const changed = await asAdmin('/api/admin/settings');
  assert.ok(changed.data.agent_env.endsWith('AGENT_API_TOKEN=' + AGENT_TOKEN), 'строки показывают текущий токен');
});

after(() => {
  if (server) server.kill();
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(DB_FILE + suffix); } catch (_) { /* файла может не быть */ }
  }
  try { fs.rmSync(UPLOADS_DIR, { recursive: true, force: true }); } catch (_) { /* её могло и не быть */ }
});

test('копия данных забирается только по своему паролю', async () => {
  // Без пароля наружу не отдаётся ничего.
  for (const url of ['/api/admin/backup/db', '/api/admin/backup/files']) {
    const res = await request(url);
    assert.equal(res.status, 401, url + ' без токена должен отказать');
  }
  // Чужой пароль тоже не подходит.
  const settings = (await asAdmin('/api/admin/settings')).data;
  const wrong = await request('/api/admin/backup/files', {
    headers: { 'X-Backup-Token': 'x'.repeat(settings.backup_token.length) },
  });
  assert.equal(wrong.status, 401);

  // Пароль создаётся сам и виден только администратору.
  assert.match(settings.backup_token, /^[a-f0-9]{48}$/);
  // Токен бота и токен выгрузки — разные пароли: у них разная цена ошибки.
  assert.notEqual(settings.backup_token, AGENT_TOKEN);

  const headers = { 'X-Backup-Token': settings.backup_token };
  // Список вложений отдаётся.
  const files = await json('/api/admin/backup/files', { headers });
  assert.equal(files.status, 200);
  assert.ok(Array.isArray(files.data.files));

  // База отдаётся целиком и открывается как настоящая база SQLite.
  const dump = await request('/api/admin/backup/db', { headers });
  assert.equal(dump.status, 200);
  const body = Buffer.from(await dump.arrayBuffer());
  assert.ok(body.length > 1000, 'копия базы не может быть пустой');
  assert.equal(body.subarray(0, 15).toString('latin1'), 'SQLite format 3');
  // Момент снимка едет вместе с файлом — по нему потом подтверждают получение
  assert.ok(dump.headers.get('x-snapshot-at'), 'снимок должен быть подписан временем');
});

test('сервер стирает только то, получение чего подтвердили', async () => {
  const settings = (await asAdmin('/api/admin/settings')).data;
  const headers = { 'X-Backup-Token': settings.backup_token };

  // Без момента снимка подтверждение не принимается: непонятно, что подтверждают.
  const blind = await json('/api/admin/backup/confirm', {
    method: 'POST', headers, body: JSON.stringify({ files: [] }),
  });
  assert.equal(blind.status, 400);

  // Обычное подтверждение проходит и отчитывается, что убрано.
  const dump = await request('/api/admin/backup/db', { headers });
  await dump.arrayBuffer();
  const snapshotAt = dump.headers.get('x-snapshot-at');
  const done = await json('/api/admin/backup/confirm', {
    method: 'POST', headers, body: JSON.stringify({ snapshot_at: snapshotAt, files: [] }),
  });
  assert.equal(done.status, 200);
  assert.equal(typeof done.data.deleted_orders, 'number');
  assert.equal(typeof done.data.deleted_photos, 'number');

  // Момент последнего подтверждения виден администратору.
  const after = (await asAdmin('/api/admin/settings')).data;
  assert.equal(after.backup_confirmed_at, snapshotAt);

  // Срок хранения настраивается и не принимает бессмыслицу.
  const bad = await asAdmin('/api/admin/settings', {
    method: 'PATCH', body: JSON.stringify({ purge_after_days: -5 }),
  });
  assert.equal(bad.status, 400);
  const good = await asAdmin('/api/admin/settings', {
    method: 'PATCH', body: JSON.stringify({ purge_after_days: 7 }),
  });
  assert.equal(good.status, 200);
  assert.equal((await asAdmin('/api/admin/settings')).data.purge_after_days, 7);
});

test('витрина знает, что юани продаются и за баты', async () => {
  const { data } = await json('/api/public');
  const dir = data.directions.find(d => d.from_cur === 'THB' && d.to_cur === 'CNY');
  assert.ok(dir, 'направление ฿ → ¥ должно появиться само');
  assert.equal(dir.label, '฿ → ¥');
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
    method: 'PATCH', body: JSON.stringify({ ...dir, price_mode: 'manual', manual_rate: 2.5 }),
  });
  assert.equal(patched.status, 200);

  const shown = dirOf((await json('/api/public')).data.directions, 'THB', 'RUB');
  assert.equal(shown.rate, 2.5, 'на витрине стоит ручной курс');

  // Возвращаем направление боту
  await asAdmin('/api/admin/directions/' + dir.id, {
    method: 'PATCH', body: JSON.stringify({ ...dir, price_mode: 'bot', manual_rate: '' }),
  });
  assert.equal(dirOf((await json('/api/public')).data.directions, 'THB', 'RUB').rate, 2.91);

  // Прежний способ — прислать один только курс, без режима — тоже работает
  await asAdmin('/api/admin/directions/' + dir.id, {
    method: 'PATCH', body: JSON.stringify({ manual_rate: 2.4 }),
  });
  assert.equal(dirOf((await json('/api/public')).data.directions, 'THB', 'RUB').rate, 2.4,
    'ручной курс без указания режима по-прежнему переключает направление');
  await asAdmin('/api/admin/directions/' + dir.id, {
    method: 'PATCH', body: JSON.stringify({ manual_rate: '' }),
  });
  assert.equal(dirOf((await json('/api/public')).data.directions, 'THB', 'RUB').rate, 2.91,
    'и пустой курс возвращает направление боту');
});

test('у каждого способа отправки свой курс, а тезер через QR не купить', async () => {
  // Бот присылает цены по каналам вместе с лучшей ценой направления.
  await json('/api/agent/rates', {
    method: 'POST',
    headers: { 'X-Agent-Token': AGENT_TOKEN },
    body: JSON.stringify({
      ...BOARD,
      client_channels: {
        // Баты можно купить всеми тремя способами
        RUB_THB: { qr: 1 / 2.83, tbank: 1 / 2.85, bank: 1 / 2.88 },
        // Тезер — только двумя: подрядчик QR выдаёт лишь баты
        RUB_USDT: { tbank: 1 / 97.92, bank: 1 / 98.5 },
      },
    }),
  });

  const dirs = (await json('/api/public')).data.directions;
  const thb = dirOf(dirs, 'RUB', 'THB');
  // Все три способа приходят на витрину со своими ценами.
  assert.deepEqual(Object.keys(thb.channel_rates).sort(), ['bank', 'qr', 'tbank']);
  assert.equal(Number((1 / thb.channel_rates.qr).toFixed(2)), 2.83);
  assert.equal(Number((1 / thb.channel_rates.bank).toFixed(2)), 2.88);

  // В направлении на тезер способа qr нет вовсе.
  const usdt = dirOf(dirs, 'RUB', 'USDT');
  assert.deepEqual(Object.keys(usdt.channel_rates).sort(), ['bank', 'tbank']);
  assert.equal(usdt.channel_rates.qr, undefined);
});

test('курс держится, пока бот не пришлёт новый, а юань живёт только свежим', async () => {
  // Сначала полный набор, вместе с юанем.
  const full = {
    usdt_thb: 33,
    rub_usdt: 97,
    client: { ...BOARD.client, USDT_CNY: 6.9 },
  };
  await json('/api/agent/rates', {
    method: 'POST', body: JSON.stringify(full), headers: { 'X-Agent-Token': AGENT_TOKEN },
  });
  let dirs = (await json('/api/public')).data.directions;
  assert.equal(dirOf(dirs, 'USDT', 'CNY').rate, 6.9);
  // У каждой цены есть момент подтверждения.
  assert.ok(dirOf(dirs, 'THB', 'RUB').rate_at, 'курс подписан временем');

  // Следующая отправка потеряла часть курсов: биржа не ответила.
  await json('/api/agent/rates', {
    method: 'POST',
    body: JSON.stringify({ usdt_thb: 33, rub_usdt: 97, client: { RUB_THB: 1 / 2.9 } }),
    headers: { 'X-Agent-Token': AGENT_TOKEN },
  });
  dirs = (await json('/api/public')).data.directions;
  // Новый курс встал.
  assert.equal(Number((1 / dirOf(dirs, 'RUB', 'THB').rate).toFixed(2)), 2.9);
  // Старые остались на витрине, а не пропали.
  assert.equal(dirOf(dirs, 'THB', 'RUB').rate, 2.91);
  assert.equal(dirOf(dirs, 'USDT', 'RUB').rate, 98);
  // А юань исчез: его курс называют по запросу, вчерашний тут не годится.
  assert.equal(dirOf(dirs, 'USDT', 'CNY').rate, null);
  assert.equal(dirOf(dirs, 'USDT', 'CNY').on_request, true);
  // Это правило распространяется на все юаневые направления, включая новые.
  for (const [from, to] of [['RUB', 'CNY'], ['THB', 'CNY']]) {
    const dir = dirOf(dirs, from, to);
    if (dir) assert.equal(dir.rate, null, `${from}→${to}: старый курс юаня не показываем`);
  }

  // Возвращаем прежнюю цену бата, чтобы следующий тест видел её.
  await json('/api/agent/rates', {
    method: 'POST', body: JSON.stringify(BOARD), headers: { 'X-Agent-Token': AGENT_TOKEN },
  });
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

test('в карточке направления видна маржа, которую заложил бот', async () => {
  await request('/api/agent/rates', {
    method: 'POST',
    headers: { 'X-Agent-Token': AGENT_TOKEN },
    body: JSON.stringify({
      ...BOARD,
      margins: { qr1: 3, qr2: 2.5, tbank: 2, global: 1.8, rub_sale: 2.2, cny_sale: 4, thb_usdt: 1.5 },
    }),
  });

  const { data } = await asAdmin('/api/admin/directions');
  const find = (from, to) => data.directions.find(d => d.from_cur === from && d.to_cur === to);

  // Рубли клиента: у каждого способа отправки своя наценка, по QR берём дешёвую
  assert.deepEqual(find('RUB', 'THB').margin, { tbank: 2, bank: 1.8, qr: 2.5 });
  // Через QR тезер не купить — и канала в марже нет
  assert.deepEqual(find('RUB', 'USDT').margin, { tbank: 2, bank: 1.8 });
  // Остальные направления идут одной цифрой
  assert.deepEqual(find('THB', 'RUB').margin, { all: 2.2 });
  assert.deepEqual(find('THB', 'USDT').margin, { all: 1.5 });
  assert.deepEqual(find('THB', 'CNY').margin, { all: 4 });
  assert.deepEqual(find('RUB', 'CNY').margin, { all: 4 });
});

test('своя маржа считает цену от себестоимости', async () => {
  const dirs = (await asAdmin('/api/admin/directions')).data.directions;
  const dir = dirs.find(d => d.from_cur === 'THB' && d.to_cur === 'RUB');
  // Себестоимость — тот самый справочный кросс-курс: 97 ₽ за USDT / 33 ฿ за USDT
  const cost = dir.base_rate;
  assert.ok(cost > 0, 'себестоимость известна');

  const saved = await asAdmin('/api/admin/directions/' + dir.id, {
    method: 'PATCH', body: JSON.stringify({ ...dir, price_mode: 'margin', markup_pct: 5, manual_rate: '' }),
  });
  assert.equal(saved.status, 200, saved.data.error);

  const shown = dirOf((await json('/api/public')).data.directions, 'THB', 'RUB');
  assert.ok(Math.abs(shown.rate - cost * 0.95) < 1e-6,
    `клиент получает на 5% меньше себестоимости: ждали ${cost * 0.95}, показано ${shown.rate}`);
  assert.equal(shown.on_request, false);
  // Способы отправки в этом режиме не различаются
  assert.equal(shown.channel_rates, null, 'своя маржа — одна цена на все каналы');

  const back = (await asAdmin('/api/admin/directions')).data.directions.find(d => d.id === dir.id);
  assert.equal(back.rate_source, 'margin', 'админка показывает, чем назначена цена');

  // Возвращаем боту
  await asAdmin('/api/admin/directions/' + dir.id, {
    method: 'PATCH', body: JSON.stringify({ ...dir, price_mode: 'bot', manual_rate: '' }),
  });
  assert.equal(dirOf((await json('/api/public')).data.directions, 'THB', 'RUB').rate, 2.91);
});

test('маржа без себестоимости не выдумывает курс', async () => {
  const dirs = (await asAdmin('/api/admin/directions')).data.directions;
  // Юань бот в этом наборе не присылал — считать не от чего
  const dir = dirs.find(d => d.from_cur === 'THB' && d.to_cur === 'CNY');
  await asAdmin('/api/admin/directions/' + dir.id, {
    method: 'PATCH', body: JSON.stringify({ ...dir, price_mode: 'margin', markup_pct: 4, manual_rate: '' }),
  });
  const shown = dirOf((await json('/api/public')).data.directions, 'THB', 'CNY');
  assert.equal(shown.rate, null, 'без себестоимости цены нет');
  assert.equal(shown.on_request, true, 'направление честно уходит в «по запросу»');
});

test('себестоимость держится на курсах бота, а не на внешнем справочнике', async () => {
  // Прогоняем расчёт напрямую: у модуля курсов своя таблица, и она должна
  // обходиться присланными ботом ногами без похода наружу.
  const { execFileSync } = require('node:child_process');
  const script = `
    const rates = require('./rates.js');
    // Внешний источник недоступен — как будто интернета нет вовсе
    global.fetch = () => Promise.reject(new Error('нет сети'));
    const { setSetting } = require('./db.js');
    setSetting('agent_board', JSON.stringify({
      usdt_thb: 33, rub_usdt: 97, received_at: new Date().toISOString(),
      client: { THB_RUB: 2.91 },
    }));
    rates.applyPushedBoard();
    const dir = { from_cur: 'THB', to_cur: 'RUB', markup_pct: 5, price_mode: 'margin' };
    const priced = rates.directionRate(dir);
    console.log(JSON.stringify({ base: rates.crossRate('THB', 'RUB'), rate: priced.rate, source: priced.source }));
  `;
  const out = execFileSync(process.execPath, ['-e', script], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, DB_FILE: path.join(os.tmpdir(), `kometa-cost-${crypto.randomBytes(4).toString('hex')}.db`), UPLOADS_DIR },
  }).toString();
  const result = JSON.parse(out.trim().split('\n').pop());

  assert.ok(Math.abs(result.base - 97 / 33) < 1e-9, 'себестоимость посчиталась из ног бота');
  assert.equal(result.source, 'margin');
  assert.ok(Math.abs(result.rate - (97 / 33) * 0.95) < 1e-9, 'маржа снялась с этой себестоимости');
});

test('закупочная цена ключей приходит от бота и показывается как есть', async () => {
  await request('/api/agent/rates', {
    method: 'POST',
    headers: { 'X-Agent-Token': AGENT_TOKEN },
    body: JSON.stringify({
      ...BOARD,
      keys: { youpin_cny: 11.14, buy_usdt: 1.61, buy_rub: 142.71, margin_percent: 4 },
    }),
  });

  const { data } = await asAdmin('/api/admin/directions');
  assert.deepEqual(data.keys, { youpin_cny: 11.14, buy_usdt: 1.61, buy_rub: 142.71, margin_percent: 4 },
    'сайт отдаёт цену ключей ровно такой, какой прислал бот');

  // Наружу, клиентам, она не уходит: это внутренняя цифра оператора
  const pub = await json('/api/public');
  assert.equal(pub.data.keys, undefined, 'на витрине цены закупки нет');
});

test('без цены ключей сайт не выдумывает её', async () => {
  await request('/api/agent/rates', {
    method: 'POST',
    headers: { 'X-Agent-Token': AGENT_TOKEN },
    body: JSON.stringify({ ...BOARD, keys: { youpin_cny: null, buy_usdt: null, buy_rub: null, margin_percent: 4 } }),
  });
  const { data } = await asAdmin('/api/admin/directions');
  assert.equal(data.keys.buy_usdt, null);
  assert.equal(data.keys.youpin_cny, null);
});

test('ключи на витрине только выкупаются, обратной пары нет', async () => {
  await request('/api/agent/rates', {
    method: 'POST',
    headers: { 'X-Agent-Token': AGENT_TOKEN },
    body: JSON.stringify({
      ...BOARD,
      client: { ...BOARD.client, KEY_USDT: 1.61, KEY_RUB: 142.71 },
      keys: { youpin_cny: 11.14, buy_usdt: 1.61, buy_rub: 142.71, margin_percent: 4 },
    }),
  });

  const pub = (await json('/api/public')).data.directions;
  const toUsdt = dirOf(pub, 'KEY', 'USDT');
  const toRub = dirOf(pub, 'KEY', 'RUB');

  assert.ok(toUsdt, 'направление «ключи за тезер» есть на витрине');
  assert.equal(toUsdt.rate, 1.61, 'за ключ дают ровно то, что посчитал бот');
  assert.equal(toRub.rate, 142.71);

  // Обратной стороны быть не должно: продажей ключей стол не занимается
  assert.equal(dirOf(pub, 'USDT', 'KEY'), undefined);
  assert.equal(dirOf(pub, 'RUB', 'KEY'), undefined);
});

test('цена выкупа ключей держится, пока не прислали новую', async () => {
  // Набор без ключей: цену сегодня не отправляли
  await request('/api/agent/rates', {
    method: 'POST',
    headers: { 'X-Agent-Token': AGENT_TOKEN },
    body: JSON.stringify(BOARD),
  });

  const pub = (await json('/api/public')).data.directions;
  const toUsdt = dirOf(pub, 'KEY', 'USDT');
  // Цена ключа на площадке стоит неделями, поэтому прошлая остаётся верной
  assert.equal(toUsdt.rate, 1.61, 'прежняя цена выкупа осталась на витрине');
  assert.equal(toUsdt.on_request, false);
  assert.equal(dirOf(pub, 'KEY', 'RUB').rate, 142.71);

  // А юань в том же наборе всё равно исчезает: там правило другое
  assert.equal(dirOf(pub, 'RUB', 'CNY').on_request, true);
});
