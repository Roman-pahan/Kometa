// Проверка учёта рекламного трафика от начала до конца: сервер поднимается
// на временной базе, запросы идут по HTTP, как из настоящего браузера.
// Боевые данные не затрагиваются: путь к базе подменяется через DB_FILE.

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const PORT = 3987;
const BASE = `http://127.0.0.1:${PORT}`;
const DB_FILE = path.join(os.tmpdir(), `kometa-test-${crypto.randomBytes(6).toString('hex')}.db`);
// Учётка администратора создаётся только внутри временной базы
const ADMIN_EMAIL = 'stats-test@example.invalid';
const ADMIN_PASSWORD = crypto.randomBytes(18).toString('hex');
// Обычный браузерный User-Agent: без него запрос считается ботом
const BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126 Safari/537.36';

let server;
let adminCookie = '';

// Запросы с сохранением куков: так ведёт себя браузер одного посетителя
function visitor() {
  const jar = new Map();
  return async function request(url, options = {}) {
    const headers = { 'User-Agent': BROWSER, ...(options.headers || {}) };
    if (jar.size) headers.Cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
    if (options.body) headers['Content-Type'] = 'application/json';
    const res = await fetch(BASE + url, { ...options, headers, redirect: 'manual' });
    for (const raw of res.headers.getSetCookie?.() || []) {
      const [pair] = raw.split(';');
      const index = pair.indexOf('=');
      jar.set(pair.slice(0, index), pair.slice(index + 1));
    }
    const data = await res.json().catch(() => ({}));
    return { status: res.status, data, jar };
  };
}

before(async () => {
  server = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, PORT: String(PORT), DB_FILE, ADMIN_EMAIL, ADMIN_PASSWORD, NODE_ENV: 'test' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  // Ждём, пока сервер сообщит, что слушает порт
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('сервер не запустился за 15 секунд')), 15000);
    server.stdout.on('data', chunk => {
      if (String(chunk).includes('http://localhost')) { clearTimeout(timer); resolve(); }
    });
    server.on('exit', code => { clearTimeout(timer); reject(new Error('сервер завершился с кодом ' + code)); });
  });

  // Вход администратора: дальше все запросы к статистике идут с его кукой
  const admin = visitor();
  const login = await admin('/api/login', { method: 'POST', body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD }) });
  assert.equal(login.status, 200, 'администратор должен войти');
  adminCookie = [...login.jar].map(([k, v]) => `${k}=${v}`).join('; ');
});

after(() => {
  if (server) server.kill();
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(DB_FILE + suffix); } catch (_) { /* файла может не быть */ }
  }
});

function admin(url, options = {}) {
  return fetch(BASE + url, {
    ...options,
    headers: { Cookie: adminCookie, 'User-Agent': BROWSER, ...(options.body ? { 'Content-Type': 'application/json' } : {}) },
  }).then(async res => ({ status: res.status, data: await res.json().catch(() => ({})) }));
}

test('переход по рекламной ссылке записывается и источник сохраняется', async () => {
  const user = visitor();
  const first = await user('/api/track', { method: 'POST', body: JSON.stringify({ ref: 'ru_thailand', event: 'visit', path: '/' }) });
  assert.equal(first.status, 200);
  assert.equal(first.data.recorded, true, 'первое посещение должно записаться');

  const stats = await admin('/api/admin/stats');
  const row = stats.data.sources.find(s => s.ref === 'ru_thailand');
  assert.ok(row, 'источник должен появиться в таблице');
  assert.equal(row.visits, 1);
  assert.equal(row.visitors, 1);
});

test('источник переживает переход на другую страницу сайта', async () => {
  const user = visitor();
  await user('/api/track', { method: 'POST', body: JSON.stringify({ ref: 'blockside', event: 'visit', path: '/' }) });
  // Вторая страница открыта уже без параметра в адресе
  await new Promise(r => setTimeout(r, 3100));
  await user('/api/track', { method: 'POST', body: JSON.stringify({ event: 'visit', path: '/cabinet.html' }) });

  const stats = await admin('/api/admin/stats');
  const row = stats.data.sources.find(s => s.ref === 'blockside');
  assert.equal(row.visits, 2, 'оба просмотра принадлежат одному источнику');
  assert.equal(row.visitors, 1, 'это один и тот же посетитель');
});

test('повторное посещение не создаёт нового уникального посетителя', async () => {
  const user = visitor();
  await user('/api/track', { method: 'POST', body: JSON.stringify({ ref: 'p2p_channel_01', event: 'visit', path: '/' }) });
  await new Promise(r => setTimeout(r, 3100));
  await user('/api/track', { method: 'POST', body: JSON.stringify({ ref: 'p2p_channel_01', event: 'visit', path: '/' }) });

  const stats = await admin('/api/admin/stats');
  const row = stats.data.sources.find(s => s.ref === 'p2p_channel_01');
  assert.equal(row.visits, 2, 'обновление страницы — это повторный просмотр');
  assert.equal(row.visitors, 1, 'но не новый посетитель');
  assert.equal(row.repeat, 1);
});

test('обновление страницы подряд не считается отдельным посещением', async () => {
  const user = visitor();
  await user('/api/track', { method: 'POST', body: JSON.stringify({ ref: 'dedupe_ref', event: 'visit', path: '/' }) });
  const again = await user('/api/track', { method: 'POST', body: JSON.stringify({ ref: 'dedupe_ref', event: 'visit', path: '/' }) });
  assert.equal(again.data.recorded, false, 'технический повтор запроса не пишется');

  const stats = await admin('/api/admin/stats');
  assert.equal(stats.data.sources.find(s => s.ref === 'dedupe_ref').visits, 1);
});

test('переход без ref учитывается как прямой трафик', async () => {
  const user = visitor();
  await user('/api/track', { method: 'POST', body: JSON.stringify({ event: 'visit', path: '/' }) });

  const stats = await admin('/api/admin/stats');
  const direct = stats.data.sources.find(s => s.ref === '');
  assert.ok(direct, 'прямой трафик показывается отдельной строкой');
  assert.equal(direct.title, 'Прямой трафик');
  assert.ok(stats.data.summary.direct >= 1);
});

test('запросы ботов не попадают в статистику', async () => {
  const before = (await admin('/api/admin/stats')).data.summary.visits;
  await fetch(BASE + '/api/track', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1)' },
    body: JSON.stringify({ ref: 'ru_thailand', event: 'visit', path: '/' }),
  });
  const after = (await admin('/api/admin/stats')).data.summary.visits;
  assert.equal(after, before, 'обходчик не увеличивает счётчик');
});

test('нажатия на обмен и на Telegram считаются с тем же источником', async () => {
  const user = visitor();
  await user('/api/track', { method: 'POST', body: JSON.stringify({ ref: 'clicks_ref', event: 'visit', path: '/' }) });
  await user('/api/track', { method: 'POST', body: JSON.stringify({ event: 'exchange_click', path: '/' }) });
  await user('/api/track', { method: 'POST', body: JSON.stringify({ event: 'telegram_click', path: '/' }) });

  const detail = (await admin('/api/admin/stats/source/clicks_ref')).data;
  assert.equal(detail.exchange_clicks, 1, 'нажатие на обмен записано');
  assert.equal(detail.telegram_clicks, 1, 'переход в Telegram записан');
  assert.equal(detail.visitors, 1);
  assert.equal(detail.telegram_rate, 100, 'сто процентов посетителей ушли в Telegram');
});

test('рекламная ссылка создаётся и её ref нельзя повторить', async () => {
  const created = await admin('/api/admin/sources', {
    method: 'POST',
    body: JSON.stringify({ ref: 'ru_thailand', title: 'Русские в Таиланде', comment: 'закреп', cost: 5000, placed_on: '2026-08-04' }),
  });
  assert.equal(created.status, 200);
  assert.match(created.data.link, /\?ref=ru_thailand$/, 'ссылка формируется автоматически');

  const twice = await admin('/api/admin/sources', {
    method: 'POST', body: JSON.stringify({ ref: 'ru_thailand', title: 'Дубль' }),
  });
  assert.equal(twice.status, 400, 'второй источник с тем же ref не создаётся');
});

test('правка источника не стирает накопленную статистику', async () => {
  const { sources } = (await admin('/api/admin/sources')).data;
  const source = sources.find(s => s.ref === 'ru_thailand');
  const before = (await admin('/api/admin/stats/source/ru_thailand')).data.visits;

  const patched = await admin('/api/admin/sources/' + source.id, {
    method: 'PATCH', body: JSON.stringify({ title: 'Русские в Таиланде — переименован', cost: 7000, enabled: false }),
  });
  assert.equal(patched.status, 200);

  const after = (await admin('/api/admin/stats/source/ru_thailand')).data;
  assert.equal(after.visits, before, 'посещения на месте');
  assert.equal(after.cost, 7000, 'новая стоимость применилась');
  assert.equal(after.cost_per_visitor, Math.round(7000 / after.visitors * 100) / 100, 'цена посетителя пересчитана');
});

test('стоимостные показатели не считаются без стоимости рекламы', async () => {
  await admin('/api/admin/sources', { method: 'POST', body: JSON.stringify({ ref: 'no_cost', title: 'Без цены' }) });
  const user = visitor();
  await user('/api/track', { method: 'POST', body: JSON.stringify({ ref: 'no_cost', event: 'visit', path: '/' }) });

  const detail = (await admin('/api/admin/stats/source/no_cost')).data;
  assert.equal(detail.cost, null);
  assert.equal(detail.cost_per_visitor, null, 'без цены размещения показатель не выводится');
});

test('фильтр по источнику и по периоду сужает сводку', async () => {
  const all = (await admin('/api/admin/stats')).data.summary;
  const one = (await admin('/api/admin/stats?ref=p2p_channel_01')).data.summary;
  assert.ok(one.visits < all.visits, 'по одному каналу посещений меньше, чем по всем');
  assert.equal(one.visits, 2);

  const future = (await admin('/api/admin/stats?from=2099-01-01')).data.summary;
  assert.equal(future.visits, 0, 'в будущем периоде посещений нет');
});

test('моменты переходов отдаются в UTC, без второго сдвига часового пояса', async () => {
  const stats = await admin('/api/admin/stats');
  const row = stats.data.sources.find(s => s.ref === 'ru_thailand');
  const stamp = new Date(row.first_visit.replace(' ', 'T') + 'Z');
  // Записи сделаны только что: расхождение с текущим временем не больше часа
  const diffHours = Math.abs(Date.now() - stamp.getTime()) / 3600000;
  assert.ok(diffHours < 1, `первый переход показан со сдвигом ${diffHours.toFixed(1)} ч`);
});

test('график по дням приходит вместе со сводкой', async () => {
  const stats = await admin('/api/admin/stats');
  assert.ok(Array.isArray(stats.data.daily) && stats.data.daily.length, 'дни для гистограммы должны быть');
  const day = stats.data.daily.at(-1);
  assert.match(day.day, /^\d{4}-\d{2}-\d{2}$/);
  assert.ok(day.visits > 0);
});

test('маркетолог видит статистику и не видит остального', async () => {
  // Администратор выдаёт доступ по почте
  const invited = await admin('/api/admin/staff', {
    method: 'POST', body: JSON.stringify({ email: 'marketer@example.invalid' }),
  });
  assert.equal(invited.status, 200);
  assert.match(invited.data.link, /reset\.html\?token=[a-f0-9]{64}/, 'ссылка для установки пароля создаётся');
  // Почта не настроена, значит письмо не ушло — и отчитываться об отправке нельзя
  assert.equal(invited.data.mailed, false, 'без SMTP сервер не докладывает об отправленном письме');

  // До установки пароля войти нельзя
  const early = visitor();
  const noPassword = await early('/api/login', { method: 'POST', body: JSON.stringify({ email: 'marketer@example.invalid', password: '' }) });
  assert.equal(noPassword.status, 400, 'учётка без пароля не пускает');

  // Маркетолог сам задаёт пароль по ссылке из письма
  const token = invited.data.link.split('token=')[1];
  const own = visitor();
  const password = crypto.randomBytes(12).toString('hex');
  const set = await own('/api/reset-password', { method: 'POST', body: JSON.stringify({ token, password }) });
  assert.equal(set.status, 200, 'пароль устанавливается по ссылке');

  const login = await own('/api/login', { method: 'POST', body: JSON.stringify({ email: 'marketer@example.invalid', password }) });
  assert.equal(login.status, 200);
  assert.equal(login.data.role, 'marketer', 'вход возвращает роль, по ней страница ведёт в кабинет');

  // Статистика открыта
  const stats = await own('/api/admin/stats');
  assert.equal(stats.status, 200);
  assert.ok(stats.data.summary.visits > 0);

  // Всё остальное закрыто
  for (const url of ['/api/admin/orders', '/api/admin/clients', '/api/admin/verifications', '/api/admin/staff']) {
    const res = await own(url);
    assert.equal(res.status, 403, url + ' маркетологу недоступен');
  }
  // И заводить ссылки он тоже не может
  const create = await own('/api/admin/sources', { method: 'POST', body: JSON.stringify({ ref: 'from_marketer', title: 'Не должно создаться' }) });
  assert.equal(create.status, 403);
});

test('доступ маркетолога снимается вместе с сессиями', async () => {
  const { staff } = (await admin('/api/admin/staff')).data;
  const marketer = staff.find(s => s.email === 'marketer@example.invalid');
  assert.ok(marketer, 'маркетолог есть в списке сотрудников');

  const removed = await admin('/api/admin/staff/' + marketer.id, { method: 'DELETE' });
  assert.equal(removed.status, 200);

  const after = (await admin('/api/admin/staff')).data.staff;
  assert.ok(!after.some(s => s.email === 'marketer@example.invalid'), 'роль снята');
});

test('API статистики закрыто от посторонних', async () => {
  // Сервер отвечает 403 «Только для администратора» — как и на остальные админские адреса
  for (const url of ['/api/admin/stats', '/api/admin/stats/source/ru_thailand', '/api/admin/sources']) {
    const res = await fetch(BASE + url, { headers: { 'User-Agent': BROWSER } });
    assert.equal(res.status, 403, url + ' должен требовать вход администратора');
    const body = await res.json().catch(() => ({}));
    assert.ok(!body.sources && !body.summary, 'данные наружу не отдаются');
  }
  const created = await fetch(BASE + '/api/admin/sources', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'User-Agent': BROWSER },
    body: JSON.stringify({ ref: 'hacker', title: 'Чужой' }),
  });
  assert.equal(created.status, 403, 'создать ссылку без входа нельзя');

  // Источник действительно не появился в базе
  const { sources } = (await admin('/api/admin/sources')).data;
  assert.ok(!sources.some(s => s.ref === 'hacker'), 'чужая ссылка не создана');
});

test('дни разложены по каждой ссылке отдельно', async () => {
  // Два канала и прямой заход в один и тот же день
  const first = visitor();
  await first('/api/track', { method: 'POST', body: JSON.stringify({ ref: 'razbivka_a', event: 'visit', path: '/' }) });
  await first('/api/track', { method: 'POST', body: JSON.stringify({ event: 'telegram_click', path: '/' }) });

  const second = visitor();
  await second('/api/track', { method: 'POST', body: JSON.stringify({ ref: 'razbivka_b', event: 'visit', path: '/' }) });

  const { data } = await admin('/api/admin/stats');
  assert.ok(Array.isArray(data.daily_by_ref), 'разбивка по ссылкам приходит с сервера');

  const rowsOf = ref => data.daily_by_ref.filter(row => row.ref === ref);
  const a = rowsOf('razbivka_a');
  const b = rowsOf('razbivka_b');

  assert.equal(a.length, 1, 'у первой ссылки один день');
  assert.equal(a[0].visits, 1);
  assert.equal(a[0].visitors, 1);
  assert.equal(a[0].telegram_clicks, 1, 'переход в Telegram отнесён к своей ссылке');

  assert.equal(b.length, 1, 'у второй ссылки свой день');
  assert.equal(b[0].visits, 1);
  assert.equal(b[0].telegram_clicks, 0, 'чужой переход во вторую ссылку не попал');
});

test('ссылка удаляется вместе со своей статистикой, чужую не трогает', async () => {
  await admin('/api/admin/sources', { method: 'POST', body: JSON.stringify({ ref: 'udalim', title: 'На удаление' }) });
  await admin('/api/admin/sources', { method: 'POST', body: JSON.stringify({ ref: 'ostanem', title: 'Остаётся' }) });

  const doomed = visitor();
  await doomed('/api/track', { method: 'POST', body: JSON.stringify({ ref: 'udalim', event: 'visit', path: '/' }) });
  await doomed('/api/track', { method: 'POST', body: JSON.stringify({ event: 'telegram_click', path: '/' }) });
  const keeper = visitor();
  await keeper('/api/track', { method: 'POST', body: JSON.stringify({ ref: 'ostanem', event: 'visit', path: '/' }) });

  const before = (await admin('/api/admin/stats')).data;
  const target = before.sources.find(s => s.ref === 'udalim');
  assert.ok(target.id, 'у заведённой ссылки есть номер, по которому её удалять');
  assert.equal(target.visits, 1);

  const removed = await admin('/api/admin/sources/' + target.id, { method: 'DELETE' });
  assert.equal(removed.status, 200, removed.data.error);
  assert.equal(removed.data.deleted_visits, 2, 'стёрты и посещение, и переход в Telegram');

  const after = (await admin('/api/admin/stats')).data;
  assert.equal(after.sources.find(s => s.ref === 'udalim'), undefined, 'ссылки в таблице больше нет');
  assert.equal(after.daily_by_ref.filter(r => r.ref === 'udalim').length, 0, 'и в разбивке по дням тоже');

  const kept = after.sources.find(s => s.ref === 'ostanem');
  assert.equal(kept.visits, 1, 'соседняя ссылка осталась нетронутой');

  const gone = await admin('/api/admin/sources/' + target.id, { method: 'DELETE' });
  assert.equal(gone.status, 404, 'повторное удаление отвечает, что источника нет');
});

test('маркетолог удалять ссылки не может', async () => {
  const res = await fetch(BASE + '/api/admin/sources/1', { method: 'DELETE', headers: { 'User-Agent': BROWSER } });
  assert.equal(res.status, 403, 'без прав администратора удаление запрещено');
});
