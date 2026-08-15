// Учёт рекламного трафика: откуда пришёл посетитель и что он сделал.
//
// Правила, из которых всё вытекает:
// • ссылка ведёт на обычную главную, никаких промежуточных редиректов;
// • источник запоминается на 30 дней и переживает переходы по страницам;
// • IP в открытом виде не хранится — только необратимый хеш с солью;
// • обновление страницы — это повторный просмотр, а не новый посетитель.

const crypto = require('crypto');
const { db, getSetting } = require('./db');
const { clientIp } = require('./security');

// Часовой пояс проекта: касса работает в Таиланде, статистика считается по нему
const TZ_SHIFT = process.env.STATS_TZ_SHIFT || '+7 hours';

// Имена и сроки жизни куков
const VISITOR_COOKIE = 'vid';
const REF_COOKIE = 'kref';
const VISITOR_TTL_DAYS = 365;
const REF_TTL_DAYS = 30;

// Два одинаковых события подряд в этом окне считаются одним: так отсекаются
// повторные запросы страницы, а не настоящие действия посетителя
const DEDUPE_SECONDS = 3;

// События, которые умеет записывать сайт
const EVENTS = ['visit', 'exchange_click', 'telegram_click'];

// Признаки автоматических обходчиков в User-Agent
const BOT_PATTERN = /bot|crawler|spider|slurp|curl|wget|python-requests|httpclient|headless|phantom|puppeteer|playwright|monitor|uptime|pingdom|lighthouse|preview|facebookexternalhit|telegrambot|whatsapp|vkshare|yandex\.com\/bots/i;

// Соль для хеша IP: случайная и своя у каждой установки. С общей строкой хеш
// не защищал бы ничего — весь диапазон адресов перебирается за минуты, и адрес
// посетителя восстанавливается по таблице.
function ipSalt() {
  return getSetting('ip_salt') || process.env.UPLOADS_KEY || 'kometa-ip-salt';
}

function hashIp(ip) {
  if (!ip) return '';
  return crypto.createHmac('sha256', ipSalt()).update(String(ip)).digest('hex').slice(0, 32);
}

function isBot(userAgent) {
  const ua = String(userAgent || '');
  // Запрос совсем без User-Agent почти всегда автоматический
  if (!ua.trim()) return true;
  return BOT_PATTERN.test(ua);
}

// Значение ref: только буквы, цифры, дефис и подчёркивание, максимум 64 символа
function cleanRef(value) {
  return String(value || '').trim().toLowerCase().replace(/[^a-z0-9_\-]/g, '').slice(0, 64);
}

function readCookie(req, name) {
  const raw = req.headers.cookie || '';
  const match = raw.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? decodeURIComponent(match[1]) : '';
}

// Куки трекинга дописываются к тем, что уже выставил сервер
function appendCookie(res, req, name, value, days) {
  const secure = req.secure ? ' Secure;' : '';
  const cookie = `${name}=${encodeURIComponent(value)}; Path=/;${secure} SameSite=Lax; Max-Age=${days * 24 * 60 * 60}`;
  const current = res.getHeader('Set-Cookie');
  if (!current) return res.setHeader('Set-Cookie', cookie);
  res.setHeader('Set-Cookie', Array.isArray(current) ? current.concat(cookie) : [current, cookie]);
}

// Запись одного события. Возвращает, что именно записали, — это нужно тестам
// и отладке; наружу отдаётся только признак успеха.
function recordEvent(req, res, { ref, event, path } = {}) {
  const type = EVENTS.includes(event) ? event : 'visit';
  if (isBot(req.headers['user-agent'])) return { recorded: false, reason: 'bot' };

  // Постоянный анонимный идентификатор посетителя
  let visitor = readCookie(req, VISITOR_COOKIE);
  if (!/^[a-f0-9]{32}$/.test(visitor)) {
    visitor = crypto.randomBytes(16).toString('hex');
  }
  appendCookie(res, req, VISITOR_COOKIE, visitor, VISITOR_TTL_DAYS);

  // Источник: новый параметр важнее запомненного, иначе берём из куки
  const fresh = cleanRef(ref);
  const stored = cleanRef(readCookie(req, REF_COOKIE));
  const source = fresh || stored;
  // Источник живёт 30 дней и продлевается при каждом заходе по ссылке
  if (fresh) appendCookie(res, req, REF_COOKIE, fresh, REF_TTL_DAYS);

  // Технический повтор того же события не увеличивает счётчик
  const recent = db.prepare(`
    SELECT id FROM visits
    WHERE visitor = ? AND event = ? AND ifnull(path, '') = ?
      AND created_at > datetime('now', ?)
    LIMIT 1
  `).get(visitor, type, String(path || ''), `-${DEDUPE_SECONDS} seconds`);
  if (recent) return { recorded: false, reason: 'duplicate', visitor, ref: source };

  // Посетитель считается новым, пока о нём нет ни одной записи
  const seen = db.prepare('SELECT 1 FROM visits WHERE visitor = ? LIMIT 1').get(visitor);
  const isNew = seen ? 0 : 1;

  db.prepare(`
    INSERT INTO visits (visitor, ref, event, is_new, path, ip_hash)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(visitor, source, type, isNew, String(path || '').slice(0, 200), hashIp(clientIp(req)));

  return { recorded: true, visitor, ref: source, event: type, is_new: !!isNew };
}

// ---------- Статистика ----------

// Границы периода в локальном времени проекта. Пустые значения означают «за всё время».
function periodWhere(from, to) {
  const clauses = [];
  const params = [];
  if (from) {
    clauses.push(`date(created_at, '${TZ_SHIFT}') >= ?`);
    params.push(from);
  }
  if (to) {
    clauses.push(`date(created_at, '${TZ_SHIFT}') <= ?`);
    params.push(to);
  }
  return { sql: clauses.length ? ' AND ' + clauses.join(' AND ') : '', params };
}

// Сводка по всем источникам за период
function summary({ from = '', to = '', ref = null } = {}) {
  const period = periodWhere(from, to);
  const refClause = ref === null ? '' : ' AND ref = ?';
  const refParams = ref === null ? [] : [cleanRef(ref)];
  const where = `WHERE event = 'visit'${period.sql}${refClause}`;
  const params = [...period.params, ...refParams];

  const row = db.prepare(`
    SELECT
      COUNT(*) AS visits,
      COUNT(DISTINCT visitor) AS visitors,
      SUM(CASE WHEN ref = '' THEN 1 ELSE 0 END) AS direct,
      SUM(CASE WHEN ref != '' THEN 1 ELSE 0 END) AS from_ads
    FROM visits ${where}
  `).get(...params);

  // Периоды считаются от локальной даты, иначе «сегодня» съезжает на семь часов
  const since = days => db.prepare(`
    SELECT COUNT(*) AS visits FROM visits
    WHERE event = 'visit'${refClause}
      AND date(created_at, '${TZ_SHIFT}') >= date('now', '${TZ_SHIFT}', ?)
  `).get(...refParams, `-${days} days`).visits;

  return {
    visits: row.visits || 0,
    visitors: row.visitors || 0,
    direct: row.direct || 0,
    from_ads: row.from_ads || 0,
    today: since(0),
    last7: since(6),
    last30: since(29),
  };
}

// Посещения по дням за период: из этого рисуется гистограмма.
// Дни считаются по местному времени проекта, иначе сутки съезжают.
function dailyVisits({ from = '', to = '', ref = null } = {}) {
  const period = periodWhere(from, to);
  const refClause = ref === null ? '' : ' AND ref = ?';
  const refParams = ref === null ? [] : [cleanRef(ref)];
  return db.prepare(`
    SELECT date(created_at, '${TZ_SHIFT}') AS day,
           SUM(CASE WHEN event = 'visit' THEN 1 ELSE 0 END) AS visits,
           COUNT(DISTINCT CASE WHEN event = 'visit' THEN visitor END) AS visitors,
           SUM(CASE WHEN event = 'telegram_click' THEN 1 ELSE 0 END) AS telegram_clicks
    FROM visits
    WHERE 1 = 1${period.sql}${refClause}
    GROUP BY day ORDER BY day
  `).all(...period.params, ...refParams);
}

// Дни в разрезе каждой ссылки: из этого строится отдельная гистограмма на
// источник. Один запрос на все ссылки сразу — по запросу на каждую было бы
// столько обращений к базе, сколько заведено каналов.
function dailyByRef({ from = '', to = '' } = {}) {
  const period = periodWhere(from, to);
  return db.prepare(`
    SELECT ref,
           date(created_at, '${TZ_SHIFT}') AS day,
           SUM(CASE WHEN event = 'visit' THEN 1 ELSE 0 END) AS visits,
           COUNT(DISTINCT CASE WHEN event = 'visit' THEN visitor END) AS visitors,
           SUM(CASE WHEN event = 'telegram_click' THEN 1 ELSE 0 END) AS telegram_clicks
    FROM visits
    WHERE 1 = 1${period.sql}
    GROUP BY ref, day ORDER BY ref, day
  `).all(...period.params);
}

// Таблица источников: строка на каждый Telegram-канал плюс прямой трафик
function sourceRows({ from = '', to = '' } = {}) {
  const period = periodWhere(from, to);
  const rows = db.prepare(`
    SELECT
      ref,
      COUNT(*) AS visits,
      COUNT(DISTINCT visitor) AS visitors,
      -- Моменты отдаются в UTC: браузер сам переводит их в местное время.
      -- Сдвиг здесь привёл бы ко второму переводу и часам «из будущего».
      MIN(created_at) AS first_visit,
      MAX(created_at) AS last_visit,
      SUM(CASE WHEN date(created_at, '${TZ_SHIFT}') = date('now', '${TZ_SHIFT}') THEN 1 ELSE 0 END) AS today,
      SUM(CASE WHEN date(created_at, '${TZ_SHIFT}') >= date('now', '${TZ_SHIFT}', '-6 days') THEN 1 ELSE 0 END) AS last7,
      SUM(CASE WHEN date(created_at, '${TZ_SHIFT}') >= date('now', '${TZ_SHIFT}', '-29 days') THEN 1 ELSE 0 END) AS last30
    FROM visits
    WHERE event = 'visit'${period.sql}
    GROUP BY ref
  `).all(...period.params);

  // Действия считаются отдельно, чтобы конверсия шла из тех же данных
  const clicks = db.prepare(`
    SELECT ref, event, COUNT(*) AS count, COUNT(DISTINCT visitor) AS visitors
    FROM visits
    WHERE event != 'visit'${period.sql}
    GROUP BY ref, event
  `).all(...period.params);

  const sources = db.prepare('SELECT * FROM ad_sources').all();
  const byRef = new Map(sources.map(source => [source.ref, source]));

  const result = rows.map(row => {
    const source = byRef.get(row.ref);
    const exchange = clicks.find(c => c.ref === row.ref && c.event === 'exchange_click');
    const telegram = clicks.find(c => c.ref === row.ref && c.event === 'telegram_click');
    return {
      ref: row.ref,
      title: row.ref === '' ? 'Прямой трафик' : (source ? source.title : '(ссылка не заведена)'),
      known: !!source || row.ref === '',
      enabled: source ? !!source.enabled : true,
      cost: source ? source.cost : null,
      link: row.ref === '' ? '' : buildLink(row.ref),
      visits: row.visits,
      visitors: row.visitors,
      repeat: row.visits - row.visitors,
      today: row.today,
      last7: row.last7,
      last30: row.last30,
      first_visit: row.first_visit,
      last_visit: row.last_visit,
      exchange_clicks: exchange ? exchange.count : 0,
      telegram_clicks: telegram ? telegram.count : 0,
    };
  });

  // Источники без единого перехода тоже видны: иначе непонятно, работает ли ссылка
  for (const source of sources) {
    if (result.some(row => row.ref === source.ref)) continue;
    result.push({
      ref: source.ref, title: source.title, known: true, enabled: !!source.enabled,
      cost: source.cost, link: buildLink(source.ref),
      visits: 0, visitors: 0, repeat: 0, today: 0, last7: 0, last30: 0,
      first_visit: null, last_visit: null, exchange_clicks: 0, telegram_clicks: 0,
    });
  }

  return result.sort((a, b) => b.visits - a.visits);
}

// Подробная статистика одного источника, включая график по дням
function sourceDetail(ref, { from = '', to = '' } = {}) {
  const value = cleanRef(ref);
  const period = periodWhere(from, to);
  const source = db.prepare('SELECT * FROM ad_sources WHERE ref = ?').get(value) || null;

  const totals = db.prepare(`
    SELECT
      SUM(CASE WHEN event = 'visit' THEN 1 ELSE 0 END) AS visits,
      COUNT(DISTINCT CASE WHEN event = 'visit' THEN visitor END) AS visitors,
      SUM(CASE WHEN event = 'exchange_click' THEN 1 ELSE 0 END) AS exchange_clicks,
      SUM(CASE WHEN event = 'telegram_click' THEN 1 ELSE 0 END) AS telegram_clicks,
      COUNT(DISTINCT CASE WHEN event = 'telegram_click' THEN visitor END) AS telegram_visitors
    FROM visits
    WHERE ref = ?${period.sql}
  `).get(value, ...period.params);

  const daily = db.prepare(`
    SELECT date(created_at, '${TZ_SHIFT}') AS day,
           SUM(CASE WHEN event = 'visit' THEN 1 ELSE 0 END) AS visits,
           COUNT(DISTINCT CASE WHEN event = 'visit' THEN visitor END) AS visitors,
           SUM(CASE WHEN event = 'telegram_click' THEN 1 ELSE 0 END) AS telegram_clicks
    FROM visits
    WHERE ref = ?${period.sql}
    GROUP BY day ORDER BY day
  `).all(value, ...period.params);

  const visits = totals.visits || 0;
  const visitors = totals.visitors || 0;
  const telegramClicks = totals.telegram_clicks || 0;
  const cost = source && source.cost != null ? Number(source.cost) : null;

  return {
    ref: value,
    title: source ? source.title : (value === '' ? 'Прямой трафик' : '(ссылка не заведена)'),
    source,
    link: value ? buildLink(value) : '',
    visits,
    visitors,
    repeat: visits - visitors,
    exchange_clicks: totals.exchange_clicks || 0,
    telegram_clicks: telegramClicks,
    // Проценты считаются от уникальных посетителей: так понятнее, чем от показов
    exchange_rate: visitors ? Math.round((totals.exchange_clicks || 0) / visitors * 1000) / 10 : 0,
    telegram_rate: visitors ? Math.round((totals.telegram_visitors || 0) / visitors * 1000) / 10 : 0,
    cost,
    // Стоимостные показатели считаются только когда цена размещения известна
    cost_per_visitor: cost != null && visitors ? Math.round(cost / visitors * 100) / 100 : null,
    cost_per_telegram: cost != null && telegramClicks ? Math.round(cost / telegramClicks * 100) / 100 : null,
    daily,
  };
}

// Готовая рекламная ссылка для канала
function buildLink(ref) {
  const base = (getSetting('site_url') || 'https://kometa.exchange').replace(/\/+$/, '');
  return `${base}/?ref=${encodeURIComponent(ref)}`;
}

module.exports = {
  dailyByRef,
  recordEvent, summary, sourceRows, sourceDetail, dailyVisits, buildLink,
  cleanRef, isBot, hashIp,
  VISITOR_COOKIE, REF_COOKIE, EVENTS, TZ_SHIFT,
};
