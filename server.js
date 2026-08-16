const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const express = require('express');
const { db, getSetting, setSetting, restoreDefaultDirections } = require('./db');
const { refreshRates, startAutoRefresh, directionRate, directionChannels, directionMargin, ratesInfo, applyPushedBoard } = require('./rates');
const { sendMail, isConfigured: mailConfigured, diagnose: mailDiagnose } = require('./mailer');
const { encryptBuffer, decryptBuffer, sealData, verifySeal, hashBuffer } = require('./secure-store');
const { notifyAdmin, notifyAdminSafe, detectChatId, isConfigured: tgConfigured } = require('./notifier');
const agent = require('./agent');
const { buildClientRecap } = require('./order-recap');
const tracking = require('./tracking');
const googleAuth = require('./google-auth');
const { clientIp, rateLimit, reset: resetLimit, hashPassword, hashPasswordSync, verifyPassword, TooBusyError } = require('./security');

const PORT = process.env.PORT || 3210;
const app = express();
// За nginx: доверяем X-Forwarded-*, иначе req.secure и ссылки в письмах будут http
app.set('trust proxy', 1);
// Версия сервера наружу не сообщается: подсказывать, чем ломать, незачем
app.disable('x-powered-by');

// Разбор тела запроса. Двадцать пять мегабайт нужны ровно двум адресам, где
// приходят картинки в base64. Всем остальным столько незачем, а открытый на
// весь сайт лимит — это готовый способ занять память сервера пустыми запросами.
const HEAVY_BODY_ROUTES = new Set(['/api/verification', '/api/orders']);
const heavyJson = express.json({ limit: '25mb' });
const lightJson = express.json({ limit: '200kb' });
app.use((req, res, next) => (HEAVY_BODY_ROUTES.has(req.path) ? heavyJson : lightJson)(req, res, next));

// Заголовки безопасности. Главное здесь — запрет чужих скриптов и кадров:
// подменить то, что оператор видит на странице, можно только чужим кодом.
app.use((req, res, next) => {
  // По HTTPS браузеру говорим больше сюда не ходить открытым текстом:
  // иначе остаётся окно на первом заходе, когда адрес набран без https.
  if (req.secure) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    // Свои страницы держат скрипты и стили внутри разметки
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    // Запросы уходят только на свой домен: увести данные некуда
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; '));
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// Папку вложений можно переопределить, как и файл базы: иначе тесты, которые
// проверяют загрузку документов, сыплют свои картинки в боевое хранилище.
const uploadsDir = process.env.UPLOADS_DIR || path.join(__dirname, 'data', 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

// Адрес сайта для ссылок в письмах и уведомлениях. Берётся из настройки, а не
// из заголовка запроса: заголовок присылает клиент, и подменив его, можно было
// увести ссылку сброса пароля на чужой домен вместе с рабочим токеном.
function publicBase(req) {
  const configured = (process.env.PUBLIC_URL || '').trim().replace(/\/+$/, '');
  if (/^https?:\/\/\S+$/.test(configured)) return configured;
  return `${req.protocol}://${req.get('host')}`;
}

// ---------- Пароли и сессии ----------

// Сколько сессия живёт без обращений. Каждый заход продлевает срок, поэтому
// тот, кто пользуется кабинетом, не разлогинивается; забытая на чужом
// компьютере кука сама перестаёт работать через месяц.
const SESSION_TTL_DAYS = 30;

// Продлевать чаще раза в час незачем: это была бы запись в базу на каждый запрос
const SESSION_RENEW_AFTER_MS = 60 * 60 * 1000;

function sessionCookieToken(req) {
  const match = (req.headers.cookie || '').match(/(?:^|;\s*)sid=([a-f0-9]{64})/);
  return match ? match[1] : null;
}

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare(`INSERT INTO sessions (token, user_id, expires_at, used_at)
    VALUES (?, ?, datetime('now', '+${SESSION_TTL_DAYS} days'), datetime('now'))`).run(token, userId);
  return token;
}

function getSessionUser(req) {
  const token = sessionCookieToken(req);
  if (!token) return null;
  const row = db.prepare(`
    SELECT u.id, u.email, u.name, u.is_admin, u.role, u.verify_status, u.blocked, s.used_at FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token = ? AND s.expires_at > datetime('now')
  `).get(token);
  if (!row) return null;
  // Сессия живая — отодвигаем срок. Раз в час, а не на каждом запросе.
  const usedAt = row.used_at ? Date.parse(row.used_at.replace(' ', 'T') + 'Z') : 0;
  if (!usedAt || Date.now() - usedAt > SESSION_RENEW_AFTER_MS) {
    db.prepare(`UPDATE sessions SET used_at = datetime('now'),
      expires_at = datetime('now', '+${SESSION_TTL_DAYS} days') WHERE token = ?`).run(token);
  }
  const { used_at, ...user } = row;
  return user;
}

// Просроченные сессии убираются с диска: раз в сутки и при запуске
function sweepSessions() {
  const gone = db.prepare("DELETE FROM sessions WHERE expires_at <= datetime('now')").run().changes;
  if (gone) console.log(`[sessions] просроченных сессий удалено: ${gone}`);
}

function requireAuth(req, res, next) {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Требуется вход' });
  // Отдельный ответ вместо «войдите заново»: человек должен понимать, что
  // дело не в сессии и повторный вход ничего не изменит
  if (user.blocked) return res.status(403).json({ error: 'Доступ к кабинету закрыт. Напишите нам в Telegram.' });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  const user = getSessionUser(req);
  if (!user || !user.is_admin) return res.status(403).json({ error: 'Только для администратора' });
  req.user = user;
  next();
}

// Рекламный экран целиком — общий для администратора и маркетолога: смотреть
// цифры и заводить ссылки должен тот, кто размещает рекламу, иначе за каждой
// новой ссылкой ему приходится идти к владельцу.
//
// Граница проходит по экрану, а не по действиям внутри него: заявки, клиенты,
// верификации и переписка маркетологу по-прежнему закрыты.
function requireStats(req, res, next) {
  const user = getSessionUser(req);
  if (!user || (!user.is_admin && user.role !== 'marketer')) {
    return res.status(403).json({ error: 'Доступ только для администратора и маркетолога' });
  }
  req.user = user;
  next();
}

function setSidCookie(req, res, token) {
  // Флаг Secure только на HTTPS, иначе куки не работали бы на локальном http
  const secure = req.secure ? ' Secure;' : '';
  res.setHeader('Set-Cookie',
    `sid=${token}; HttpOnly;${secure} SameSite=Lax; Path=/; Max-Age=${60 * 60 * 24 * 30}`);
}

// Создание администратора при первом запуске
(function seedAdmin() {
  const exists = db.prepare('SELECT id FROM users WHERE is_admin = 1').get();
  if (exists) return;
  const email = process.env.ADMIN_EMAIL || 'admin@obmen.local';
  // Пароль по умолчанию годится только там, где сервер никому не виден.
  // На боевом сервере он задаётся переменной окружения, иначе учётка
  // администратора открыта всем, кто читал этот файл.
  const fallback = crypto.randomBytes(12).toString('base64url');
  const password = process.env.ADMIN_PASSWORD || fallback;
  const salt = crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO users (email, name, pass_hash, pass_salt, is_admin) VALUES (?, ?, ?, ?, 1)')
    .run(email, 'Администратор', hashPasswordSync(password, salt), salt);
  // Сам пароль в лог не пишется: логи сервера живут долго и видны не только
  // владельцу. Случайный показывается один раз — задать свой можно в админке.
  if (process.env.ADMIN_PASSWORD) {
    console.log(`[init] создан администратор ${email}, пароль из ADMIN_PASSWORD`);
  } else {
    console.log(`[init] создан администратор ${email}, временный пароль: ${password}`);
    console.log('[init] ADMIN_PASSWORD не задан — смените пароль в админке сразу после входа');
  }
})();

// ---------- Аутентификация ----------

const MINUTE = 60 * 1000;
const bodyEmail = req => String(req.body?.email || '').toLowerCase().trim();

// Подбор пароля ограничивается с двух сторон: по адресу, откуда стучат, и по
// учётке, в которую стучат. Первое отсекает перебор паролей к одной почте,
// второе — перебор почт с одного места.
const limitLoginByIp = rateLimit({
  name: 'login-ip', limit: 20, windowMs: 15 * MINUTE,
  message: 'Слишком много попыток входа. Подождите 15 минут.',
});
const limitLoginByEmail = rateLimit({
  name: 'login-email', limit: 10, windowMs: 15 * MINUTE, by: bodyEmail,
  message: 'Слишком много попыток входа в эту учётную запись. Подождите 15 минут.',
});

// Регистрация — вход на сайт для чужого человека, и она же способ занять диск:
// каждый аккаунт может загрузить документы верификации.
const limitRegister = rateLimit({
  name: 'register', limit: 5, windowMs: 60 * MINUTE,
  message: 'Слишком много регистраций с этого адреса. Попробуйте через час.',
});

// Восстановление пароля шлёт письмо и считает хеш — и то и другое чужими руками
const limitForgot = rateLimit({ name: 'forgot-ip', limit: 10, windowMs: 60 * MINUTE });
const limitReset = rateLimit({ name: 'reset-ip', limit: 20, windowMs: 60 * MINUTE });

// Ответ на переполненную очередь проверок пароля: сервер не отказывает
// насовсем, а просит повторить, — так поток запросов не роняет сайт целиком.
function handleAuthError(res, error) {
  if (error instanceof TooBusyError) return res.status(503).json({ error: error.message });
  throw error;
}

app.post('/api/register', limitRegister, async (req, res) => {
  const { email, password, name } = req.body || {};
  if (!email || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Укажите корректный email' });
  if (!password || password.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });
  const salt = crypto.randomBytes(16).toString('hex');
  try {
    const hash = await hashPassword(password, salt);
    const info = db.prepare('INSERT INTO users (email, name, pass_hash, pass_salt) VALUES (?, ?, ?, ?)')
      .run(email.toLowerCase().trim(), (name || '').trim(), hash, salt);
    setSidCookie(req, res, createSession(info.lastInsertRowid));
    res.json({ ok: true });
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) return res.status(400).json({ error: 'Такой email уже зарегистрирован' });
    handleAuthError(res, e);
  }
});

app.post('/api/login', limitLoginByIp, limitLoginByEmail, async (req, res) => {
  const { email, password } = req.body || {};
  const address = bodyEmail(req);
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(address);
  try {
    // Пустой pass_hash — у аккаунта, заведённого через Google: паролем в него не войти
    const ok = user && user.pass_hash && await verifyPassword(String(password || ''), user.pass_salt, user.pass_hash);
    if (!ok) return res.status(400).json({ error: 'Неверный email или пароль' });
    if (user.blocked) return res.status(403).json({ error: 'Доступ к кабинету закрыт. Напишите нам в Telegram.' });
    // Пароль подошёл — накопленные попытки больше ничего не значат
    resetLimit(`login-ip:${clientIp(req)}`);
    resetLimit(`login-email:${address}`);
    setSidCookie(req, res, createSession(user.id));
    // Роль нужна странице входа: маркетолога она ведёт в кабинет статистики
    res.json({ ok: true, is_admin: !!user.is_admin, role: user.role || '' });
  } catch (e) {
    handleAuthError(res, e);
  }
});

app.post('/api/logout', (req, res) => {
  const token = sessionCookieToken(req);
  if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0');
  res.json({ ok: true });
});

// Выход со всех устройств. Нужен ровно тогда, когда есть подозрение, что кука
// утекла: сменить пароль мало, если чужая сессия уже открыта.
app.post('/api/logout-everywhere', requireAuth, (req, res) => {
  const gone = db.prepare('DELETE FROM sessions WHERE user_id = ?').run(req.user.id).changes;
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0');
  res.json({ ok: true, closed: gone });
});

app.get('/api/me', (req, res) => {
  const user = getSessionUser(req);
  res.json({ user });
});

// ---------- Учёт рекламного трафика ----------

// Сайт сам сообщает о посещении и о нажатиях. Открытый эндпоинт: он только
// пишет обезличенную строку и ничего не отдаёт наружу. Защита от повторов
// внутри опирается на куку посетителя, а её можно и не присылать — поэтому
// счёт по адресу здесь тоже нужен, иначе строками забивается диск.
const limitTrack = rateLimit({ name: 'track', limit: 120, windowMs: 60 * 1000 });

app.post('/api/track', limitTrack, (req, res) => {
  const { ref, event, path: page } = req.body || {};
  try {
    const result = tracking.recordEvent(req, res, { ref, event, path: page });
    res.json({ ok: true, recorded: result.recorded });
  } catch (e) {
    // Счётчик никогда не должен ломать страницу клиенту
    console.error('[track] не записано:', e.message);
    res.json({ ok: false });
  }
});

app.get('/api/admin/stats', requireStats, (req, res) => {
  const { from = '', to = '', ref } = req.query || {};
  const filter = ref === undefined ? null : ref;
  res.json({
    summary: tracking.summary({ from, to, ref: filter }),
    sources: tracking.sourceRows({ from, to }),
    daily: tracking.dailyVisits({ from, to, ref: filter }),
    // Те же дни, но разложенные по рекламным ссылкам: на каждую свой график
    daily_by_ref: tracking.dailyByRef({ from, to }),
    timezone: tracking.TZ_SHIFT,
    role: req.user.is_admin ? 'admin' : req.user.role,
  });
});

app.get('/api/admin/stats/source/:ref', requireStats, (req, res) => {
  const { from = '', to = '' } = req.query || {};
  res.json(tracking.sourceDetail(req.params.ref === 'direct' ? '' : req.params.ref, { from, to }));
});

app.get('/api/admin/sources', requireStats, (req, res) => {
  res.json({ sources: db.prepare('SELECT * FROM ad_sources ORDER BY id DESC').all() });
});

app.post('/api/admin/sources', requireStats, (req, res) => {
  const b = req.body || {};
  const ref = tracking.cleanRef(b.ref);
  const title = String(b.title || '').trim();
  if (!ref) return res.status(400).json({ error: 'Укажите ref: латиница, цифры, дефис и подчёркивание' });
  if (!title) return res.status(400).json({ error: 'Укажите название Telegram-канала' });
  if (db.prepare('SELECT id FROM ad_sources WHERE ref = ?').get(ref)) {
    return res.status(400).json({ error: 'Источник с таким ref уже есть' });
  }
  const cost = b.cost === '' || b.cost == null ? null : Number(b.cost);
  if (cost != null && !Number.isFinite(cost)) return res.status(400).json({ error: 'Стоимость должна быть числом' });
  const info = db.prepare(`INSERT INTO ad_sources (ref, title, comment, cost, placed_on)
    VALUES (?, ?, ?, ?, ?)`).run(ref, title, String(b.comment || '').trim(), cost, String(b.placed_on || '').trim() || null);
  res.json({ ok: true, id: info.lastInsertRowid, ref, link: tracking.buildLink(ref) });
});

app.patch('/api/admin/sources/:id', requireStats, (req, res) => {
  const b = req.body || {};
  const source = db.prepare('SELECT * FROM ad_sources WHERE id = ?').get(Number(req.params.id));
  if (!source) return res.status(404).json({ error: 'Источник не найден' });
  // ref не меняется: иначе накопленная статистика повиснет на старом значении
  const title = b.title === undefined ? source.title : String(b.title).trim() || source.title;
  const comment = b.comment === undefined ? source.comment : String(b.comment).trim();
  const cost = b.cost === undefined ? source.cost : (b.cost === '' || b.cost === null ? null : Number(b.cost));
  if (cost != null && !Number.isFinite(cost)) return res.status(400).json({ error: 'Стоимость должна быть числом' });
  const placed = b.placed_on === undefined ? source.placed_on : (String(b.placed_on).trim() || null);
  const enabled = b.enabled === undefined ? source.enabled : (b.enabled ? 1 : 0);
  db.prepare(`UPDATE ad_sources SET title = ?, comment = ?, cost = ?, placed_on = ?, enabled = ? WHERE id = ?`)
    .run(title, comment, cost, placed, enabled, source.id);
  res.json({ ok: true });
});

// Удаление метки вместе с накопленной по ней статистикой.
//
// Работает по самой метке, а не по номеру заведённой ссылки, потому что метка
// в таблице появляется и без всякой ссылки: параметр ref может дописать кто
// угодно, да и запомненная в браузере метка продолжает приходить после того,
// как ссылку удалили. Такие строки тоже надо чем-то убирать.
//
// Записи стираются вместе со ссылкой, а не остаются сиротами: иначе метка так
// и продолжала бы висеть отдельной строкой, только уже без названия.
app.delete('/api/admin/sources/:ref', requireStats, (req, res) => {
  const ref = tracking.cleanRef(req.params.ref);
  if (!ref) return res.status(400).json({ error: 'Прямой трафик удалить нельзя — это все заходы без метки' });

  const source = db.prepare('SELECT * FROM ad_sources WHERE ref = ?').get(ref) || null;
  const seen = db.prepare('SELECT COUNT(*) AS c FROM visits WHERE ref = ?').get(ref).c;
  if (!source && !seen) return res.status(404).json({ error: 'Такой метки нет' });

  const remove = db.transaction(() => {
    const visits = db.prepare('DELETE FROM visits WHERE ref = ?').run(ref).changes;
    if (source) db.prepare('DELETE FROM ad_sources WHERE id = ?').run(source.id);
    return visits;
  });
  const deleted = remove();
  console.log(`[stats] удалена метка ${ref}, записей стёрто: ${deleted}`);
  res.json({ ok: true, ref, title: source ? source.title : null, deleted_visits: deleted });
});

// ---------- Вход через Google ----------

// Куда отправить человека после входа, в зависимости от его роли
function homeFor(user, next = '/') {
  if (user.is_admin) return '/admin.html';
  if (user.role === 'marketer') return '/marketing.html';
  return next && next.startsWith('/') ? next : '/';
}

app.get('/api/auth/google', (req, res) => {
  const url = googleAuth.authorizeUrl(req, res, String(req.query.next || '/'));
  if (!url) return res.status(503).send('Вход через Google не настроен');
  res.redirect(url);
});

app.get('/api/auth/google/callback', async (req, res) => {
  const fail = message => {
    googleAuth.clearState(req, res);
    console.error('[google] вход не удался:', message);
    res.redirect('/auth.html?google_error=1');
  };
  const saved = googleAuth.readState(req, String(req.query.state || ''));
  // Ответ без совпадающего состояния — не наш: возможно, подделка
  if (!saved) return fail('состояние не совпало');
  if (!req.query.code) return fail('Google не вернул код');

  try {
    const profile = await googleAuth.exchangeCode(req, String(req.query.code));
    let user = db.prepare('SELECT id, email, name, is_admin, role FROM users WHERE email = ?').get(profile.email);
    if (!user) {
      // Новый человек заводится обычным клиентом, без пароля: он входит через Google
      const salt = crypto.randomBytes(16).toString('hex');
      const info = db.prepare(`INSERT INTO users (email, name, pass_hash, pass_salt) VALUES (?, ?, '', ?)`)
        .run(profile.email, profile.name, salt);
      user = { id: info.lastInsertRowid, email: profile.email, is_admin: 0, role: '' };
    } else if (!user.name && profile.name) {
      db.prepare('UPDATE users SET name = ? WHERE id = ?').run(profile.name, user.id);
    }
    googleAuth.clearState(req, res);
    setSidCookie(req, res, createSession(user.id));
    res.redirect(homeFor(user, saved.next));
  } catch (e) {
    fail(e.message);
  }
});

// ---------- Сотрудники: маркетолог ----------

// Приглашение действует неделю: человек ставит пароль сам, когда ему удобно
const INVITE_TTL_MIN = 7 * 24 * 60;

// Ссылка, по которой сотрудник задаёт себе пароль. Пароль придумывает он сам,
// администратор его не видит и не передаёт.
async function inviteToSetPassword(req, user, purpose) {
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare(`INSERT INTO password_resets (token, user_id, expires_at)
    VALUES (?, ?, datetime('now', '+${INVITE_TTL_MIN} minutes'))`).run(token, user.id);
  const link = `${publicBase(req)}/reset.html?token=${token}`;
  // Сама ссылка в лог не пишется: по ней входят в учётную запись, а логи
  // сервера хранятся долго. Администратор видит её в ответе, в админке.
  console.log(`[invite] ${purpose} для ${user.email}`);
  let mailed = false;
  try {
    // Ненастроенная почта не бросает ошибку, а честно отвечает sent: false —
    // администратор должен увидеть ссылку, а не рапорт об отправке
    const result = await sendMail({
      to: user.email,
      subject: `Доступ к статистике — ${getSetting('site_name')}`,
      text: `Вам открыт доступ к статистике сайта ${getSetting('site_name')}.\n`
        + `Задайте пароль по ссылке (действует 7 дней): ${link}\n`
        + `Логин — этот адрес почты.`,
      html: `<p>Вам открыт доступ к статистике сайта <b>${getSetting('site_name')}</b>.</p>
        <p><a href="${link}">Задать пароль</a> — ссылка действует 7 дней.</p>
        <p>Логин — этот адрес почты.</p>`,
    });
    mailed = result.sent === true;
  } catch (e) {
    console.error('[invite] письмо не ушло:', e.message);
  }
  return { link, mailed };
}

app.get('/api/admin/staff', requireAdmin, (req, res) => {
  const staff = db.prepare(`SELECT id, email, name, role, created_at,
    (pass_hash = '') AS password_pending FROM users WHERE role != '' ORDER BY id`).all();
  res.json({ staff, mail_configured: mailConfigured() });
});

app.post('/api/admin/staff', requireAdmin, async (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Укажите корректный email' });

  let user = db.prepare('SELECT id, email, is_admin, role FROM users WHERE email = ?').get(email);
  if (user && user.is_admin) return res.status(400).json({ error: 'Это администратор, роль менять не нужно' });
  if (!user) {
    // Учётка заводится без рабочего пароля: его задаст сам сотрудник по ссылке
    const salt = crypto.randomBytes(16).toString('hex');
    const info = db.prepare(`INSERT INTO users (email, name, pass_hash, pass_salt, role)
      VALUES (?, '', '', ?, 'marketer')`).run(email, salt);
    user = { id: info.lastInsertRowid, email };
  } else {
    db.prepare("UPDATE users SET role = 'marketer' WHERE id = ?").run(user.id);
  }
  const invite = await inviteToSetPassword(req, user, 'Приглашение маркетолога');
  res.json({ ok: true, email, mailed: invite.mailed, link: invite.link });
});

app.post('/api/admin/staff/:id/invite', requireAdmin, async (req, res) => {
  const user = db.prepare("SELECT id, email FROM users WHERE id = ? AND role != ''").get(Number(req.params.id));
  if (!user) return res.status(404).json({ error: 'Сотрудник не найден' });
  const invite = await inviteToSetPassword(req, user, 'Повторное приглашение');
  res.json({ ok: true, mailed: invite.mailed, link: invite.link });
});

app.delete('/api/admin/staff/:id', requireAdmin, (req, res) => {
  const user = db.prepare("SELECT id FROM users WHERE id = ? AND role != ''").get(Number(req.params.id));
  if (!user) return res.status(404).json({ error: 'Сотрудник не найден' });
  // Роль снимается, учётка и её данные остаются на месте
  db.prepare("UPDATE users SET role = '' WHERE id = ?").run(user.id);
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id);
  res.json({ ok: true });
});

// ---------- Восстановление пароля ----------

const RESET_TTL_MIN = 60;

// Одна ссылка на адрес в минуту. Счёт ведёт общий механизм ограничений: он сам
// подчищает за собой, а прежняя карта в памяти росла от каждого запроса.
const limitForgotByEmail = rateLimit({
  name: 'forgot-email', limit: 1, windowMs: 60 * 1000, by: bodyEmail,
  message: 'Ссылка уже запрошена — проверьте почту или подождите минуту',
});

app.post('/api/forgot-password', limitForgot, limitForgotByEmail, async (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  if (!email) return res.status(400).json({ error: 'Укажите email' });

  const user = db.prepare('SELECT id, email FROM users WHERE email = ?').get(email);
  // Ответ всегда одинаковый, чтобы нельзя было проверить, зарегистрирован ли email
  const reply = { ok: true, message: 'Если такой email зарегистрирован, на него отправлена ссылка для сброса пароля' };
  if (!user) return res.json(reply);

  const token = crypto.randomBytes(32).toString('hex');
  db.prepare(`INSERT INTO password_resets (token, user_id, expires_at)
    VALUES (?, ?, datetime('now', '+${RESET_TTL_MIN} minutes'))`).run(token, user.id);

  const link = `${publicBase(req)}/reset.html?token=${token}`;
  // Ссылка сброса в лог не попадает: она равносильна паролю в течение часа
  console.log(`[reset] запрошен сброс пароля: ${user.email}`);
  try {
    await sendMail({
      to: user.email,
      subject: `Сброс пароля — ${getSetting('site_name')}`,
      text: `Вы запросили сброс пароля. Перейдите по ссылке (действует ${RESET_TTL_MIN} минут): ${link}\n\nЕсли это были не вы — просто проигнорируйте письмо.`,
      html: `<p>Вы запросили сброс пароля на сайте <b>${getSetting('site_name')}</b>.</p>
        <p><a href="${link}">Задать новый пароль</a> (ссылка действует ${RESET_TTL_MIN} минут).</p>
        <p>Если это были не вы — просто проигнорируйте письмо.</p>`,
    });
  } catch (e) {
    console.error('[reset] Ошибка отправки письма:', e.message);
    return res.status(502).json({ error: 'Не удалось отправить письмо. Свяжитесь с нами в Telegram.' });
  }
  res.json(reply);
});

app.get('/api/reset-password/:token', (req, res) => {
  const row = db.prepare(`SELECT user_id FROM password_resets
    WHERE token = ? AND used = 0 AND expires_at > datetime('now')`).get(req.params.token);
  res.json({ valid: !!row });
});

app.post('/api/reset-password', limitReset, async (req, res) => {
  const { token, password } = req.body || {};
  const row = db.prepare(`SELECT token, user_id FROM password_resets
    WHERE token = ? AND used = 0 AND expires_at > datetime('now')`).get(String(token || ''));
  if (!row) return res.status(400).json({ error: 'Ссылка недействительна или устарела. Запросите новую.' });
  if (!password || password.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });

  const salt = crypto.randomBytes(16).toString('hex');
  try {
    const hash = await hashPassword(password, salt);
    db.prepare('UPDATE users SET pass_hash = ?, pass_salt = ? WHERE id = ?').run(hash, salt, row.user_id);
    db.prepare('UPDATE password_resets SET used = 1 WHERE token = ?').run(row.token);
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(row.user_id); // разлогинить все устройства
    // Остальные выданные ссылки гасим: восстановление уже состоялось
    db.prepare('UPDATE password_resets SET used = 1 WHERE user_id = ? AND used = 0').run(row.user_id);
    res.json({ ok: true });
  } catch (e) {
    handleAuthError(res, e);
  }
});

// ---------- Публичные данные ----------

// Лёгкая версия для шапки: название и Telegram без списка направлений
app.get('/api/site', (req, res) => {
  res.json({
    site_name: getSetting('site_name'),
    telegram: getSetting('telegram_username'),
    // Кнопка входа через Google показывается только когда ключи заведены
    google_auth: googleAuth.isConfigured(),
  });
});

app.get('/api/public', (req, res) => {
  const dirs = db.prepare('SELECT * FROM directions WHERE enabled = 1 ORDER BY sort, id').all();
  const directions = dirs.map(d => {
    const { rate, source, at } = directionRate(d);
    // Цены по каналам оплаты: у QR, Т-Банка и любого банка они разные,
    // а через QR тезер не купить вовсе — такого канала там просто нет.
    const byChannel = directionChannels(d);
    return {
      id: d.id, from_cur: d.from_cur, to_cur: d.to_cur, label: d.label,
      payment_note: d.payment_note, min_from: d.min_from,
      // Восемь знаков: обратный курс должен разворачиваться в ту же цену
      rate: rate != null ? Number(rate.toFixed(8)) : null,
      // Направление без цены не «сломано», а считается по запросу
      on_request: source === 'on_request',
      // Когда оператор подтвердил именно этот курс
      rate_at: at || null,
      channel_rates: byChannel
        ? Object.fromEntries(Object.entries(byChannel).map(([key, value]) => [key, Number(value.rate.toFixed(8))]))
        : null,
    };
  });
  res.json({
    directions,
    // Способы отправки рублей и их условия, чтобы сайт писал то же, что оператор
    payment_channels: Object.entries(PAYMENT_CHANNELS).map(([key, value]) => ({
      key,
      label: value.label,
      requires_verification: value.requires_verification,
      min_rub: value.min_rub,
      note: value.note || '',
    })),
    // Способы выдачи, чтобы форма спрашивала ровно то, что нужно оператору
    payout_types: Object.entries(PAYOUT_TYPES).map(([key, label]) => ({ key, label })),
    rates: ratesInfo(),
    site_name: getSetting('site_name'),
    telegram: getSetting('telegram_username'),
  });
});

// ---------- Заявки пользователя ----------

const STATUSES = ['new', 'processing', 'awaiting_payment', 'done', 'cancelled'];

// Способы, которыми клиент присылает рубли. Оплата по QR идёт через подрядчика,
// который принимает деньги только от проверенного отправителя, поэтому без
// верификации такая заявка не создаётся.
const PAYMENT_CHANNELS = {
  qr: { label: 'QR', requires_verification: true, min_rub: 0, note: 'Нужна верификация: паспорт и фото лица' },
  tbank: { label: 'Отправка с Вашего Т-Банк по СБП', requires_verification: false, min_rub: 30000, note: 'Квитанция на почту от имени банка, реквизиты 5–20 минут' },
  bank: { label: 'Отправка с любого Вашего банка по СБП', requires_verification: false, min_rub: 20000, note: 'Проверка получения может занять некоторое время' },
};

// Поля заявки, которые после создания меняться не должны. Статус и комментарий
// оператора сюда не входят: они по смыслу меняются в ходе работы.
const SEALED_ORDER_FIELDS = [
  'id', 'user_id', 'direction_id', 'amount_from', 'amount_to', 'rate',
  'contact', 'requisites', 'comment', 'payment_channel', 'payout_type',
  'recipient_name', 'recipient_bank', 'recipient_account',
  'delivery_address', 'delivery_geo', 'attachment', 'attachment_hash', 'created_at',
];

// Одно и то же представление заявки для подписи и для проверки
function orderFingerprint(order) {
  return JSON.stringify(SEALED_ORDER_FIELDS.map(field => order[field] ?? null));
}

// Печать ставится один раз, сразу после создания заявки
function sealOrder(orderId) {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
  if (!order) return;
  db.prepare('UPDATE orders SET seal = ? WHERE id = ?').run(sealData(orderFingerprint(order)), orderId);
}

// Возвращает состояние заявки: печать цела, нарушена или её ещё нет
function orderIntegrity(order) {
  if (!order.seal) return 'unsealed';
  return verifySeal(orderFingerprint(order), order.seal) ? 'ok' : 'broken';
}

// Как клиент получает деньги. Поля под каждый способ необязательные:
// чего-то может не быть на руках, остальное оператор уточнит в чате.
const PAYOUT_TYPES = {
  transfer: 'Перевод',
  delivery: 'Доставка',
  atm: 'Банкомат',
};

// Заявка уходит уведомлением в Telegram, поэтому поток заявок с одной учётки —
// это ещё и поток сообщений оператору. Живому клиенту двадцати в час хватает.
const limitOrders = rateLimit({
  name: 'orders', limit: 20, windowMs: 60 * MINUTE, by: req => req.user?.id ?? '',
  message: 'Слишком много заявок подряд. Напишите нам в Telegram — оператор поможет.',
});

app.post('/api/orders', requireAuth, limitOrders, (req, res) => {
  const { direction_id, amount_from, contact, requisites, comment, payment_channel } = req.body || {};
  const b = req.body || {};
  const dir = db.prepare('SELECT * FROM directions WHERE id = ? AND enabled = 1').get(Number(direction_id));
  if (!dir) return res.status(400).json({ error: 'Направление не найдено' });

  // Способ отправки спрашивается только там, где клиент платит рублями
  let channel = '';
  if (dir.from_cur === 'RUB') {
    channel = String(payment_channel || '').trim();
    const rules = PAYMENT_CHANNELS[channel];
    if (!rules) return res.status(400).json({ error: 'Выберите способ отправки рублей' });
    // Не каждый способ подходит каждому направлению: через QR подрядчик
    // выдаёт только баты, тезер этим путём не купить.
    const byChannel = directionChannels(dir);
    if (byChannel && !byChannel[channel]) {
      return res.status(400).json({ error: `${rules.label}: этот способ по выбранному направлению недоступен` });
    }
    if (rules.requires_verification) {
      const u = db.prepare('SELECT verify_status FROM users WHERE id = ?').get(req.user.id);
      if (u.verify_status !== 'approved') {
        return res.status(403).json({
          error: 'Для обмена через QR верификация обязательна. Пройдите её в личном кабинете или выберите другой способ отправки рублей.',
          need_verification: true,
        });
      }
    }
    if (rules.min_rub && Number(amount_from) < rules.min_rub) {
      return res.status(400).json({ error: `${rules.label}: минимальная сумма ${rules.min_rub} RUB` });
    }
  }
  const amount = Number(amount_from);
  if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'Некорректная сумма' });
  // Потолка у направлений нет: крупную сумму оператор обсуждает лично, а не
  // отбивает формой. Колонка max_from в базе осталась, но нигде не читается.
  if (dir.min_from && amount < dir.min_from) return res.status(400).json({ error: `Минимальная сумма: ${dir.min_from} ${dir.from_cur}` });
  if (!contact || !String(contact).trim()) return res.status(400).json({ error: 'Укажите контакт (Telegram)' });
  // Курс считается по выбранному способу отправки: у каждого он свой
  const { rate, source } = directionRate(dir, channel || undefined);
  if (rate == null) {
    return res.status(503).json({
      error: source === 'on_request'
        ? 'По этому направлению курс называем в чате — напишите нам, посчитаем вручную'
        : 'Курс временно недоступен, попробуйте позже',
    });
  }
  const amountTo = amount * rate;
  // Способ выдачи: незнакомое значение считаем обычным переводом
  const payoutType = PAYOUT_TYPES[String(b.payout_type || '')] ? String(b.payout_type) : 'transfer';
  // Каждое поле реквизитов необязательное, поэтому просто подрезаем пробелы
  const text = value => String(value || '').trim().slice(0, 500);
  // Фото реквизитов шифруется так же, как документы верификации
  let attachment = null;
  let attachmentHash = null;
  if (b.attachment) {
    const saved = saveImage(b.attachment, `order-u${req.user.id}`);
    if (saved.error) return res.status(400).json({ error: 'Вложение: ' + saved.error });
    attachment = saved.name;
    attachmentHash = saved.hash;
  }

  const info = db.prepare(`
    INSERT INTO orders (user_id, direction_id, amount_from, amount_to, rate, contact, requisites, comment,
      payment_channel, payout_type, recipient_name, recipient_bank, recipient_account,
      delivery_address, delivery_geo, attachment, attachment_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(req.user.id, dir.id, amount, Number(amountTo.toFixed(2)), Number(rate.toFixed(6)),
    String(contact).trim(), text(requisites), text(comment), channel,
    payoutType, text(b.recipient_name), text(b.recipient_bank), text(b.recipient_account),
    payoutType === 'delivery' ? text(b.delivery_address) : '',
    payoutType === 'delivery' ? text(b.delivery_geo) : '',
    attachment, attachmentHash);
  // Печать ставится сразу: дальше реквизиты в заявке не меняются
  sealOrder(info.lastInsertRowid);

  // Тот же текст сверки, что уходит оператору, возвращается клиенту:
  // он подтверждает его на сайте и отправляет в чат одним нажатием
  const recap = buildClientRecap({
    id: info.lastInsertRowid, dir, amount, amountTo,
    channel: PAYMENT_CHANNELS[channel]?.label || '',
    payout: PAYOUT_TYPES[payoutType],
    recipientName: text(b.recipient_name),
    recipientBank: text(b.recipient_bank),
    recipientAccount: text(b.recipient_account),
    deliveryAddress: payoutType === 'delivery' ? text(b.delivery_address) : '',
    deliveryGeo: payoutType === 'delivery' ? text(b.delivery_geo) : '',
    hasAttachment: !!attachment,
  });
  notifyNewOrder({
    id: info.lastInsertRowid, dir, amount, amountTo,
    email: req.user.email, contact: String(contact).trim(),
    channel: PAYMENT_CHANNELS[channel]?.label || '',
    payout: PAYOUT_TYPES[payoutType],
    recipient: [text(b.recipient_name), text(b.recipient_bank), text(b.recipient_account)].filter(Boolean).join(', '),
    delivery: payoutType === 'delivery' ? [text(b.delivery_address), text(b.delivery_geo)].filter(Boolean).join(' · ') : '',
    hasAttachment: !!attachment,
    // Отдельные поля нужны сообщению клиенту: там каждая строка своя
    recipientName: text(b.recipient_name),
    recipientBank: text(b.recipient_bank),
    recipientAccount: text(b.recipient_account),
    deliveryAddress: payoutType === 'delivery' ? text(b.delivery_address) : '',
    deliveryGeo: payoutType === 'delivery' ? text(b.delivery_geo) : '',
  });
  // Ник оператора нужен, чтобы открыть чат с готовым сообщением
  res.json({ ok: true, id: info.lastInsertRowid, recap, telegram: getSetting('telegram_username') || '' });
});

// Экранирование текста для Telegram с parse_mode HTML
function escapeHtml(text) {
  return String(text ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Уведомление о новой заявке. Если агент подключён и умеет считать это направление,
// добавляем его расчёт: себестоимость, маржу и черновик ответа клиенту.
function notifyNewOrder(order) {
  const { id, dir, amount, amountTo, email, contact, channel, payout, recipient, delivery, hasAttachment } = order;
  const head = `🆕 <b>Заявка №${id}</b>\n${escapeHtml(dir.label)}\n` +
    `Отдаёт: ${amount} ${dir.from_cur} → Получает: ${amountTo.toFixed(2)} ${dir.to_cur}\n` +
    (channel ? `Отправка: ${escapeHtml(channel)}\n` : '') +
    (payout ? `Выдача: ${escapeHtml(payout)}\n` : '') +
    (recipient ? `Реквизиты: ${escapeHtml(recipient)}\n` : '') +
    (delivery ? `Доставка: ${escapeHtml(delivery)}\n` : '') +
    (hasAttachment ? 'Приложено фото реквизитов\n' : '') +
    `Клиент: ${escapeHtml(email)}\nКонтакт: ${escapeHtml(contact)}`;

  // Отдельным сообщением уходит готовый текст клиенту: нажал на него, скопировал,
  // отправил. Ссылка рядом открывает чат клиента в Telegram.
  const tg = String(contact || '').trim().replace(/^@/, '');
  const recapText = `📋 <b>Клиенту на сверку</b>` +
    (tg && /^[a-zA-Z0-9_]{4,32}$/.test(tg) ? ` — <a href="https://t.me/${tg}">открыть чат @${escapeHtml(tg)}</a>` : '') +
    `\n\n<pre>${escapeHtml(buildClientRecap(order))}</pre>`;

  const agentDirection = agent.directionForAgent(dir.from_cur, dir.to_cur);
  if (!agent.isConfigured() || !agentDirection) {
    notifyAdminSafe(head);
    notifyAdminSafe(recapText);
    return;
  }
  // Сверку отправляем сразу, не дожидаясь расчёта агента
  notifyAdminSafe(recapText);

  (async () => {
    try {
      const payload = { direction: agentDirection, analyze_bybit: true };
      // Суммы передаются в той валюте, в которой их понимают правила агента
      if (dir.from_cur === 'RUB') payload.amount_rub = amount;
      else if (dir.from_cur === 'THB') payload.amount_thb = amount;
      else if (dir.from_cur === 'USDT') payload.amount_usdt = amount;
      if (dir.from_cur === 'RUB' && dir.to_cur === 'THB') payload.client_has_tbank = true;

      const deal = await agent.calcDeal(payload);
      const lines = [head, '', '<b>Расчёт агента</b>'];
      if (deal.scenario) lines.push(`Сценарий: ${escapeHtml(deal.scenario)}`);
      if (deal.client_rate != null) lines.push(`Курс клиенту: ${Number(deal.client_rate).toFixed(4)}`);
      if (deal.margin_percent != null) lines.push(`Маржа: ${Number(deal.margin_percent).toFixed(2)}%`);
      if (deal.selected_bybit_ad) {
        lines.push(`Стакан Bybit: ${escapeHtml(deal.selected_bybit_ad.advertiser || '—')} по ${escapeHtml(deal.selected_bybit_ad.price)}`);
      }
      for (const w of (deal.warnings || []).slice(0, 5)) lines.push(`⚠️ ${escapeHtml(w)}`);
      if (deal.client_draft) {
        lines.push('', '<b>Черновик ответа клиенту</b>', escapeHtml(deal.client_draft));
      }
      // Telegram не принимает сообщения длиннее 4096 символов
      let text = lines.join('\n');
      if (text.length > 3900) text = text.slice(0, 3900) + '\n…';
      notifyAdminSafe(text);
    } catch (e) {
      // Агент недоступен — отправляем обычное уведомление, заявка не теряется
      notifyAdminSafe(head + `\n\n⚠️ Агент не ответил: ${escapeHtml(e.message)}`);
    }
  })();
}

app.get('/api/orders', requireAuth, (req, res) => {
  const orders = db.prepare(`
    SELECT o.*, d.label AS direction_label, d.from_cur, d.to_cur
    FROM orders o JOIN directions d ON d.id = o.direction_id
    WHERE o.user_id = ? ORDER BY o.id DESC
  `).all(req.user.id);
  // Клиент тоже видит, что его реквизиты не подменяли, но не видит служебных полей
  res.json({
    orders: orders.map(order => {
      const integrity = orderIntegrity(order);
      const { attachment, attachment_hash, seal, ...rest } = order;
      return { ...rest, integrity };
    }),
  });
});

// Клиент убирает из своего кабинета отработавшую заявку.
//
// Только выполненные и отменённые: пока заявка в работе, она нужна не столько
// клиенту, сколько оператору — по ней сверяют реквизиты и ведут сделку. Дать
// стирать её на ходу значило бы разрешить убрать запись о деньгах, которые
// уже отправлены.
const CLIENT_DELETABLE = ['done', 'cancelled'];

app.delete('/api/orders/:id', requireAuth, (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?').get(Number(req.params.id), req.user.id);
  if (!order) return res.status(404).json({ error: 'Заявка не найдена' });
  if (!CLIENT_DELETABLE.includes(order.status)) {
    return res.status(400).json({ error: 'Убрать можно только выполненную или отменённую заявку. Эта ещё в работе — напишите нам в Telegram.' });
  }
  deleteUpload(order.attachment);
  db.prepare('DELETE FROM orders WHERE id = ?').run(order.id);
  console.log(`[cabinet] клиент удалил свою заявку №${order.id} (${order.status})`);
  res.json({ ok: true, id: order.id });
});

// ---------- Верификация клиента ----------

const VERIFY_STATUSES = ['none', 'pending', 'approved', 'rejected'];
const MAX_IMAGE_BYTES = 8 * 1024 * 1024;

// Сколько всего места разрешено занимать вложениям. Диск сервера — один гигабайт,
// и на нём же лежит база. Без этого предела достаточно нескольких десятков
// регистраций с фотографиями, чтобы диск кончился и сайт перестал писать вообще.
const MAX_UPLOADS_BYTES = 400 * 1024 * 1024;

// Занятое вложениями место. Считается один раз при запуске и дальше ведётся
// по ходу дела: перечитывать каталог на каждую загрузку незачем.
let uploadsBytes = 0;
try {
  for (const name of fs.readdirSync(uploadsDir)) {
    uploadsBytes += fs.statSync(path.join(uploadsDir, name)).size;
  }
} catch (_) { /* каталога ещё нет */ }

// Подпись формата в первых байтах файла. Расширение и заголовок data-URL
// присылает клиент, а это — то, чем файл является на самом деле.
function looksLikeImage(buf, kind) {
  if (kind === 'png') return buf.length > 8 && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  if (kind === 'jpg') return buf.length > 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff;
  if (kind === 'webp') return buf.length > 12 && buf.subarray(0, 4).toString('latin1') === 'RIFF' && buf.subarray(8, 12).toString('latin1') === 'WEBP';
  return false;
}

// Принимает data-URL картинки, шифрует (AES-256-GCM) и сохраняет в data/uploads
function saveImage(dataUrl, prefix) {
  const m = /^data:image\/(png|jpe?g|webp);base64,(.+)$/.exec(String(dataUrl || ''));
  if (!m) return { error: 'Файл должен быть картинкой (JPG, PNG или WebP)' };
  const buf = Buffer.from(m[2], 'base64');
  if (buf.length < 1000) return { error: 'Файл слишком маленький или повреждён' };
  if (buf.length > MAX_IMAGE_BYTES) return { error: 'Файл больше 8 МБ' };
  const ext = m[1] === 'jpeg' ? 'jpg' : m[1];
  if (!looksLikeImage(buf, ext)) return { error: 'Это не картинка — сохраните фото заново и попробуйте ещё раз' };
  if (uploadsBytes + buf.length > MAX_UPLOADS_BYTES) {
    console.error('[uploads] место под вложения кончилось — загрузка отклонена');
    return { error: 'Хранилище переполнено, напишите нам в Telegram' };
  }
  const name = `${prefix}-${crypto.randomBytes(8).toString('hex')}.${ext}.enc`;
  const encrypted = encryptBuffer(buf);
  fs.writeFileSync(path.join(uploadsDir, name), encrypted);
  uploadsBytes += encrypted.length;
  // Отпечаток исходной картинки, чтобы поймать подмену файла на диске
  return { name, hash: hashBuffer(buf) };
}

const IMAGE_MIME = { jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp' };

// Чтение файла верификации: новые файлы (.enc) расшифровываются, старые отдаются как есть
function readUpload(name) {
  const file = path.basename(name);
  const raw = fs.readFileSync(path.join(uploadsDir, file));
  const encrypted = file.endsWith('.enc');
  const ext = (encrypted ? file.slice(0, -4) : file).split('.').pop().toLowerCase();
  return { buf: encrypted ? decryptBuffer(raw) : raw, mime: IMAGE_MIME[ext] || 'application/octet-stream' };
}

function deleteUpload(name) {
  if (!name) return;
  const p = path.join(uploadsDir, path.basename(name));
  try {
    // Размер снимается до удаления: из него ведётся счёт занятого места
    const { size } = fs.statSync(p);
    fs.unlinkSync(p);
    uploadsBytes = Math.max(0, uploadsBytes - size);
  } catch (_) {}
}

app.get('/api/verification', requireAuth, (req, res) => {
  const u = db.prepare(`SELECT verify_status, verify_comment, verify_submitted_at,
    full_name, phone, telegram FROM users WHERE id = ?`).get(req.user.id);
  res.json({
    status: u.verify_status, comment: u.verify_comment || '', submitted_at: u.verify_submitted_at,
    full_name: u.full_name || '', phone: u.phone || '', telegram: u.telegram || '',
  });
});

// Каждая отправка кладёт на диск две картинки. Прежние удаляются, но перебирать
// их без счёта незачем: пять попыток в сутки покрывают любую переснятую фотографию.
const limitVerification = rateLimit({
  name: 'verification', limit: 5, windowMs: 24 * 60 * MINUTE, by: req => req.user?.id ?? '',
  message: 'Сегодня документы отправлялись уже пять раз. Напишите нам в Telegram.',
});

app.post('/api/verification', requireAuth, limitVerification, (req, res) => {
  const u = db.prepare('SELECT verify_status, verify_passport, verify_selfie FROM users WHERE id = ?').get(req.user.id);
  if (u.verify_status === 'approved') return res.status(400).json({ error: 'Верификация уже пройдена' });

  const fullName = String(req.body?.full_name || '').trim();
  const phone = String(req.body?.phone || '').trim();
  const telegram = String(req.body?.telegram || '').trim().replace(/^@/, '');
  if (fullName.split(/\s+/).length < 2) return res.status(400).json({ error: 'Укажите полные ФИО (фамилия и имя обязательны)' });
  if (phone.replace(/\D/g, '').length < 10) return res.status(400).json({ error: 'Укажите корректный номер телефона, к которому привязан банк' });
  if (!telegram) return res.status(400).json({ error: 'Укажите ваш Telegram' });

  const passport = saveImage(req.body?.passport, `u${req.user.id}-passport`);
  if (passport.error) return res.status(400).json({ error: 'Паспорт: ' + passport.error });
  const selfie = saveImage(req.body?.selfie, `u${req.user.id}-selfie`);
  if (selfie.error) { deleteUpload(passport.name); return res.status(400).json({ error: 'Фото лица: ' + selfie.error }); }

  deleteUpload(u.verify_passport);
  deleteUpload(u.verify_selfie);
  db.prepare(`UPDATE users SET verify_status = 'pending', verify_passport = ?, verify_selfie = ?,
    verify_comment = '', verify_submitted_at = datetime('now'),
    full_name = ?, phone = ?, telegram = ? WHERE id = ?`)
    .run(passport.name, selfie.name, fullName, phone, telegram, req.user.id);
  // Ссылка открывает админку сразу на вкладке верификации, где ждёт заявка
  const verifyLink = `${publicBase(req)}/admin.html#verify`;
  notifyAdminSafe(`🪪 <b>Новая верификация</b>\n${escapeHtml(fullName)}\n${escapeHtml(req.user.email)}\n` +
    `Телефон: ${escapeHtml(phone)}\nTelegram: @${escapeHtml(telegram)}\n\n` +
    `<a href="${verifyLink}">Проверить в админке</a>`);
  res.json({ ok: true });
});

app.get('/api/admin/verifications', requireAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT id, email, name, full_name, phone, telegram, verify_status, verify_comment, verify_submitted_at,
      (verify_passport IS NOT NULL) AS has_passport, (verify_selfie IS NOT NULL) AS has_selfie
    FROM users WHERE verify_status != 'none'
    ORDER BY CASE verify_status WHEN 'pending' THEN 0 ELSE 1 END, verify_submitted_at DESC
  `).all();
  res.json({ users });
});

app.get('/api/admin/clients', requireAdmin, (req, res) => {
  const clients = db.prepare(`
    SELECT u.id, u.email, u.name, u.full_name, u.phone, u.telegram, u.verify_status, u.blocked, u.created_at,
      COUNT(o.id) AS orders_count,
      (SELECT contact FROM orders WHERE user_id = u.id ORDER BY id DESC LIMIT 1) AS last_order_contact
    FROM users u LEFT JOIN orders o ON o.user_id = u.id
    WHERE u.is_admin = 0
    GROUP BY u.id ORDER BY u.id DESC
  `).all();
  res.json({ clients });
});

// Закрыть или вернуть доступ клиенту. Учётка и вся её история остаются на
// месте — меняется только возможность войти. Открытые входы закрываются сразу,
// иначе уже вошедший продолжал бы работать до конца месяца.
app.patch('/api/admin/clients/:id', requireAdmin, (req, res) => {
  const user = db.prepare('SELECT id, email, is_admin FROM users WHERE id = ?').get(Number(req.params.id));
  if (!user) return res.status(404).json({ error: 'Клиент не найден' });
  if (user.is_admin) return res.status(400).json({ error: 'Администратора заблокировать нельзя' });
  const blocked = req.body?.blocked ? 1 : 0;
  db.prepare('UPDATE users SET blocked = ? WHERE id = ?').run(blocked, user.id);
  if (blocked) db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id);
  console.log(`[admin] клиент ${user.email}: доступ ${blocked ? "закрыт" : "открыт"}`);
  res.json({ ok: true, id: user.id, blocked: !!blocked });
});

// Удаление клиента со всем, что за ним числится.
//
// Заявки, переписка и документы уходят вместе с учёткой: оставить их значило бы
// хранить персональные данные человека, которого в системе уже нет. Файлы
// стираются с диска отдельно — база про них знает только имена.
app.delete('/api/admin/clients/:id', requireAdmin, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(req.params.id));
  if (!user) return res.status(404).json({ error: 'Клиент не найден' });
  if (user.is_admin) return res.status(400).json({ error: 'Администратора удалить нельзя' });

  // Сначала собираем имена файлов: после удаления строк их будет не найти
  const files = [user.verify_passport, user.verify_selfie].filter(Boolean);
  for (const row of db.prepare('SELECT attachment FROM orders WHERE user_id = ? AND attachment IS NOT NULL').all(user.id)) {
    files.push(row.attachment);
  }

  const wipe = db.transaction(() => {
    const orders = db.prepare('DELETE FROM orders WHERE user_id = ?').run(user.id).changes;
    const messages = db.prepare('DELETE FROM messages WHERE user_id = ?').run(user.id).changes;
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id);
    db.prepare('DELETE FROM password_resets WHERE user_id = ?').run(user.id);
    db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
    return { orders, messages };
  });
  const removed = wipe();
  for (const name of files) deleteUpload(name);

  console.log(`[admin] удалён клиент ${user.email}: заявок ${removed.orders}, сообщений ${removed.messages}, файлов ${files.length}`);
  res.json({ ok: true, email: user.email, deleted_orders: removed.orders, deleted_messages: removed.messages, deleted_files: files.length });
});

// Фото реквизитов из заявки: лежит зашифрованным, отдаётся только администратору
app.get('/api/admin/orders/:orderId/attachment', requireAdmin, (req, res) => {
  const row = db.prepare('SELECT * FROM orders WHERE id = ?').get(Number(req.params.orderId));
  if (!row || !row.attachment) return res.status(404).json({ error: 'Вложения нет' });
  // Заявка с нарушенной печатью не показывается: файл мог быть подменён вместе с ней
  if (orderIntegrity(row) === 'broken') {
    console.error(`[integrity] вложение заявки №${row.id} не отдано: печать не сошлась`);
    return res.status(409).json({ error: 'Данные заявки изменены после создания — вложению нельзя доверять' });
  }
  try {
    const { buf, mime } = readUpload(row.attachment);
    // Отпечаток ловит подмену самого файла на диске
    if (row.attachment_hash && hashBuffer(buf) !== row.attachment_hash) {
      console.error(`[integrity] вложение заявки №${row.id}: содержимое не совпадает с отпечатком`);
      return res.status(409).json({ error: 'Файл на диске не совпадает с тем, что прислал клиент' });
    }
    res.set('Content-Type', mime).send(buf);
  } catch (e) {
    console.error('[uploads] не удалось прочитать вложение заявки:', e.message);
    res.status(500).json({ error: 'Не удалось расшифровать файл (проверьте secret.key)' });
  }
});

app.get('/api/admin/verifications/:userId/file/:kind', requireAdmin, (req, res) => {
  const col = req.params.kind === 'selfie' ? 'verify_selfie' : 'verify_passport';
  const u = db.prepare(`SELECT ${col} AS f FROM users WHERE id = ?`).get(Number(req.params.userId));
  if (!u || !u.f) return res.status(404).json({ error: 'Файл не найден' });
  try {
    const { buf, mime } = readUpload(u.f);
    res.set('Content-Type', mime).send(buf);
  } catch (e) {
    console.error('[uploads] не удалось прочитать файл:', e.message);
    res.status(500).json({ error: 'Не удалось расшифровать файл (проверьте secret.key)' });
  }
});

app.patch('/api/admin/verifications/:userId', requireAdmin, (req, res) => {
  const { status, comment } = req.body || {};
  if (!['approved', 'rejected'].includes(status)) return res.status(400).json({ error: 'Статус: approved или rejected' });
  const u = db.prepare('SELECT id FROM users WHERE id = ?').get(Number(req.params.userId));
  if (!u) return res.status(404).json({ error: 'Пользователь не найден' });
  db.prepare('UPDATE users SET verify_status = ?, verify_comment = ? WHERE id = ?')
    .run(status, String(comment || '').trim(), u.id);
  res.json({ ok: true });
});

// ---------- Зашифрованный чат (E2E) ----------
// Сервер не видит текст сообщений: клиент и админ обмениваются публичными ключами (ECDH P-256),
// каждый выводит общий AES-256-GCM ключ у себя в браузере. Здесь хранится только шифротекст.

const MAX_CIPHERTEXT = 100 * 1024;
const chatNotifyAt = new Map(); // userId -> время последнего TG-уведомления о чате

function validPubkeyJwk(k) {
  return k && k.kty === 'EC' && k.crv === 'P-256' && typeof k.x === 'string' && typeof k.y === 'string';
}

// Публикация своего публичного ключа (у админа он общий для всех диалогов)
app.post('/api/chat/pubkey', requireAuth, (req, res) => {
  const key = req.body?.pubkey;
  if (!validPubkeyJwk(key)) return res.status(400).json({ error: 'Некорректный публичный ключ' });
  const json = JSON.stringify({ kty: key.kty, crv: key.crv, x: key.x, y: key.y });
  if (req.user.is_admin) setSetting('admin_pubkey', json);
  else db.prepare('UPDATE users SET pubkey = ? WHERE id = ?').run(json, req.user.id);
  res.json({ ok: true });
});

// Публичный ключ собеседника
app.get('/api/chat/peer-key', requireAuth, (req, res) => {
  const raw = getSetting('admin_pubkey');
  res.json({ pubkey: raw ? JSON.parse(raw) : null });
});

app.get('/api/chat/messages', requireAuth, (req, res) => {
  const after = Number(req.query.after) || 0;
  const rows = db.prepare(`SELECT id, sender, iv, ciphertext, created_at FROM messages
    WHERE user_id = ? AND id > ? ORDER BY id`).all(req.user.id, after);
  db.prepare("UPDATE messages SET read_by_peer = 1 WHERE user_id = ? AND sender = 'admin'").run(req.user.id);
  res.json({ messages: rows });
});

// Сообщение весит до ста килобайт и ложится в базу. Переписке живого человека
// две сотни в час не мешают, а забить базу ими уже не выйдет.
const limitChat = rateLimit({
  name: 'chat', limit: 200, windowMs: 60 * MINUTE, by: req => req.user?.id ?? '',
  message: 'Слишком много сообщений подряд, подождите немного',
});

app.post('/api/chat/messages', requireAuth, limitChat, (req, res) => {
  const { iv, ciphertext } = req.body || {};
  if (typeof iv !== 'string' || typeof ciphertext !== 'string' || !iv || !ciphertext) {
    return res.status(400).json({ error: 'Пустое сообщение' });
  }
  if (ciphertext.length > MAX_CIPHERTEXT) return res.status(400).json({ error: 'Сообщение слишком длинное' });
  const info = db.prepare(`INSERT INTO messages (user_id, sender, iv, ciphertext) VALUES (?, 'user', ?, ?)`)
    .run(req.user.id, iv, ciphertext);
  // Текст зашифрован — уведомляем только о факте сообщения, не чаще раза в 5 минут на клиента
  const lastNotify = chatNotifyAt.get(req.user.id) || 0;
  if (Date.now() - lastNotify > 5 * 60 * 1000) {
    chatNotifyAt.set(req.user.id, Date.now());
    notifyAdminSafe(`💬 <b>Новое сообщение в чате</b>\nОт: ${req.user.email}\nОткройте админку, чтобы прочитать (сообщение зашифровано).`);
  }
  res.json({ ok: true, id: info.lastInsertRowid });
});

// Админ: список диалогов
app.get('/api/admin/chat/threads', requireAdmin, (req, res) => {
  const threads = db.prepare(`
    SELECT u.id, u.email, u.full_name, u.telegram, u.pubkey,
      (SELECT COUNT(*) FROM messages m WHERE m.user_id = u.id AND m.sender = 'user' AND m.read_by_peer = 0) AS unread,
      (SELECT MAX(created_at) FROM messages m WHERE m.user_id = u.id) AS last_at,
      (SELECT COUNT(*) FROM messages m WHERE m.user_id = u.id) AS total
    FROM users u WHERE u.is_admin = 0 AND u.pubkey IS NOT NULL
    ORDER BY unread DESC, last_at DESC
  `).all().filter(t => t.total > 0 || t.unread > 0);
  res.json({ threads: threads.map(t => ({ ...t, pubkey: JSON.parse(t.pubkey) })) });
});

app.get('/api/admin/chat/:userId/messages', requireAdmin, (req, res) => {
  const uid = Number(req.params.userId);
  const after = Number(req.query.after) || 0;
  const rows = db.prepare(`SELECT id, sender, iv, ciphertext, created_at FROM messages
    WHERE user_id = ? AND id > ? ORDER BY id`).all(uid, after);
  db.prepare("UPDATE messages SET read_by_peer = 1 WHERE user_id = ? AND sender = 'user'").run(uid);
  res.json({ messages: rows });
});

app.post('/api/admin/chat/:userId/messages', requireAdmin, (req, res) => {
  const uid = Number(req.params.userId);
  const target = db.prepare('SELECT id FROM users WHERE id = ? AND is_admin = 0').get(uid);
  if (!target) return res.status(404).json({ error: 'Клиент не найден' });
  const { iv, ciphertext } = req.body || {};
  if (typeof iv !== 'string' || typeof ciphertext !== 'string' || !iv || !ciphertext) {
    return res.status(400).json({ error: 'Пустое сообщение' });
  }
  if (ciphertext.length > MAX_CIPHERTEXT) return res.status(400).json({ error: 'Сообщение слишком длинное' });
  const info = db.prepare(`INSERT INTO messages (user_id, sender, iv, ciphertext) VALUES (?, 'admin', ?, ?)`)
    .run(uid, iv, ciphertext);
  res.json({ ok: true, id: info.lastInsertRowid });
});

// ---------- Админка ----------

app.get('/api/admin/orders', requireAdmin, (req, res) => {
  const orders = db.prepare(`
    SELECT o.*, d.label AS direction_label, d.from_cur, d.to_cur, u.email AS user_email, u.verify_status AS user_verify,
      (o.attachment IS NOT NULL) AS has_attachment
    FROM orders o JOIN directions d ON d.id = o.direction_id JOIN users u ON u.id = o.user_id
    ORDER BY o.id DESC
  `).all();
  // Печать проверяется на каждом чтении: оператор должен видеть, что данные
  // заявки те же, что прислал клиент. Имя файла вложения наружу не отдаём.
  res.json({
    orders: orders.map(order => {
      const integrity = orderIntegrity(order);
      if (integrity === 'broken') console.error(`[integrity] заявка №${order.id}: печать не сошлась`);
      const { attachment, attachment_hash, seal, ...rest } = order;
      return { ...rest, integrity };
    }),
  });
});

app.patch('/api/admin/orders/:id', requireAdmin, (req, res) => {
  const { status, admin_comment } = req.body || {};
  const order = db.prepare('SELECT id FROM orders WHERE id = ?').get(Number(req.params.id));
  if (!order) return res.status(404).json({ error: 'Заявка не найдена' });
  if (status !== undefined && !STATUSES.includes(status)) return res.status(400).json({ error: 'Неизвестный статус' });
  db.prepare(`
    UPDATE orders SET
      status = COALESCE(?, status),
      admin_comment = COALESCE(?, admin_comment),
      updated_at = datetime('now')
    WHERE id = ?
  `).run(status ?? null, admin_comment !== undefined ? String(admin_comment) : null, order.id);
  res.json({ ok: true });
});

// Удаление заявки вместе с приложенным к ней фото реквизитов.
//
// Стёртая заявка остаётся во вчерашней резервной копии и ещё в двадцати девяти
// до неё, так что ошибочное удаление не окончательно — но искать её придётся
// там, а не на сайте. Поэтому спрашиваем прямо, а не молча выполняем.
app.delete('/api/admin/orders/:id', requireAdmin, (req, res) => {
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(Number(req.params.id));
  if (!order) return res.status(404).json({ error: 'Заявка не найдена' });
  deleteUpload(order.attachment);
  db.prepare('DELETE FROM orders WHERE id = ?').run(order.id);
  console.log(`[admin] удалена заявка №${order.id} (${order.status})`);
  res.json({ ok: true, id: order.id, had_attachment: !!order.attachment });
});

// Удаление верификации: фото с диска и все присланные клиентом данные.
//
// Учётная запись остаётся — клиент сможет подать документы заново. Уходит
// именно то, что он присылал на проверку, включая ФИО, телефон и телеграм:
// половинчатое удаление, оставляющее персональные данные, никого не устроит.
app.delete('/api/admin/verifications/:userId', requireAdmin, (req, res) => {
  const user = db.prepare('SELECT id, verify_passport, verify_selfie FROM users WHERE id = ?').get(Number(req.params.userId));
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  let photos = 0;
  for (const name of [user.verify_passport, user.verify_selfie]) {
    if (!name) continue;
    deleteUpload(name);
    photos++;
  }
  db.prepare(`UPDATE users SET verify_status = 'none', verify_passport = NULL, verify_selfie = NULL,
    verify_comment = '', verify_submitted_at = NULL,
    full_name = '', phone = '', telegram = '' WHERE id = ?`).run(user.id);
  console.log(`[admin] удалена верификация клиента №${user.id}, фото стёрто: ${photos}`);
  res.json({ ok: true, id: user.id, deleted_photos: photos });
});

app.get('/api/admin/directions', requireAdmin, (req, res) => {
  const dirs = db.prepare('SELECT * FROM directions ORDER BY sort, id').all();
  res.json({
    directions: dirs.map(d => {
      const { rate, source, base, at } = directionRate(d);
      // Маржа показывается как есть: сайт ею не считает, её задаёт бот
      return { ...d, current_rate: rate, rate_source: source, base_rate: base, rate_at: at || null, margin: directionMargin(d) };
    }),
    rates: ratesInfo(),
  });
});

function directionFields(body) {
  return {
    from_cur: String(body.from_cur || '').toUpperCase().trim(),
    to_cur: String(body.to_cur || '').toUpperCase().trim(),
    label: String(body.label || '').trim(),
    payment_note: String(body.payment_note || '').trim(),
    markup_pct: Number(body.markup_pct) || 0,
    manual_rate: body.manual_rate === null || body.manual_rate === '' || body.manual_rate === undefined
      ? null : Number(body.manual_rate),
    // Режим берём как прислали. Если его не прислали вовсе, но задан курс —
    // это старое обращение к API, где ручной курс сам по себе означал ручной
    // режим; такие вызовы должны работать по-прежнему.
    price_mode: ['bot', 'margin', 'manual'].includes(body.price_mode)
      ? body.price_mode
      : (Number(body.manual_rate) > 0 ? 'manual' : 'bot'),
    min_from: Number(body.min_from) || 0,
    max_from: Number(body.max_from) || 0,
    enabled: body.enabled ? 1 : 0,
    sort: Number(body.sort) || 100,
  };
}

app.post('/api/admin/directions', requireAdmin, (req, res) => {
  const f = directionFields(req.body || {});
  if (!f.from_cur || !f.to_cur) return res.status(400).json({ error: 'Укажите валюты (например THB и RUB)' });
  if (!f.label) f.label = `${f.from_cur} → ${f.to_cur}`;
  const info = db.prepare(`
    INSERT INTO directions (from_cur, to_cur, label, payment_note, markup_pct, manual_rate, min_from, max_from, enabled, sort, price_mode)
    VALUES (@from_cur, @to_cur, @label, @payment_note, @markup_pct, @manual_rate, @min_from, @max_from, @enabled, @sort, @price_mode)
  `).run(f);
  res.json({ ok: true, id: info.lastInsertRowid });
});

app.patch('/api/admin/directions/:id', requireAdmin, (req, res) => {
  const dir = db.prepare('SELECT * FROM directions WHERE id = ?').get(Number(req.params.id));
  if (!dir) return res.status(404).json({ error: 'Направление не найдено' });
  // Режим либо назван в запросе, либо выводится из него же: прежний способ
  // «прислать ручной курс и этим переключить направление» должен работать
  // и дальше, поэтому смотрим именно на тело запроса, а не на слитую строку.
  const askedMode = req.body.price_mode
    ?? (Number(req.body.manual_rate) > 0 ? 'manual'
      : (req.body.manual_rate === '' || req.body.manual_rate === null ? 'bot' : dir.price_mode));
  const f = directionFields({ ...dir, ...req.body, price_mode: askedMode, enabled: req.body.enabled ?? !!dir.enabled });
  db.prepare(`
    UPDATE directions SET from_cur=@from_cur, to_cur=@to_cur, label=@label, payment_note=@payment_note,
      markup_pct=@markup_pct, manual_rate=@manual_rate, min_from=@min_from, max_from=@max_from,
      enabled=@enabled, sort=@sort, price_mode=@price_mode WHERE id=@id
  `).run({ ...f, id: dir.id });
  res.json({ ok: true });
});

app.post('/api/admin/directions/restore-defaults', requireAdmin, (req, res) => {
  const added = restoreDefaultDirections();
  res.json({ ok: true, added });
});

app.delete('/api/admin/directions/:id', requireAdmin, (req, res) => {
  const used = db.prepare('SELECT COUNT(*) AS c FROM orders WHERE direction_id = ?').get(Number(req.params.id)).c;
  if (used > 0) {
    db.prepare('UPDATE directions SET enabled = 0 WHERE id = ?').run(Number(req.params.id));
    return res.json({ ok: true, disabled: true, note: 'По направлению есть заявки — оно отключено, а не удалено' });
  }
  db.prepare('DELETE FROM directions WHERE id = ?').run(Number(req.params.id));
  res.json({ ok: true });
});

app.get('/api/admin/settings', requireAdmin, (req, res) => {
  res.json({
    site_name: getSetting('site_name'),
    telegram_username: getSetting('telegram_username'),
    smtp_host: getSetting('smtp_host') || '',
    smtp_port: getSetting('smtp_port') || '465',
    smtp_user: getSetting('smtp_user') || '',
    smtp_pass_set: !!(getSetting('smtp_pass') || ''),
    smtp_from: getSetting('smtp_from') || '',
    mail_configured: mailConfigured(),
    tg_bot_token_set: !!(getSetting('tg_bot_token') || ''),
    tg_chat_id: getSetting('tg_chat_id') || '',
    tg_configured: tgConfigured(),
    agent_url: getSetting('agent_url') || '',
    agent_token_set: !!(getSetting('agent_token') || ''),
    agent_configured: agent.isConfigured(),
    // Готовые строки для .env бота: администратор копирует их одной кнопкой.
    // Токен виден только ему — эндпоинт закрыт requireAdmin.
    agent_env: [
      `SITE_URL=${publicBase(req)}`,
      `AGENT_API_TOKEN=${getSetting('agent_token') || ''}`,
    ].join('\n'),
    // Когда бот последний раз присылал курсы
    agent_rates_at: (() => {
      try { return JSON.parse(getSetting('agent_board') || '{}').received_at || null; } catch (_) { return null; }
    })(),
    // Секрет Google наружу не отдаётся — только признак, что он заполнен
    google_client_id: getSetting('google_client_id') || '',
    google_secret_set: !!(getSetting('google_client_secret') || ''),
    google_configured: googleAuth.isConfigured(),
    google_redirect_uri: googleAuth.redirectUri(req),
    // Пароль для выгрузки данных на компьютер владельца. Виден только ему —
    // эндпоинт закрыт requireAdmin.
    backup_token: getSetting('backup_token') || '',
    backup_confirmed_at: getSetting('backup_confirmed_at') || null,
    purge_after_days: purgeAfterDays(),
    rates: ratesInfo(),
  });
});

app.patch('/api/admin/settings', requireAdmin, (req, res) => {
  const b = req.body || {};
  if (b.site_name !== undefined) setSetting('site_name', String(b.site_name).trim());
  if (b.telegram_username !== undefined) setSetting('telegram_username', String(b.telegram_username).replace(/^@/, '').trim());
  if (b.smtp_host !== undefined) setSetting('smtp_host', String(b.smtp_host).trim());
  if (b.smtp_port !== undefined) setSetting('smtp_port', String(b.smtp_port).trim());
  if (b.smtp_user !== undefined) setSetting('smtp_user', String(b.smtp_user).trim());
  if (b.smtp_pass) setSetting('smtp_pass', String(b.smtp_pass)); // пустое значение не затирает пароль
  if (b.smtp_from !== undefined) setSetting('smtp_from', String(b.smtp_from).trim());
  if (b.tg_bot_token) setSetting('tg_bot_token', String(b.tg_bot_token).trim());
  if (b.tg_chat_id !== undefined) setSetting('tg_chat_id', String(b.tg_chat_id).trim());
  if (b.agent_url !== undefined) setSetting('agent_url', String(b.agent_url).trim());
  if (b.agent_token) setSetting('agent_token', String(b.agent_token).trim());
  // Через сколько дней завершённая заявка уходит с сервера после подтверждения
  if (b.purge_after_days !== undefined) {
    // Пустое поле означает «не удалять никогда»
    const asked = String(b.purge_after_days ?? '').trim();
    if (asked === '') {
      setSetting('purge_after_days', 'never');
    } else {
      const days = Number(asked);
      if (!Number.isFinite(days) || days < 0) return res.status(400).json({ error: 'Срок хранения — число дней от нуля, либо пусто, чтобы не удалять' });
      setSetting('purge_after_days', String(Math.round(days)));
    }
  }
  if (b.google_client_id !== undefined) setSetting('google_client_id', String(b.google_client_id).trim());
  // Пустое значение секрета не затирает сохранённый, как и у пароля почты
  if (b.google_client_secret) setSetting('google_client_secret', String(b.google_client_secret).trim());
  res.json({ ok: true });
});

// ---------- Выгрузка данных на компьютер владельца ----------

// Данные клиентов живут на сервере, но владелец хочет держать копию у себя.
// Доступ по отдельному паролю, а не по входу в админку: скрипт выгрузки
// работает по расписанию, и хранить ради него пароль от админки незачем.
// Токен подбирать бессмысленно — он случайный и длинный, — но попытки всё равно
// считаем: так подбор не превращается ещё и в нагрузку на сервер.
const limitTokenAuth = rateLimit({ name: 'token-auth', limit: 30, windowMs: 15 * MINUTE });

function requireBackupToken(req, res, next) {
  const expected = (getSetting('backup_token') || '').trim();
  if (!expected) return res.status(503).json({ error: 'Токен выгрузки не задан' });
  const supplied = String(req.headers['x-backup-token'] || '').trim();
  // Сравнение постоянного времени: длины приводим, чтобы timingSafeEqual не бросал
  const ok = supplied.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected));
  if (!ok) return res.status(401).json({ error: 'Неверный токен' });
  next();
}

// Сколько дней завершённая заявка ещё лежит на сервере после того, как её
// копия подтверждена у владельца. Ноль означает «стирать сразу же».
//
// null означает «не удалять никогда» — и это значение по умолчанию. Сервер,
// который сам ничего не стирает, теряет данные только вместе с диском, и
// тогда их достаёт резервная копия. Обратный порядок — когда единственный
// экземпляр переезжает на чужой компьютер — оставлял бы всё на одной ниточке.
function purgeAfterDays() {
  const raw = getSetting('purge_after_days');
  if (raw === null || String(raw).trim() === '' || String(raw) === 'never') return null;
  const value = Number(raw);
  return Number.isFinite(value) && value >= 0 ? value : null;
}

// Снимок базы целиком. VACUUM INTO делает согласованную копию на ходу —
// простое копирование файла во время записи дало бы битую базу.
app.get('/api/admin/backup/db', limitTokenAuth, requireBackupToken, (req, res) => {
  const snapshot = path.join(os.tmpdir(), `kometa-backup-${crypto.randomBytes(6).toString('hex')}.db`);
  try {
    // Момент снимка едет вместе с файлом: по нему потом определяется, что
    // именно уже лежит у владельца и что можно стирать с сервера.
    const takenAt = new Date().toISOString();
    db.exec(`VACUUM INTO '${snapshot.replace(/'/g, "''")}'`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('X-Snapshot-At', takenAt);
    res.setHeader('Content-Disposition', 'attachment; filename="exchange.db"');
    const stream = fs.createReadStream(snapshot);
    // Временный снимок удаляется в любом случае: и после отдачи, и при обрыве
    const cleanup = () => { try { fs.unlinkSync(snapshot); } catch (_) {} };
    stream.on('close', cleanup);
    stream.on('error', cleanup);
    stream.pipe(res);
  } catch (e) {
    try { fs.unlinkSync(snapshot); } catch (_) {}
    res.status(500).json({ error: 'Не удалось снять копию базы: ' + e.message });
  }
});

// Список вложений верификации. Файлы уже зашифрованы на диске и такими же
// уезжают на компьютер: ключ лежит отдельно, в переменных сервера.
app.get('/api/admin/backup/files', limitTokenAuth, requireBackupToken, (req, res) => {
  try {
    const files = fs.readdirSync(uploadsDir).map(name => ({
      name,
      size: fs.statSync(path.join(uploadsDir, name)).size,
    }));
    res.json({ files });
  } catch (e) {
    res.status(500).json({ error: 'Не удалось прочитать вложения: ' + e.message });
  }
});

app.get('/api/admin/backup/file/:name', limitTokenAuth, requireBackupToken, (req, res) => {
  // basename отрезает любые попытки выйти из папки вложений
  const file = path.join(uploadsDir, path.basename(req.params.name));
  if (!fs.existsSync(file)) return res.status(404).json({ error: 'Файл не найден' });
  res.setHeader('Content-Type', 'application/octet-stream');
  fs.createReadStream(file).pipe(res);
});

// Подтверждение, что копия доехала. Только после него сервер что-либо стирает:
// пока владелец не сказал «получил», данные лежат на месте, чем бы ни
// закончилась выгрузка.
app.post('/api/admin/backup/confirm', limitTokenAuth, requireBackupToken, (req, res) => {
  const snapshotAt = String(req.body?.snapshot_at || '').trim();
  // Без момента снимка непонятно, что именно подтверждают.
  if (!snapshotAt || Number.isNaN(Date.parse(snapshotAt))) {
    return res.status(400).json({ error: 'Укажите snapshot_at из заголовка X-Snapshot-At' });
  }
  // Список файлов, которые владелец действительно забрал.
  const received = new Set((Array.isArray(req.body?.files) ? req.body.files : []).map(name => path.basename(String(name))));
  setSetting('backup_confirmed_at', snapshotAt);

  // Срок не задан — сервер оставляет у себя всё. Подтверждение тогда значит
  // только одно: копия у владельца есть, и по ней видно, на какой момент.
  const days = purgeAfterDays();
  if (days === null) {
    return res.json({ ok: true, confirmed_at: snapshotAt, deleted_orders: 0, deleted_photos: 0, purge_after_days: null });
  }

  // Фото верификации: стираем только те, по которым решение уже принято.
  // Пока заявка на верификацию висит, фото нужно самому оператору.
  const decided = db.prepare(`SELECT verify_passport, verify_selfie FROM users
    WHERE verify_status IN ('approved', 'rejected')`).all();
  let photos = 0;
  for (const row of decided) {
    for (const name of [row.verify_passport, row.verify_selfie]) {
      if (!name || !received.has(path.basename(name))) continue;
      if (!fs.existsSync(path.join(uploadsDir, path.basename(name)))) continue;
      deleteUpload(name);
      photos++;
    }
  }

  // Заявки: только завершённые, только попавшие в подтверждённый снимок,
  // и только те, что отлежали заданный срок. Заявка в работе не трогается.
  const purge = db.prepare(`DELETE FROM orders
    WHERE status IN ('done', 'cancelled')
      AND created_at <= ?
      AND created_at <= datetime('now', ?)`);
  const orders = purge.run(snapshotAt.replace('T', ' ').slice(0, 19), `-${days} days`).changes;

  res.json({ ok: true, confirmed_at: snapshotAt, deleted_orders: orders, deleted_photos: photos, purge_after_days: days });
});

// Курсы, присланные ботом. Оператор проверяет курс в Telegram, бот отправляет
// сюда весь набор, и сайт считает по нему до следующей проверки. Так связка
// работает, даже когда бот запущен не на сервере, а у оператора.
app.post('/api/agent/rates', limitTokenAuth, (req, res) => {
  const expected = (getSetting('agent_token') || '').trim();
  if (!expected) return res.status(503).json({ error: 'Токен агента не задан в админке' });
  const supplied = String(req.headers['x-agent-token'] || '').trim();
  // Сравнение постоянного времени: длины приводим, чтобы timingSafeEqual не бросал
  const ok = supplied.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected));
  if (!ok) return res.status(401).json({ error: 'Неверный токен' });

  const board = req.body || {};
  if (!board.usdt_thb && !board.rub_usdt) return res.status(400).json({ error: 'Пустой набор курсов' });
  setSetting('agent_board', JSON.stringify({ ...board, received_at: new Date().toISOString() }));
  applyPushedBoard();
  res.json({ ok: true });
});

app.post('/api/admin/agent/test', requireAdmin, async (req, res) => {
  if (!agent.isConfigured()) return res.status(400).json({ error: 'Укажите адрес агента и токен' });
  try {
    const health = await agent.health();
    const rates = await agent.fetchRates();
    res.json({
      ok: true,
      health,
      usdt_thb: rates.usdt_thb,
      rub_usdt: rates.rub_usdt,
      warnings: rates.warnings || [],
    });
  } catch (e) {
    res.status(502).json({ error: 'Агент не отвечает: ' + e.message });
  }
});

app.post('/api/admin/telegram/detect', requireAdmin, async (req, res) => {
  const token = String(req.body?.token || getSetting('tg_bot_token') || '').trim();
  if (!token) return res.status(400).json({ error: 'Сначала укажите токен бота' });
  try {
    const { chatId, name } = await detectChatId(token);
    setSetting('tg_bot_token', token);
    setSetting('tg_chat_id', chatId);
    res.json({ ok: true, chatId, name });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post('/api/admin/telegram/test', requireAdmin, async (req, res) => {
  try {
    const r = await notifyAdmin('✅ Проверка связи: уведомления обменника работают.');
    if (!r.sent) return res.status(400).json({ error: 'Бот не настроен — укажите токен и chat ID' });
    res.json({ ok: true });
  } catch (e) {
    res.status(502).json({ error: 'Ошибка Telegram: ' + e.message });
  }
});

// Разбор проблем с почтой: что сохранено и что отвечает сервер провайдера
app.get('/api/admin/mail-check', requireAdmin, async (req, res) => {
  res.json(await mailDiagnose());
});

app.post('/api/admin/test-mail', requireAdmin, async (req, res) => {
  // Адрес проверки задаётся вручную: почта админской учётки не всегда та,
  // которую читают. Пустое поле — отправляем самому администратору.
  const asked = String(req.body?.to || '').trim();
  if (asked && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(asked)) {
    return res.status(400).json({ error: 'Укажите корректный адрес получателя' });
  }
  try {
    const r = await sendMail({
      to: asked || req.user.email,
      subject: `Проверка почты — ${getSetting('site_name')}`,
      text: 'Если вы читаете это письмо, SMTP настроен правильно.',
      html: '<p>Если вы читаете это письмо, SMTP настроен правильно.</p>',
    });
    if (!r.sent) return res.status(400).json({ error: 'SMTP не настроен — заполните хост, логин и пароль' });
    res.json({ ok: true, to: asked || req.user.email });
  } catch (e) {
    res.status(502).json({ error: 'Ошибка отправки: ' + e.message });
  }
});

app.post('/api/admin/password', requireAdmin, async (req, res) => {
  const { current_password, new_password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  try {
    if (!await verifyPassword(String(current_password || ''), user.pass_salt, user.pass_hash)) {
      return res.status(400).json({ error: 'Текущий пароль неверный' });
    }
    if (!new_password || new_password.length < 8) {
      return res.status(400).json({ error: 'Новый пароль минимум 8 символов' });
    }
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = await hashPassword(new_password, salt);
    db.prepare('UPDATE users SET pass_hash = ?, pass_salt = ? WHERE id = ?').run(hash, salt, user.id);
    // Разлогинить все остальные сессии этого пользователя
    db.prepare('DELETE FROM sessions WHERE user_id = ? AND token != ?')
      .run(user.id, sessionCookieToken(req) || '');
    res.json({ ok: true });
  } catch (e) {
    handleAuthError(res, e);
  }
});

app.post('/api/admin/rates/refresh', requireAdmin, async (req, res) => {
  try {
    const info = await refreshRates();
    res.json({ ok: true, ...info });
  } catch (e) {
    res.status(502).json({ error: 'Не удалось обновить курсы: ' + e.message });
  }
});

// ---------- Уборка ----------

// Всё, что накапливается само и никем не удаляется: просроченные сессии и
// использованные ссылки восстановления. Без этого диск в один гигабайт
// кончается тихо и в самый неудобный момент.
//
// Записи посещений отсюда намеренно исключены. Статистика хранится целиком и
// навсегда: она нужна для сравнения года с годом, а рекламный источник может
// понадобиться разобрать спустя долгое время после того, как он отработал.
function housekeeping() {
  try {
    sweepSessions();
    const links = db.prepare(`DELETE FROM password_resets
      WHERE used = 1 OR expires_at <= datetime('now', '-7 days')`).run().changes;
    if (links) console.log(`[uborka] отработавших ссылок восстановления удалено: ${links}`);
  } catch (e) {
    // Уборка не должна мешать работе сайта: не вышло — повторим завтра
    console.error('[uborka] не удалась:', e.message);
  }
}

// ---------- Запуск ----------

housekeeping();
setInterval(housekeeping, 24 * 60 * 60 * 1000).unref();
startAutoRefresh();
app.listen(PORT, () => console.log(`[server] http://localhost:${PORT}`));
