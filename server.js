const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const { db, getSetting, setSetting, restoreDefaultDirections } = require('./db');
const { refreshRates, startAutoRefresh, directionRate, ratesInfo } = require('./rates');
const { sendMail, isConfigured: mailConfigured } = require('./mailer');
const { encryptBuffer, decryptBuffer } = require('./secure-store');
const { notifyAdmin, notifyAdminSafe, detectChatId, isConfigured: tgConfigured } = require('./notifier');
const agent = require('./agent');

const PORT = process.env.PORT || 3210;
const app = express();
// За nginx: доверяем X-Forwarded-*, иначе req.secure и ссылки в письмах будут http
app.set('trust proxy', 1);
// Лимит увеличен: документы верификации приходят как base64-картинки
app.use(express.json({ limit: '25mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const uploadsDir = path.join(__dirname, 'data', 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

// ---------- Пароли и сессии ----------

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').run(token, userId);
  return token;
}

function getSessionUser(req) {
  const cookie = req.headers.cookie || '';
  const match = cookie.match(/(?:^|;\s*)sid=([a-f0-9]{64})/);
  if (!match) return null;
  return db.prepare(`
    SELECT u.id, u.email, u.name, u.is_admin FROM sessions s
    JOIN users u ON u.id = s.user_id WHERE s.token = ?
  `).get(match[1]) || null;
}

function requireAuth(req, res, next) {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Требуется вход' });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  const user = getSessionUser(req);
  if (!user || !user.is_admin) return res.status(403).json({ error: 'Только для администратора' });
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
  const password = process.env.ADMIN_PASSWORD || 'admin12345';
  const salt = crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO users (email, name, pass_hash, pass_salt, is_admin) VALUES (?, ?, ?, ?, 1)')
    .run(email, 'Администратор', hashPassword(password, salt), salt);
  console.log(`[init] Создан администратор: ${email} / ${password} — смените пароль!`);
})();

// ---------- Аутентификация ----------

app.post('/api/register', (req, res) => {
  const { email, password, name } = req.body || {};
  if (!email || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Укажите корректный email' });
  if (!password || password.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });
  const salt = crypto.randomBytes(16).toString('hex');
  try {
    const info = db.prepare('INSERT INTO users (email, name, pass_hash, pass_salt) VALUES (?, ?, ?, ?)')
      .run(email.toLowerCase().trim(), (name || '').trim(), hashPassword(password, salt), salt);
    setSidCookie(req, res, createSession(info.lastInsertRowid));
    res.json({ ok: true });
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) return res.status(400).json({ error: 'Такой email уже зарегистрирован' });
    throw e;
  }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(String(email || '').toLowerCase().trim());
  if (!user || hashPassword(String(password || ''), user.pass_salt) !== user.pass_hash) {
    return res.status(400).json({ error: 'Неверный email или пароль' });
  }
  setSidCookie(req, res, createSession(user.id));
  res.json({ ok: true, is_admin: !!user.is_admin });
});

app.post('/api/logout', (req, res) => {
  const cookie = req.headers.cookie || '';
  const match = cookie.match(/(?:^|;\s*)sid=([a-f0-9]{64})/);
  if (match) db.prepare('DELETE FROM sessions WHERE token = ?').run(match[1]);
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const user = getSessionUser(req);
  res.json({ user });
});

// ---------- Восстановление пароля ----------

const RESET_TTL_MIN = 60;
const lastResetRequest = new Map(); // email -> timestamp (защита от спама)

app.post('/api/forgot-password', async (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  if (!email) return res.status(400).json({ error: 'Укажите email' });

  const prev = lastResetRequest.get(email);
  if (prev && Date.now() - prev < 60 * 1000) {
    return res.status(429).json({ error: 'Ссылка уже запрошена — проверьте почту или подождите минуту' });
  }
  lastResetRequest.set(email, Date.now());

  const user = db.prepare('SELECT id, email FROM users WHERE email = ?').get(email);
  // Ответ всегда одинаковый, чтобы нельзя было проверить, зарегистрирован ли email
  const reply = { ok: true, message: 'Если такой email зарегистрирован, на него отправлена ссылка для сброса пароля' };
  if (!user) return res.json(reply);

  const token = crypto.randomBytes(32).toString('hex');
  db.prepare(`INSERT INTO password_resets (token, user_id, expires_at)
    VALUES (?, ?, datetime('now', '+${RESET_TTL_MIN} minutes'))`).run(token, user.id);

  const base = `${req.protocol}://${req.get('host')}`;
  const link = `${base}/reset.html?token=${token}`;
  console.log(`[reset] Ссылка для сброса пароля ${user.email}: ${link}`);
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

app.post('/api/reset-password', (req, res) => {
  const { token, password } = req.body || {};
  const row = db.prepare(`SELECT token, user_id FROM password_resets
    WHERE token = ? AND used = 0 AND expires_at > datetime('now')`).get(String(token || ''));
  if (!row) return res.status(400).json({ error: 'Ссылка недействительна или устарела. Запросите новую.' });
  if (!password || password.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });

  const salt = crypto.randomBytes(16).toString('hex');
  db.prepare('UPDATE users SET pass_hash = ?, pass_salt = ? WHERE id = ?')
    .run(hashPassword(password, salt), salt, row.user_id);
  db.prepare('UPDATE password_resets SET used = 1 WHERE token = ?').run(row.token);
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(row.user_id); // разлогинить все устройства
  res.json({ ok: true });
});

// ---------- Публичные данные ----------

// Лёгкая версия для шапки: название и Telegram без списка направлений
app.get('/api/site', (req, res) => {
  res.json({ site_name: getSetting('site_name'), telegram: getSetting('telegram_username') });
});

app.get('/api/public', (req, res) => {
  const dirs = db.prepare('SELECT * FROM directions WHERE enabled = 1 ORDER BY sort, id').all();
  const directions = dirs.map(d => {
    const { rate } = directionRate(d);
    return {
      id: d.id, from_cur: d.from_cur, to_cur: d.to_cur, label: d.label,
      payment_note: d.payment_note, min_from: d.min_from, max_from: d.max_from,
      rate: rate != null ? Number(rate.toFixed(6)) : null,
    };
  });
  res.json({
    directions,
    rates: ratesInfo(),
    site_name: getSetting('site_name'),
    telegram: getSetting('telegram_username'),
  });
});

// ---------- Заявки пользователя ----------

const STATUSES = ['new', 'processing', 'awaiting_payment', 'done', 'cancelled'];

app.post('/api/orders', requireAuth, (req, res) => {
  const { direction_id, amount_from, contact, requisites, comment } = req.body || {};
  const dir = db.prepare('SELECT * FROM directions WHERE id = ? AND enabled = 1').get(Number(direction_id));
  if (!dir) return res.status(400).json({ error: 'Направление не найдено' });
  const amount = Number(amount_from);
  if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'Некорректная сумма' });
  if (dir.min_from && amount < dir.min_from) return res.status(400).json({ error: `Минимальная сумма: ${dir.min_from} ${dir.from_cur}` });
  if (dir.max_from && amount > dir.max_from) return res.status(400).json({ error: `Максимальная сумма: ${dir.max_from} ${dir.from_cur}` });
  if (!contact || !String(contact).trim()) return res.status(400).json({ error: 'Укажите контакт (Telegram)' });
  const { rate } = directionRate(dir);
  if (rate == null) return res.status(503).json({ error: 'Курс временно недоступен, попробуйте позже' });
  const amountTo = amount * rate;
  const info = db.prepare(`
    INSERT INTO orders (user_id, direction_id, amount_from, amount_to, rate, contact, requisites, comment)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(req.user.id, dir.id, amount, Number(amountTo.toFixed(2)), Number(rate.toFixed(6)),
    String(contact).trim(), String(requisites || '').trim(), String(comment || '').trim());
  notifyNewOrder({
    id: info.lastInsertRowid, dir, amount, amountTo,
    email: req.user.email, contact: String(contact).trim(),
  });
  res.json({ ok: true, id: info.lastInsertRowid });
});

// Экранирование текста для Telegram с parse_mode HTML
function escapeHtml(text) {
  return String(text ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Уведомление о новой заявке. Если агент подключён и умеет считать это направление,
// добавляем его расчёт: себестоимость, маржу и черновик ответа клиенту.
function notifyNewOrder(order) {
  const { id, dir, amount, amountTo, email, contact } = order;
  const head = `🆕 <b>Заявка №${id}</b>\n${escapeHtml(dir.label)}\n` +
    `Отдаёт: ${amount} ${dir.from_cur} → Получает: ${amountTo.toFixed(2)} ${dir.to_cur}\n` +
    `Клиент: ${escapeHtml(email)}\nКонтакт: ${escapeHtml(contact)}`;

  const agentDirection = agent.directionForAgent(dir.from_cur, dir.to_cur);
  if (!agent.isConfigured() || !agentDirection) {
    notifyAdminSafe(head);
    return;
  }

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
  res.json({ orders });
});

// ---------- Верификация клиента ----------

const VERIFY_STATUSES = ['none', 'pending', 'approved', 'rejected'];
const MAX_IMAGE_BYTES = 10 * 1024 * 1024;

// Принимает data-URL картинки, шифрует (AES-256-GCM) и сохраняет в data/uploads
function saveImage(dataUrl, prefix) {
  const m = /^data:image\/(png|jpe?g|webp);base64,(.+)$/.exec(String(dataUrl || ''));
  if (!m) return { error: 'Файл должен быть картинкой (JPG, PNG или WebP)' };
  const buf = Buffer.from(m[2], 'base64');
  if (buf.length < 1000) return { error: 'Файл слишком маленький или повреждён' };
  if (buf.length > MAX_IMAGE_BYTES) return { error: 'Файл больше 10 МБ' };
  const ext = m[1] === 'jpeg' ? 'jpg' : m[1];
  const name = `${prefix}-${crypto.randomBytes(8).toString('hex')}.${ext}.enc`;
  fs.writeFileSync(path.join(uploadsDir, name), encryptBuffer(buf));
  return { name };
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
  try { fs.unlinkSync(p); } catch (_) {}
}

app.get('/api/verification', requireAuth, (req, res) => {
  const u = db.prepare(`SELECT verify_status, verify_comment, verify_submitted_at,
    full_name, phone, telegram FROM users WHERE id = ?`).get(req.user.id);
  res.json({
    status: u.verify_status, comment: u.verify_comment || '', submitted_at: u.verify_submitted_at,
    full_name: u.full_name || '', phone: u.phone || '', telegram: u.telegram || '',
  });
});

app.post('/api/verification', requireAuth, (req, res) => {
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
  const verifyLink = `${req.protocol}://${req.get('host')}/admin.html#verify`;
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
    SELECT u.id, u.email, u.name, u.full_name, u.phone, u.telegram, u.verify_status, u.created_at,
      COUNT(o.id) AS orders_count,
      (SELECT contact FROM orders WHERE user_id = u.id ORDER BY id DESC LIMIT 1) AS last_order_contact
    FROM users u LEFT JOIN orders o ON o.user_id = u.id
    WHERE u.is_admin = 0
    GROUP BY u.id ORDER BY u.id DESC
  `).all();
  res.json({ clients });
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

app.post('/api/chat/messages', requireAuth, (req, res) => {
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
    SELECT o.*, d.label AS direction_label, d.from_cur, d.to_cur, u.email AS user_email, u.verify_status AS user_verify
    FROM orders o JOIN directions d ON d.id = o.direction_id JOIN users u ON u.id = o.user_id
    ORDER BY o.id DESC
  `).all();
  res.json({ orders });
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

app.get('/api/admin/directions', requireAdmin, (req, res) => {
  const dirs = db.prepare('SELECT * FROM directions ORDER BY sort, id').all();
  res.json({
    directions: dirs.map(d => {
      const { rate, source, base } = directionRate(d);
      return { ...d, current_rate: rate, rate_source: source, base_rate: base };
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
    INSERT INTO directions (from_cur, to_cur, label, payment_note, markup_pct, manual_rate, min_from, max_from, enabled, sort)
    VALUES (@from_cur, @to_cur, @label, @payment_note, @markup_pct, @manual_rate, @min_from, @max_from, @enabled, @sort)
  `).run(f);
  res.json({ ok: true, id: info.lastInsertRowid });
});

app.patch('/api/admin/directions/:id', requireAdmin, (req, res) => {
  const dir = db.prepare('SELECT * FROM directions WHERE id = ?').get(Number(req.params.id));
  if (!dir) return res.status(404).json({ error: 'Направление не найдено' });
  const f = directionFields({ ...dir, ...req.body, enabled: req.body.enabled ?? !!dir.enabled });
  db.prepare(`
    UPDATE directions SET from_cur=@from_cur, to_cur=@to_cur, label=@label, payment_note=@payment_note,
      markup_pct=@markup_pct, manual_rate=@manual_rate, min_from=@min_from, max_from=@max_from,
      enabled=@enabled, sort=@sort WHERE id=@id
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

app.post('/api/admin/test-mail', requireAdmin, async (req, res) => {
  try {
    const r = await sendMail({
      to: req.user.email,
      subject: `Проверка почты — ${getSetting('site_name')}`,
      text: 'Если вы читаете это письмо, SMTP настроен правильно.',
      html: '<p>Если вы читаете это письмо, SMTP настроен правильно.</p>',
    });
    if (!r.sent) return res.status(400).json({ error: 'SMTP не настроен — заполните хост, логин и пароль' });
    res.json({ ok: true });
  } catch (e) {
    res.status(502).json({ error: 'Ошибка отправки: ' + e.message });
  }
});

app.post('/api/admin/password', requireAdmin, (req, res) => {
  const { current_password, new_password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (hashPassword(String(current_password || ''), user.pass_salt) !== user.pass_hash) {
    return res.status(400).json({ error: 'Текущий пароль неверный' });
  }
  if (!new_password || new_password.length < 8) {
    return res.status(400).json({ error: 'Новый пароль минимум 8 символов' });
  }
  const salt = crypto.randomBytes(16).toString('hex');
  db.prepare('UPDATE users SET pass_hash = ?, pass_salt = ? WHERE id = ?')
    .run(hashPassword(new_password, salt), salt, user.id);
  // Разлогинить все остальные сессии этого пользователя
  const cookie = req.headers.cookie || '';
  const match = cookie.match(/(?:^|;\s*)sid=([a-f0-9]{64})/);
  db.prepare('DELETE FROM sessions WHERE user_id = ? AND token != ?').run(user.id, match ? match[1] : '');
  res.json({ ok: true });
});

app.post('/api/admin/rates/refresh', requireAdmin, async (req, res) => {
  try {
    const info = await refreshRates();
    res.json({ ok: true, ...info });
  } catch (e) {
    res.status(502).json({ error: 'Не удалось обновить курсы: ' + e.message });
  }
});

// ---------- Запуск ----------

startAutoRefresh();
app.listen(PORT, () => console.log(`[server] http://localhost:${PORT}`));
