const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const secure = require('./secure-store');

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

// Путь к базе можно переопределить: тесты работают на своей копии,
// чтобы никогда не трогать боевые данные
const dbFile = process.env.DB_FILE || path.join(dataDir, 'exchange.db');
const db = new Database(dbFile);
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  name TEXT DEFAULT '',
  pass_hash TEXT NOT NULL,
  pass_salt TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS directions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_cur TEXT NOT NULL,
  to_cur TEXT NOT NULL,
  label TEXT NOT NULL,
  payment_note TEXT DEFAULT '',
  markup_pct REAL NOT NULL DEFAULT 2,
  manual_rate REAL,
  min_from REAL NOT NULL DEFAULT 0,
  max_from REAL NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  sort INTEGER NOT NULL DEFAULT 100
);
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  direction_id INTEGER NOT NULL REFERENCES directions(id),
  amount_from REAL NOT NULL,
  amount_to REAL NOT NULL,
  rate REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'new',
  contact TEXT NOT NULL,
  requisites TEXT DEFAULT '',
  comment TEXT DEFAULT '',
  admin_comment TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);
CREATE TABLE IF NOT EXISTS password_resets (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  expires_at TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  sender TEXT NOT NULL CHECK (sender IN ('user', 'admin')),
  iv TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  read_by_peer INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_messages_user ON messages(user_id, id);

-- Рекламные источники: один Telegram-канал = одна ссылка с параметром ref
CREATE TABLE IF NOT EXISTS ad_sources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ref TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  comment TEXT DEFAULT '',
  cost REAL,
  placed_on TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Посещения и действия на сайте. IP не хранится: только необратимый хеш.
-- Пустой ref означает прямой трафик, без рекламной ссылки.
CREATE TABLE IF NOT EXISTS visits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  visitor TEXT NOT NULL,
  ref TEXT NOT NULL DEFAULT '',
  event TEXT NOT NULL DEFAULT 'visit',
  is_new INTEGER NOT NULL DEFAULT 0,
  path TEXT DEFAULT '',
  ip_hash TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_visits_ref ON visits(ref, created_at);
CREATE INDEX IF NOT EXISTS idx_visits_visitor ON visits(visitor, created_at);
CREATE INDEX IF NOT EXISTS idx_visits_created ON visits(created_at);
CREATE INDEX IF NOT EXISTS idx_visits_event ON visits(event, created_at);

-- Метки, которые владелец удалил. Браузер помнит метку месяц и продолжает
-- присылать её после удаления ссылки, поэтому строка появлялась снова — уже
-- без названия. Такие метки перечислены здесь и в статистику не попадают.
CREATE TABLE IF NOT EXISTS retired_refs (
  ref TEXT PRIMARY KEY,
  retired_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

// Миграция: поля верификации у пользователей (ALTER падает, если колонка уже есть)
for (const sql of [
  "ALTER TABLE users ADD COLUMN verify_status TEXT NOT NULL DEFAULT 'none'",
  'ALTER TABLE users ADD COLUMN verify_passport TEXT',
  'ALTER TABLE users ADD COLUMN verify_selfie TEXT',
  "ALTER TABLE users ADD COLUMN verify_comment TEXT DEFAULT ''",
  'ALTER TABLE users ADD COLUMN verify_submitted_at TEXT',
  "ALTER TABLE users ADD COLUMN full_name TEXT DEFAULT ''",
  "ALTER TABLE users ADD COLUMN phone TEXT DEFAULT ''",
  "ALTER TABLE users ADD COLUMN telegram TEXT DEFAULT ''",
  'ALTER TABLE users ADD COLUMN pubkey TEXT',
  // Роль сотрудника: пусто — обычный клиент, marketer — доступ к статистике
  "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT ''",
  // Способ, которым клиент отправляет рубли: qr, tbank или bank
  "ALTER TABLE orders ADD COLUMN payment_channel TEXT DEFAULT ''",
  // Как клиент получает деньги: transfer, delivery или atm
  "ALTER TABLE orders ADD COLUMN payout_type TEXT DEFAULT ''",
  // Реквизиты получателя, каждое поле необязательное
  "ALTER TABLE orders ADD COLUMN recipient_name TEXT DEFAULT ''",
  "ALTER TABLE orders ADD COLUMN recipient_bank TEXT DEFAULT ''",
  "ALTER TABLE orders ADD COLUMN recipient_account TEXT DEFAULT ''",
  // Доставка: адрес и ссылка на точку на карте
  "ALTER TABLE orders ADD COLUMN delivery_address TEXT DEFAULT ''",
  "ALTER TABLE orders ADD COLUMN delivery_geo TEXT DEFAULT ''",
  // Приложенное фото реквизитов, зашифровано как и документы верификации
  "ALTER TABLE orders ADD COLUMN attachment TEXT",
  // Отпечаток содержимого фото: ловит подмену файла на диске
  "ALTER TABLE orders ADD COLUMN attachment_hash TEXT",
  // Печать целостности заявки: считается при создании и больше не меняется
  "ALTER TABLE orders ADD COLUMN seal TEXT",
  // Срок жизни сессии. Без него украденная кука работала бы вечно.
  'ALTER TABLE sessions ADD COLUMN expires_at TEXT',
  // Когда сессией пользовались в последний раз: по нему срок продлевается
  'ALTER TABLE sessions ADD COLUMN used_at TEXT',
  // Закрытый доступ: учётка остаётся со всей историей, но войти по ней нельзя
  'ALTER TABLE users ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0',
  // Чем назначается цена направления: bot — присланной ботом, margin — своей
  // маржой от себестоимости, manual — вписанным вручную курсом
  "ALTER TABLE directions ADD COLUMN price_mode TEXT NOT NULL DEFAULT 'bot'",
]) {
  try { db.exec(sql); } catch (_) { /* колонка уже существует */ }
}

// Сессиям, заведённым до появления срока, он проставляется от даты создания —
// ровно тот месяц, который был обещан куке. Никто не разлогинивается досрочно.
db.exec(`UPDATE sessions SET expires_at = datetime(created_at, '+30 days') WHERE expires_at IS NULL`);
db.exec('DELETE FROM sessions WHERE expires_at <= datetime(\'now\')');
db.exec('CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)');

// Направления, где до появления режимов стоял ручной курс, остаются ручными:
// прежде наличие manual_rate само по себе означало «считать по нему».
db.exec("UPDATE directions SET price_mode = 'manual' WHERE manual_rate IS NOT NULL AND manual_rate > 0 AND price_mode = 'bot'");

// ---------- Настройки ----------

// Настройки, которые по сути являются паролями. В снимке базы они не должны
// читаться глазами: копия базы уезжает на компьютер владельца и в бэкапы.
const SECRET_SETTINGS = new Set([
  'smtp_pass', 'tg_bot_token', 'google_client_secret', 'agent_token', 'backup_token', 'ip_salt',
]);

// Шифровать секреты можно только ключом, который переживёт перезапуск.
// Иначе после ближайшего деплоя расшифровать их будет нечем, и разом отвалятся
// почта, бот и связь с агентом. Пока ключ ненадёжен — храним как раньше.
const ENCRYPT_SECRETS = secure.keyIsPersistent();

function getSetting(key, def = null) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  if (!row) return def;
  return SECRET_SETTINGS.has(key) ? secure.decryptSecret(row.value, key) : row.value;
}

function setSetting(key, value) {
  const text = String(value);
  const stored = SECRET_SETTINGS.has(key) && ENCRYPT_SECRETS && text ? secure.encryptSecret(text) : text;
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
    .run(key, stored);
}

// Смена ключа — событие, о котором надо знать: всё, что было им зашифровано,
// перестало читаться. Отпечаток хранится рядом и сверяется при каждом запуске.
{
  const seen = db.prepare("SELECT value FROM settings WHERE key = 'key_fingerprint'").get();
  const current = secure.keyFingerprint();
  if (!seen) {
    db.prepare("INSERT INTO settings (key, value) VALUES ('key_fingerprint', ?)").run(current);
  } else if (seen.value !== current) {
    console.error('[db] ВНИМАНИЕ: ключ шифрования сменился. Прежние фото верификации '
      + 'и зашифрованные настройки больше не читаются. Проверьте UPLOADS_KEY и data/secret.key.');
    db.prepare("UPDATE settings SET value = ? WHERE key = 'key_fingerprint'").run(current);
  }
}

// Миграция: секреты, сохранённые до появления шифрования, дошифровываются на месте
if (ENCRYPT_SECRETS) {
  let sealed = 0;
  for (const key of SECRET_SETTINGS) {
    const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
    if (!row || !row.value || secure.isEncryptedSecret(row.value)) continue;
    db.prepare('UPDATE settings SET value = ? WHERE key = ?').run(secure.encryptSecret(row.value), key);
    sealed++;
  }
  if (sealed) console.log(`[db] секретов зашифровано в базе: ${sealed}`);
} else {
  console.warn('[db] ключ шифрования непостоянный — секреты в базе остаются открытым текстом. '
    + 'Задайте UPLOADS_KEY в переменных окружения.');
}

// Первичное наполнение направлений обмена
// Порядок задан оператором: сверху то, чем торгуют чаще.
// В названиях только значки валют: подробности клиент узнаёт внутри, у оператора.
const DEFAULT_DIRECTIONS = [
  { from_cur: 'USDT', to_cur: 'RUB', label: '₮ → ₽', payment_note: '', markup_pct: 2, min_from: 30, max_from: 15000, sort: 10 },
  { from_cur: 'RUB', to_cur: 'USDT', label: '₽ → ₮', payment_note: '', markup_pct: 2, min_from: 3000, max_from: 1500000, sort: 20 },
  { from_cur: 'RUB', to_cur: 'THB', label: '₽ → ฿', payment_note: '', markup_pct: 2, min_from: 3000, max_from: 1500000, sort: 30 },
  { from_cur: 'THB', to_cur: 'RUB', label: '฿ → ₽', payment_note: '', markup_pct: 2, min_from: 1000, max_from: 500000, sort: 40 },
  { from_cur: 'THB', to_cur: 'USDT', label: '฿ → ₮', payment_note: '', markup_pct: 2, min_from: 1000, max_from: 500000, sort: 50 },
  { from_cur: 'USDT', to_cur: 'THB', label: '₮ → ฿', payment_note: '', markup_pct: 2, min_from: 30, max_from: 15000, sort: 60 },
  { from_cur: 'RUB', to_cur: 'CNY', label: '₽ → ¥', payment_note: '', markup_pct: 2.5, min_from: 3000, max_from: 1000000, sort: 70 },
  { from_cur: 'USDT', to_cur: 'CNY', label: '₮ → ¥', payment_note: '', markup_pct: 2.5, min_from: 30, max_from: 15000, sort: 80 },
  { from_cur: 'THB', to_cur: 'CNY', label: '฿ → ¥', payment_note: '', markup_pct: 2.5, min_from: 1000, max_from: 500000, sort: 90 },
  // Ключи TF2 стол только выкупает: клиент отдаёт ключи и получает деньги.
  // Обратной пары нет — продажей ключей мы не занимаемся.
  { from_cur: 'KEY', to_cur: 'USDT', label: '🔑 Ключи TF2 → ₮',
    payment_note: 'Выкупаем ключи Mann Co. Supply Crate Key. Передача через обмен в Steam, оплата после получения.',
    markup_pct: 4, min_from: 1, max_from: 0, sort: 100 },
  { from_cur: 'KEY', to_cur: 'RUB', label: '🔑 Ключи TF2 → ₽',
    payment_note: 'Выкупаем ключи Mann Co. Supply Crate Key. Передача через обмен в Steam, оплата после получения.',
    markup_pct: 4, min_from: 1, max_from: 0, sort: 110 },
];

// Добавляет отсутствующие стандартные направления (по паре валют), не трогая существующие.
// Возвращает число добавленных.
function restoreDefaultDirections() {
  const ins = db.prepare(`INSERT INTO directions
    (from_cur, to_cur, label, payment_note, markup_pct, min_from, max_from, sort)
    VALUES (@from_cur, @to_cur, @label, @payment_note, @markup_pct, @min_from, @max_from, @sort)`);
  const exists = db.prepare('SELECT id FROM directions WHERE from_cur = ? AND to_cur = ?');
  let added = 0;
  for (const d of DEFAULT_DIRECTIONS) {
    if (!exists.get(d.from_cur, d.to_cur)) { ins.run(d); added++; }
  }
  return added;
}

const dirCount = db.prepare('SELECT COUNT(*) AS c FROM directions').get().c;
if (dirCount === 0) restoreDefaultDirections();

// Миграция: сеть перевода USDT обсуждается с клиентом лично, на сайте её нет
const trcRows = db.prepare("SELECT id, label, payment_note FROM directions WHERE payment_note LIKE '%TRC%' OR label LIKE '%TRC%'").all();
for (const row of trcRows) {
  const clean = text => String(text || '').replace(/\s*\(TRC-?20\)/gi, '').replace(/\s*TRC-?20\s*/gi, ' ').replace(/\s{2,}/g, ' ').trim();
  db.prepare('UPDATE directions SET label = ?, payment_note = ? WHERE id = ?').run(clean(row.label), clean(row.payment_note), row.id);
}
if (trcRows.length) console.log(`[db] упоминание сети USDT убрано из ${trcRows.length} направлений`);

// Миграция: обмен USDT на рубли и обратно — отдельные направления сайта.
// Добавляем только эти две пары, остальное, что оператор удалил, не трогаем.
const usdtRub = DEFAULT_DIRECTIONS.filter(d =>
  (d.from_cur === 'USDT' && d.to_cur === 'RUB') || (d.from_cur === 'RUB' && d.to_cur === 'USDT'));
const insDir = db.prepare(`INSERT INTO directions
  (from_cur, to_cur, label, payment_note, markup_pct, min_from, max_from, sort)
  VALUES (@from_cur, @to_cur, @label, @payment_note, @markup_pct, @min_from, @max_from, @sort)`);
const dirExists = db.prepare('SELECT id FROM directions WHERE from_cur = ? AND to_cur = ?');
let addedDirs = 0;
for (const d of usdtRub) {
  if (!dirExists.get(d.from_cur, d.to_cur)) { insDir.run(d); addedDirs++; }
}
if (addedDirs) console.log(`[db] добавлены направления USDT↔RUB: ${addedDirs}`);

// Миграция: выкуп ключей TF2 — двух направлений раньше не существовало.
for (const pair of [['KEY', 'USDT'], ['KEY', 'RUB']]) {
  const wanted = DEFAULT_DIRECTIONS.find(d => d.from_cur === pair[0] && d.to_cur === pair[1]);
  if (wanted && !dirExists.get(pair[0], pair[1])) {
    insDir.run(wanted);
    console.log(`[db] добавлено направление ${wanted.label}`);
  }
}

// Миграция: юани стол продаёт и за баты тоже — направления раньше не было.
const thbCny = DEFAULT_DIRECTIONS.find(d => d.from_cur === 'THB' && d.to_cur === 'CNY');
if (thbCny && !dirExists.get('THB', 'CNY')) {
  insDir.run(thbCny);
  console.log('[db] добавлено направление ฿ → ¥');
}

// Миграция: у ключей название и пояснение должны читаться без догадок —
// один значок 🔑 ничего не говорит человеку, который сюда попал впервые.
for (const pair of [['KEY', 'USDT'], ['KEY', 'RUB']]) {
  const wanted = DEFAULT_DIRECTIONS.find(d => d.from_cur === pair[0] && d.to_cur === pair[1]);
  if (!wanted) continue;
  const changed = db.prepare(`UPDATE directions SET label = ?, payment_note = ?
    WHERE from_cur = ? AND to_cur = ? AND (label != ? OR payment_note != ?)`)
    .run(wanted.label, wanted.payment_note, pair[0], pair[1], wanted.label, wanted.payment_note).changes;
  if (changed) console.log(`[db] подписано направление ${wanted.label}`);
}

// Миграция: в названиях направлений остаются только значки валют, а способы
// оплаты с публичной страницы уходят — их клиент выясняет у оператора
const setLabel = db.prepare('UPDATE directions SET label = ?, payment_note = ? WHERE from_cur = ? AND to_cur = ? AND (label != ? OR payment_note != ?)');
let relabelled = 0;
for (const d of DEFAULT_DIRECTIONS) {
  relabelled += setLabel.run(d.label, d.payment_note, d.from_cur, d.to_cur, d.label, d.payment_note).changes;
}
if (relabelled) console.log(`[db] названия направлений переведены на значки валют: ${relabelled}`);

// Миграция: порядок направлений в списке задаётся кодом, а не тем, как их заводили
const setSort = db.prepare('UPDATE directions SET sort = ? WHERE from_cur = ? AND to_cur = ? AND sort != ?');
let resorted = 0;
for (const d of DEFAULT_DIRECTIONS) {
  resorted += setSort.run(d.sort, d.from_cur, d.to_cur, d.sort).changes;
}
if (resorted) console.log(`[db] порядок направлений обновлён: ${resorted}`);

// Миграция: рубли принимаются по СБП и по QR, оплата картой больше не описывается
const cardNote = db.prepare("UPDATE directions SET payment_note = 'Оплата по СБП или QR, выдача батов' WHERE from_cur = 'RUB' AND to_cur = 'THB' AND payment_note = 'Оплата с карты РФ, выдача батов'").run();
if (cardNote.changes) console.log('[db] описание оплаты рублями обновлено на СБП и QR');

// Миграция: юани мы только выдаём, приём юаней с Alipay больше не предлагается
const cnyIn = db.prepare("SELECT id FROM directions WHERE from_cur = 'CNY' AND enabled = 1").all();
for (const row of cnyIn) db.prepare('UPDATE directions SET enabled = 0 WHERE id = ?').run(row.id);
if (cnyIn.length) console.log(`[db] приём юаней отключён (${cnyIn.length} направление), включить можно в админке`);

if (getSetting('site_name') === null) setSetting('site_name', 'Kometa Exchange');
// Миграция: прежние названия обменника заменяются на текущее
if (['Kometa', 'Обмен валют'].includes(getSetting('site_name'))) {
  setSetting('site_name', 'Kometa Exchange');
  console.log('[db] название сайта: Kometa Exchange');
}
// Пароль, которым бот оператора подписывает присланные курсы. Придумывать его
// вручную незачем: сайт заводит случайный сам, а в админке показан готовый
// кусок .env, который остаётся скопировать боту.
if (!getSetting('agent_token')) {
  setSetting('agent_token', require('crypto').randomBytes(24).toString('hex'));
  console.log('[db] создан токен для бота — он показан в админке, в настройках');
}

// Пароль для выгрузки данных на компьютер владельца. Отдельный от токена бота:
// у него другая цена ошибки — он открывает доступ ко всей базе целиком.
if (!getSetting('backup_token')) {
  setSetting('backup_token', require('crypto').randomBytes(24).toString('hex'));
  console.log('[db] создан токен выгрузки — он показан в админке, в настройках');
}

// Соль для хеша IP посетителей. Случайная и своя: с общей строкой хеш
// перебирается по всему диапазону адресов за минуты, и обезличивание мнимое.
if (!getSetting('ip_salt')) setSetting('ip_salt', crypto.randomBytes(24).toString('hex'));

if (getSetting('telegram_username') === null) setSetting('telegram_username', 'Kometa_ex');
// Миграция: связь с клиентами переехала на канал обменника.
// Заменяются только прежние значения — ник, выставленный вручную, не трогаем.
if (['your_telegram', 'Happy_Pattaya'].includes(getSetting('telegram_username'))) {
  setSetting('telegram_username', 'Kometa_ex');
  console.log('[db] Telegram для связи: @Kometa_ex');
}

module.exports = { db, getSetting, setSetting, restoreDefaultDirections };
