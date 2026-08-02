const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, 'exchange.db'));
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
  // Способ, которым клиент отправляет рубли: qr, tbank или bank
  "ALTER TABLE orders ADD COLUMN payment_channel TEXT DEFAULT ''",
]) {
  try { db.exec(sql); } catch (_) { /* колонка уже существует */ }
}

function getSetting(key, def = null) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : def;
}
function setSetting(key, value) {
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
    .run(key, String(value));
}

// Первичное наполнение направлений обмена
const DEFAULT_DIRECTIONS = [
  { from_cur: 'THB', to_cur: 'RUB', label: 'Баты → Рубли', payment_note: 'Приём батов, выплата на карту РФ', markup_pct: 2, min_from: 1000, max_from: 500000, sort: 10 },
  { from_cur: 'RUB', to_cur: 'THB', label: 'Рубли → Баты', payment_note: 'Оплата по СБП или QR, выдача батов', markup_pct: 2, min_from: 3000, max_from: 1500000, sort: 20 },
  { from_cur: 'THB', to_cur: 'USDT', label: 'Баты → USDT', payment_note: 'Выплата USDT, сеть обсуждаем в чате', markup_pct: 2, min_from: 1000, max_from: 500000, sort: 30 },
  { from_cur: 'USDT', to_cur: 'THB', label: 'USDT → Баты', payment_note: 'Приём USDT, выдача батов', markup_pct: 2, min_from: 30, max_from: 15000, sort: 40 },
  { from_cur: 'RUB', to_cur: 'CNY', label: 'Рубли → Юани (Alipay)', payment_note: 'Пополнение Alipay юанями', markup_pct: 2.5, min_from: 3000, max_from: 1000000, sort: 50 },
  { from_cur: 'USDT', to_cur: 'CNY', label: 'USDT → Юани (Alipay)', payment_note: 'Пополнение Alipay за USDT', markup_pct: 2.5, min_from: 30, max_from: 15000, sort: 70 },
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

// Миграция: рубли принимаются по СБП и по QR, оплата картой больше не описывается
const cardNote = db.prepare("UPDATE directions SET payment_note = 'Оплата по СБП или QR, выдача батов' WHERE from_cur = 'RUB' AND to_cur = 'THB' AND payment_note = 'Оплата с карты РФ, выдача батов'").run();
if (cardNote.changes) console.log('[db] описание оплаты рублями обновлено на СБП и QR');

// Миграция: юани мы только выдаём, приём юаней с Alipay больше не предлагается
const cnyIn = db.prepare("SELECT id FROM directions WHERE from_cur = 'CNY' AND enabled = 1").all();
for (const row of cnyIn) db.prepare('UPDATE directions SET enabled = 0 WHERE id = ?').run(row.id);
if (cnyIn.length) console.log(`[db] приём юаней отключён (${cnyIn.length} направление), включить можно в админке`);

if (getSetting('site_name') === null) setSetting('site_name', 'Обмен валют');
if (getSetting('telegram_username') === null) setSetting('telegram_username', 'your_telegram');

module.exports = { db, getSetting, setSetting, restoreDefaultDirections };
