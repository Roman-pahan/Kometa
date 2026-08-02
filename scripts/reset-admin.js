// Сброс доступа в админку, когда пароль потерян.
//
// Пароль скрипт не печатает и никуда не отправляет: он берёт его из переменной
// окружения, считает тот же scrypt-хеш, что и сайт, и записывает в базу.
//
// Запуск (Render → Shell → в каталоге проекта):
//   ADMIN_EMAIL='you@mail.com' ADMIN_NEW_PASSWORD='ваш-новый-пароль' node scripts/reset-admin.js
//
// Если администратора с такой почтой ещё нет, он будет создан.

const crypto = require('crypto');
const { db } = require('../db');

// Тот же алгоритм, что и в server.js
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

const email = String(process.env.ADMIN_EMAIL || '').toLowerCase().trim();
const password = String(process.env.ADMIN_NEW_PASSWORD || '');

if (!email) {
  console.error('Укажите ADMIN_EMAIL — почту, под которой заходить в админку.');
  process.exit(1);
}
if (password.length < 8) {
  console.error('Укажите ADMIN_NEW_PASSWORD длиной хотя бы 8 символов.');
  process.exit(1);
}

const salt = crypto.randomBytes(16).toString('hex');
const hash = hashPassword(password, salt);
const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);

if (existing) {
  db.prepare('UPDATE users SET pass_hash = ?, pass_salt = ?, is_admin = 1 WHERE id = ?').run(hash, salt, existing.id);
  console.log(`Пароль обновлён, права администратора выданы: ${email}`);
} else {
  db.prepare('INSERT INTO users (email, name, pass_hash, pass_salt, is_admin) VALUES (?, ?, ?, ?, 1)')
    .run(email, 'Администратор', hash, salt);
  console.log(`Создан администратор: ${email}`);
}

// Старые сессии этого пользователя больше не действуют
const dropped = db.prepare('DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = ?)').run(email);
if (dropped.changes) console.log(`Старые сессии закрыты: ${dropped.changes}`);

console.log('Готово. Заходите на /admin.html');
