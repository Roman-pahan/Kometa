// Telegram-уведомления администратору (новые заявки, верификации, сообщения в чате).
// Настройки в админке: токен бота (@BotFather) и chat ID администратора.
// Если бот не настроен — уведомления тихо пропускаются, сайт работает как обычно.

const { getSetting } = require('./db');

function botConfig() {
  const token = (getSetting('tg_bot_token') || '').trim();
  const chatId = (getSetting('tg_chat_id') || '').trim();
  if (!token || !chatId) return null;
  return { token, chatId };
}

function isConfigured() {
  return !!botConfig();
}

async function notifyAdmin(text) {
  const cfg = botConfig();
  if (!cfg) return { sent: false, reason: 'Бот не настроен' };
  const res = await fetch(`https://api.telegram.org/bot${cfg.token}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: cfg.chatId, text, parse_mode: 'HTML', disable_web_page_preview: true }),
  });
  const data = await res.json().catch(() => ({}));
  if (!data.ok) throw new Error(data.description || `Telegram HTTP ${res.status}`);
  return { sent: true };
}

// Как notifyAdmin, но ошибки не роняют основной запрос — только лог
function notifyAdminSafe(text) {
  notifyAdmin(text).catch(err => console.error('[tg] уведомление не отправлено:', err.message));
}

// Определение chat ID: администратор пишет боту /start, мы берём чат из getUpdates
async function detectChatId(token) {
  const res = await fetch(`https://api.telegram.org/bot${token.trim()}/getUpdates`);
  const data = await res.json().catch(() => ({}));
  if (!data.ok) throw new Error(data.description || 'Неверный токен бота');
  const withMsg = (data.result || []).filter(u => u.message && u.message.chat);
  if (!withMsg.length) throw new Error('Сообщений боту не найдено. Напишите вашему боту /start и попробуйте снова.');
  const chat = withMsg[withMsg.length - 1].message.chat;
  return { chatId: String(chat.id), name: [chat.first_name, chat.last_name, chat.username && '@' + chat.username].filter(Boolean).join(' ') };
}

module.exports = { notifyAdmin, notifyAdminSafe, detectChatId, isConfigured };
