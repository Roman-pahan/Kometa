// Отправка почты через SMTP (настройки — в админке).
// Если SMTP не настроен, письмо не уходит: ссылка печатается в консоль сервера,
// а функция возвращает { sent: false } — удобно для локальной разработки.

const nodemailer = require('nodemailer');
const { getSetting } = require('./db');

function smtpConfig() {
  const host = (getSetting('smtp_host') || '').trim();
  const user = (getSetting('smtp_user') || '').trim();
  const pass = getSetting('smtp_pass') || '';
  const port = Number(getSetting('smtp_port')) || 465;
  if (!host || !user) return null;
  return {
    host,
    port,
    secure: port === 465,
    auth: { user, pass },
    from: (getSetting('smtp_from') || '').trim() || user,
  };
}

function isConfigured() {
  return !!smtpConfig();
}

async function sendMail({ to, subject, html, text }) {
  const cfg = smtpConfig();
  if (!cfg) {
    console.log(`[mail] SMTP не настроен. Письмо для ${to} (${subject}) не отправлено.`);
    if (text) console.log(`[mail] Содержимое: ${text}`);
    return { sent: false, reason: 'SMTP не настроен' };
  }
  const transport = nodemailer.createTransport({
    host: cfg.host, port: cfg.port, secure: cfg.secure, auth: cfg.auth,
  });
  await transport.sendMail({ from: cfg.from, to, subject, html, text });
  return { sent: true };
}

module.exports = { sendMail, isConfigured };
