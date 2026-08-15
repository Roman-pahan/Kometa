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
    // Тело письма в лог не выводится: в письмах бывают ссылки восстановления,
    // а по такой ссылке входят в учётную запись. Логи хранятся дольше письма.
    console.log(`[mail] SMTP не настроен. Письмо для ${to} (${subject}) не отправлено.`);
    return { sent: false, reason: 'SMTP не настроен' };
  }
  const transport = nodemailer.createTransport({
    host: cfg.host, port: cfg.port, secure: cfg.secure, auth: cfg.auth,
  });
  await transport.sendMail({ from: cfg.from, to, subject, html, text });
  return { sent: true };
}

// Проверка соединения с SMTP: показывает, что именно сохранено и что отвечает
// сервер. Пароль наружу не отдаётся — только длина, чтобы поймать лишний пробел
// или обрезанный при копировании ключ.
async function diagnose() {
  const cfg = smtpConfig();
  const pass = getSetting('smtp_pass') || '';
  const info = {
    host: cfg ? cfg.host : null,
    port: cfg ? cfg.port : Number(getSetting('smtp_port')) || null,
    secure: cfg ? cfg.secure : null,
    user: cfg ? cfg.auth.user : null,
    from: cfg ? cfg.from : null,
    pass_set: !!pass,
    pass_len: pass.length,
    // Пробелы по краям — частая причина отказа: их не видно в поле ввода
    pass_has_spaces: pass !== pass.trim(),
  };
  if (!cfg) return { ...info, verify: 'not_configured' };
  const transport = nodemailer.createTransport({
    host: cfg.host, port: cfg.port, secure: cfg.secure, auth: cfg.auth, connectionTimeout: 10000,
  });
  try {
    await transport.verify();
    return { ...info, verify: 'ok' };
  } catch (e) {
    return { ...info, verify: 'failed', error: e.message, code: e.code || null };
  }
}

module.exports = { sendMail, isConfigured, diagnose };
