// Вход через Google по протоколу OAuth 2.0.
//
// Работает без внешних библиотек и без скриптов Google на страницах сайта:
// пользователь уходит на страницу согласия Google и возвращается к нам с кодом,
// код меняется на токен запросом с сервера. Поэтому строгая политика
// безопасности страниц остаётся нетронутой.
//
// Ключи заводит администратор в настройках. Секрет наружу не отдаётся никогда.

const crypto = require('crypto');
const { getSetting } = require('./db');

const AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';

// Кука с одноразовым состоянием: она защищает от подделки ответа Google
const STATE_COOKIE = 'gstate';
const STATE_TTL_SECONDS = 600;

function config() {
  const id = (getSetting('google_client_id') || '').trim();
  const secret = (getSetting('google_client_secret') || '').trim();
  return id && secret ? { id, secret } : null;
}

function isConfigured() {
  return !!config();
}

// Адрес возврата должен совпадать с тем, что вписан в консоли Google
function redirectUri(req) {
  return `${req.protocol}://${req.get('host')}/api/auth/google/callback`;
}

// Ссылка на страницу согласия Google вместе с одноразовым состоянием
function authorizeUrl(req, res, next = '/') {
  const cfg = config();
  if (!cfg) return null;
  const state = crypto.randomBytes(16).toString('hex');
  const payload = Buffer.from(JSON.stringify({ state, next })).toString('base64url');
  const secure = req.secure ? ' Secure;' : '';
  res.setHeader('Set-Cookie',
    `${STATE_COOKIE}=${payload}; Path=/; HttpOnly;${secure} SameSite=Lax; Max-Age=${STATE_TTL_SECONDS}`);

  const params = new URLSearchParams({
    client_id: cfg.id,
    redirect_uri: redirectUri(req),
    response_type: 'code',
    scope: 'openid email profile',
    state,
    prompt: 'select_account',
  });
  return `${AUTH_URL}?${params}`;
}

// Проверка состояния из куки: значение должно совпасть с тем, что вернул Google
function readState(req, stateFromGoogle) {
  const raw = (req.headers.cookie || '').match(new RegExp(`(?:^|;\\s*)${STATE_COOKIE}=([^;]+)`));
  if (!raw) return null;
  try {
    const data = JSON.parse(Buffer.from(decodeURIComponent(raw[1]), 'base64url').toString('utf8'));
    if (!data.state || data.state !== stateFromGoogle) return null;
    return data;
  } catch (_) {
    return null;
  }
}

// Разбор середины id_token. Подпись не проверяется намеренно: токен получен
// прямым запросом к серверу Google по TLS, а не принят от браузера.
function readIdToken(idToken) {
  const parts = String(idToken || '').split('.');
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch (_) {
    return null;
  }
}

// Обмен кода на токен и получение почты пользователя
async function exchangeCode(req, code) {
  const cfg = config();
  if (!cfg) throw new Error('Вход через Google не настроен');
  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id: cfg.id,
      client_secret: cfg.secret,
      redirect_uri: redirectUri(req),
      grant_type: 'authorization_code',
    }),
  });
  const data = await res.json().catch(() => ({}));
  // Ответ Google не логируем целиком: в нём токены
  if (!res.ok) throw new Error('Google отклонил запрос: ' + (data.error || res.status));

  const claims = readIdToken(data.id_token);
  if (!claims || !claims.email) throw new Error('Google не вернул почту');
  // Почта должна быть подтверждена явно. Проверка именно на «истину», а не на
  // «не ложь»: отсутствующий признак — тоже неподтверждённая почта, а по чужому
  // адресу входят в чужой кабинет.
  if (claims.email_verified !== true && String(claims.email_verified) !== 'true') {
    throw new Error('Почта в аккаунте Google не подтверждена');
  }
  return { email: String(claims.email).toLowerCase().trim(), name: String(claims.name || '').trim() };
}

// Кука состояния одноразовая: после возврата её нужно погасить
function clearState(req, res) {
  const secure = req.secure ? ' Secure;' : '';
  const cookie = `${STATE_COOKIE}=; Path=/; HttpOnly;${secure} SameSite=Lax; Max-Age=0`;
  const current = res.getHeader('Set-Cookie');
  if (!current) return res.setHeader('Set-Cookie', cookie);
  res.setHeader('Set-Cookie', Array.isArray(current) ? current.concat(cookie) : [current, cookie]);
}

module.exports = { isConfigured, authorizeUrl, readState, exchangeCode, clearState, redirectUri };
