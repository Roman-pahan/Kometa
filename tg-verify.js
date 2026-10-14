'use strict';

// Бот верификации Kometa: приветствует клиента и открывает форму проверки
// прямо внутри Telegram (Mini App). Форма — страница этого же сайта, заявка
// ложится в ту же вкладку «Верификация» админки, что и из личного кабинета.
//
// Зачем бот, если есть кабинет: мутному клиенту, который пишет в Telegram,
// проще нажать «запустить бота», чем регистрироваться на сайте. Почта ему не
// нужна вовсе — кто он, подтверждает сам Telegram своей подписью.
//
// Бот свой, отдельный от того, что шлёт уведомления админу: у него один
// собеседник — клиент, и токен от @BotFather задаётся в TG_VERIFY_BOT_TOKEN.

const crypto = require('crypto');

const TG_API = 'https://api.telegram.org/bot';
const WEBHOOK_PATH = '/tg/verify-webhook';
// Страница формы. Тот же адрес задан кнопкой меню бота.
const APP_PATH = '/tg-verify.html';

// Данные запуска старше суток не принимаем: форму открывают и заполняют сразу,
// а старая подпись — это уже не тот, кто нажал кнопку сейчас.
const MAX_AGE_SEC = 24 * 60 * 60;

const token = () => (process.env.TG_VERIFY_BOT_TOKEN || '').trim();

// Секрет вебхука выводится из токена: отдельная переменная не нужна, а чужой
// запрос на адрес вебхука без него отбрасывается.
const webhookSecret = () => crypto.createHmac('sha256', 'kometa-verify-webhook').update(token()).digest('hex');

function checkString(params) {
  return [...params.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`)
    .join('\n');
}

/**
 * Проверяет данные запуска Mini App и возвращает пользователя Telegram.
 *
 * Telegram подписывает их токеном бота; не зная токена, подпись не подделать.
 * Сошлась — значит форму действительно открыл этот человек из нашего бота.
 * Алгоритм из документации Telegram:
 *   secret = HMAC_SHA256(key = "WebAppData", data = bot_token)
 *   hash   = hex(HMAC_SHA256(key = secret, data = поля без hash, по алфавиту, "k=v" через \n))
 */
function validateInitData(initData, botToken = token(), now = Date.now()) {
  if (!initData || !botToken) return { ok: false, reason: 'нет данных' };
  const params = new URLSearchParams(String(initData));
  const hash = params.get('hash');
  if (!hash || !/^[0-9a-f]{64}$/i.test(hash)) return { ok: false, reason: 'нет подписи' };
  params.delete('hash');

  const secret = crypto.createHmac('sha256', 'WebAppData').update(botToken).digest();
  const expected = crypto.createHmac('sha256', secret).update(checkString(params)).digest();
  const given = Buffer.from(hash, 'hex');
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) {
    return { ok: false, reason: 'подпись не сходится' };
  }

  const authDate = Number(params.get('auth_date'));
  if (!authDate || now / 1000 - authDate > MAX_AGE_SEC) return { ok: false, reason: 'данные запуска устарели' };

  let user = null;
  try { user = JSON.parse(params.get('user') || 'null'); } catch (_) { /* битый JSON */ }
  if (!user || !Number.isSafeInteger(user.id) || user.id <= 0) return { ok: false, reason: 'нет пользователя' };
  return { ok: true, user };
}

/** Подписанные данные запуска — только для тестов. */
function signInitData(fields, botToken) {
  const params = new URLSearchParams(fields);
  const secret = crypto.createHmac('sha256', 'WebAppData').update(botToken).digest();
  params.set('hash', crypto.createHmac('sha256', secret).update(checkString(params)).digest('hex'));
  return params.toString();
}

async function tg(method, body) {
  const r = await fetch(`${TG_API}${token()}/${method}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  });
  const j = await r.json().catch(() => ({}));
  if (!j.ok) throw new Error(`Telegram ${method}: ${j.description || r.status}`);
  return j.result;
}

const GREETING =
  'Здравствуйте! Это верификация Kometa Exchange.\n\n' +
  'Нажмите кнопку ниже: укажите ФИО и телефон, сфотографируйте паспорт и лицо с камеры. ' +
  'Проверка занимает немного времени — результат сообщит оператор.';

/** Отвечает на любое сообщение в личке приветствием с кнопкой формы. */
async function handleUpdate(update, appUrl) {
  const msg = update && update.message;
  // Бот работает только в личке: в группе форму с паспортом открывать незачем
  if (!msg || !msg.chat || msg.chat.type !== 'private') return;
  await tg('sendMessage', {
    chat_id: msg.chat.id,
    text: GREETING,
    reply_markup: { inline_keyboard: [[{ text: '🔐 Пройти верификацию', web_app: { url: appUrl } }]] },
  });
}

/**
 * Подключает вебхук бота к серверу и ставит кнопку меню.
 *
 * Без токена бот выключен, сайт работает как раньше. Mini App открывается
 * только по https, поэтому на локальном запуске вебхук и кнопка не ставятся.
 */
function mount(app, { baseUrl }) {
  if (!token()) {
    console.log('[tg-verify] выключен: нет TG_VERIFY_BOT_TOKEN');
    return;
  }
  const appUrl = baseUrl + APP_PATH;

  app.post(WEBHOOK_PATH, (req, res) => {
    const given = Buffer.from(String(req.get('X-Telegram-Bot-Api-Secret-Token') || ''));
    const expected = Buffer.from(webhookSecret());
    if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return res.sendStatus(401);
    res.sendStatus(200);
    handleUpdate(req.body, appUrl).catch(e => console.error('[tg-verify]', e.message));
  });

  // Без https Telegram не откроет форму — и в Telegram тогда идти незачем.
  // Заодно локальный запуск и тесты не трогают боевой вебхук бота.
  if (!/^https:\/\//.test(baseUrl)) {
    console.log(`[tg-verify] нужен https-адрес сайта в PUBLIC_URL (сейчас «${baseUrl}»), вебхук и кнопку не ставлю`);
    return;
  }

  (async () => {
    try {
      const me = await tg('getMe');
      await tg('setWebhook', {
        url: baseUrl + WEBHOOK_PATH,
        secret_token: webhookSecret(),
        allowed_updates: ['message'],
        drop_pending_updates: true,
      });
      await tg('setChatMenuButton', { menu_button: { type: 'web_app', text: 'Верификация', web_app: { url: appUrl } } });
      console.log(`[tg-verify] @${me.username} подключён, форма: ${appUrl}`);
    } catch (err) {
      console.error('[tg-verify] не удалось подключиться:', err.message);
    }
  })();
}

module.exports = { mount, validateInitData, signInitData, handleUpdate, webhookSecret, APP_PATH, WEBHOOK_PATH, isEnabled: () => !!token() };
