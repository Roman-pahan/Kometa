// Ограничение частоты запросов и стоимость проверки пароля.
//
// Две отдельные беды решаются здесь вместе, потому что у них общая причина.
// Первая: пароль можно было подбирать бесконечно — ни задержки, ни блокировки.
// Вторая: проверка пароля считалась синхронно, а сервер в Node один на всех,
// и на время счёта он не отвечал больше никому. Десятка запросов на вход
// хватало, чтобы витрина перестала открываться.
//
// Счётчики живут в памяти. Сервис работает одним экземпляром, поэтому этого
// достаточно, и ради него не нужно ни новой зависимости, ни внешнего хранилища.

const crypto = require('crypto');

// Адрес клиента. За Cloudflare настоящий адрес приходит отдельным заголовком:
// без него все посетители выглядели бы одним и тем же адресом узла сети.
function clientIp(req) {
  const viaCloudflare = String(req.headers['cf-connecting-ip'] || '').trim();
  return viaCloudflare || req.ip || '';
}

// ---------- Счётчик попыток ----------

// Одна корзина на ключ: сколько попыток и когда окно началось
const buckets = new Map();

// Корзины подчищаются лениво, чтобы карта не росла от разовых посетителей
let lastSweep = Date.now();
function sweep(now) {
  if (now - lastSweep < 60 * 1000) return;
  lastSweep = now;
  for (const [key, bucket] of buckets) {
    if (bucket.until <= now) buckets.delete(key);
  }
}

// Засчитывает попытку. Возвращает, сколько секунд ждать, или 0 — можно.
function hit(key, limit, windowMs) {
  const now = Date.now();
  sweep(now);
  const bucket = buckets.get(key);
  if (!bucket || bucket.until <= now) {
    buckets.set(key, { count: 1, until: now + windowMs });
    return 0;
  }
  bucket.count++;
  if (bucket.count <= limit) return 0;
  return Math.ceil((bucket.until - now) / 1000);
}

// Успешный вход снимает накопленные попытки: человек, который просто забыл
// пароль и вспомнил его с третьего раза, не должен ждать четверть часа.
function reset(key) {
  buckets.delete(key);
}

// Готовая прослойка. `by` возвращает, что считать: адрес, почту, номер клиента.
function rateLimit({ name, limit, windowMs, by = clientIp, message }) {
  return (req, res, next) => {
    const subject = by(req);
    // Считать нечего — пропускаем: это забота проверки самих данных, не счётчика
    if (subject === null || subject === undefined || subject === '') return next();
    const wait = hit(`${name}:${subject}`, limit, windowMs);
    if (!wait) return next();
    res.setHeader('Retry-After', String(wait));
    return res.status(429).json({
      error: message || `Слишком много попыток. Попробуйте через ${Math.ceil(wait / 60)} мин.`,
    });
  };
}

// ---------- Пароли ----------

// Ровно те же параметры, что у scryptSync по умолчанию, поэтому хеши, посчитанные
// прежней версией, продолжают сходиться. Меняется только то, что счёт уходит
// в отдельный поток и не останавливает сервер.
const KEY_LENGTH = 64;

// Сколько проверок пароля разрешено считать одновременно. Дальше очередь растёт,
// а вместе с ней и время ответа всем остальным, поэтому лишним отвечаем отказом.
const MAX_PARALLEL_HASHES = 8;
let hashesInFlight = 0;

class TooBusyError extends Error {
  constructor() {
    super('Сервер занят, повторите через несколько секунд');
    this.tooBusy = true;
  }
}

function hashPassword(password, salt) {
  return new Promise((resolve, reject) => {
    if (hashesInFlight >= MAX_PARALLEL_HASHES) return reject(new TooBusyError());
    hashesInFlight++;
    crypto.scrypt(String(password), String(salt), KEY_LENGTH, (err, key) => {
      hashesInFlight--;
      if (err) return reject(err);
      resolve(key.toString('hex'));
    });
  });
}

// Тот же расчёт, но синхронный: нужен один раз при первом запуске, когда
// сервер ещё никого не обслуживает и блокировать нечего.
function hashPasswordSync(password, salt) {
  return crypto.scryptSync(String(password), String(salt), KEY_LENGTH).toString('hex');
}

// Сравнение за постоянное время, чтобы по длительности ответа нельзя было
// угадывать хеш посимвольно.
async function verifyPassword(password, salt, expectedHex) {
  const expected = Buffer.from(String(expectedHex || ''), 'hex');
  const actual = Buffer.from(await hashPassword(password, salt), 'hex');
  if (expected.length !== actual.length) return false;
  return crypto.timingSafeEqual(expected, actual);
}

module.exports = {
  clientIp, rateLimit, reset, hit,
  hashPassword, hashPasswordSync, verifyPassword, TooBusyError,
};
