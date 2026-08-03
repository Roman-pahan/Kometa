// Шифрование файлов верификации на диске (AES-256-GCM).
// Ключ хранится ОТДЕЛЬНО от папки data: файл secret.key в корне проекта
// (или переменная окружения UPLOADS_KEY с 64 hex-символами — приоритетнее).
// Если украдут папку data с фото и базой — без ключа файлы не расшифровать.
// ВАЖНО: сделайте резервную копию secret.key. Потеря ключа = потеря всех фото.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const KEY_FILE = path.join(__dirname, 'secret.key');

function loadKey() {
  const env = (process.env.UPLOADS_KEY || '').trim();
  if (/^[0-9a-f]{64}$/i.test(env)) return Buffer.from(env, 'hex');
  if (fs.existsSync(KEY_FILE)) {
    const hex = fs.readFileSync(KEY_FILE, 'utf8').trim();
    if (/^[0-9a-f]{64}$/i.test(hex)) return Buffer.from(hex, 'hex');
    throw new Error('secret.key повреждён: ожидается 64 hex-символа');
  }
  const key = crypto.randomBytes(32);
  fs.writeFileSync(KEY_FILE, key.toString('hex'), 'utf8');
  console.log(`[secure-store] Создан новый ключ шифрования файлов: ${KEY_FILE} — сохраните его резервную копию!`);
  return key;
}

const KEY = loadKey();

// Формат файла: iv(12) | authTag(16) | ciphertext
function encryptBuffer(buf) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const ct = Buffer.concat([cipher.update(buf), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]);
}

function decryptBuffer(buf) {
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const ct = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

// Отдельный ключ для печатей целостности, выведенный из основного.
// Так подпись и шифрование не используют один и тот же ключ.
const SEAL_KEY = crypto.createHmac('sha256', KEY).update('order-seal-v1').digest();

// Печать по содержимому: любое изменение данных делает её недействительной.
// Ключ лежит вне базы, поэтому переписать строку и пересчитать печать
// не получится даже при полном доступе к файлу базы.
function sealData(value) {
  return crypto.createHmac('sha256', SEAL_KEY).update(String(value)).digest('hex');
}

// Проверка печати за постоянное время, чтобы не подсказывать подбор
function verifySeal(value, seal) {
  const expected = Buffer.from(sealData(value), 'hex');
  const supplied = Buffer.from(String(seal || ''), 'hex');
  if (expected.length !== supplied.length) return false;
  return crypto.timingSafeEqual(expected, supplied);
}

// Отпечаток содержимого файла: ловит подмену картинки на диске
function hashBuffer(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

module.exports = { encryptBuffer, decryptBuffer, sealData, verifySeal, hashBuffer };
