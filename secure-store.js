// Шифрование файлов верификации на диске (AES-256-GCM).
//
// Ключ ищется по порядку: переменная окружения UPLOADS_KEY (64 hex-символа),
// затем data/secret.key, затем secret.key в корне проекта — так лежали ключи
// у прежних установок. Новый ключ создаётся уже только в data/.
//
// Почему в data/, а не в корне: на сервере постоянный диск примонтирован
// именно туда. Ключ в корне проекта живёт до первого деплоя, а вместе с ним
// живут и все фото — после деплоя они превращаются в нечитаемый мусор.
//
// Если украдут папку data с фото и базой — без ключа файлы не расшифровать.
// ВАЖНО: сделайте резервную копию ключа. Потеря ключа = потеря всех фото.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = path.join(__dirname, 'data');
const KEY_FILE = path.join(DATA_DIR, 'secret.key');
const LEGACY_KEY_FILE = path.join(__dirname, 'secret.key');

// Откуда взялся ключ: от этого зависит, переживёт ли он деплой
let keySource = 'none';

function readKeyFile(file) {
  if (!fs.existsSync(file)) return null;
  const hex = fs.readFileSync(file, 'utf8').trim();
  if (/^[0-9a-f]{64}$/i.test(hex)) return Buffer.from(hex, 'hex');
  throw new Error(`${file} повреждён: ожидается 64 hex-символа`);
}

function loadKey() {
  const env = (process.env.UPLOADS_KEY || '').trim();
  if (/^[0-9a-f]{64}$/i.test(env)) {
    keySource = 'env';
    return Buffer.from(env, 'hex');
  }
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

  const onDisk = readKeyFile(KEY_FILE);
  if (onDisk) {
    keySource = 'disk';
    return onDisk;
  }
  // Ключ прежней установки: переносим на постоянный диск, чтобы он пережил деплой
  const legacy = readKeyFile(LEGACY_KEY_FILE);
  if (legacy) {
    fs.writeFileSync(KEY_FILE, legacy.toString('hex'), 'utf8');
    keySource = 'disk';
    console.log(`[secure-store] ключ перенесён на постоянный диск: ${KEY_FILE}`);
    return legacy;
  }
  const key = crypto.randomBytes(32);
  fs.writeFileSync(KEY_FILE, key.toString('hex'), 'utf8');
  keySource = 'disk';
  console.log(`[secure-store] создан новый ключ шифрования: ${KEY_FILE} — сохраните его резервную копию!`);
  return key;
}

const KEY = loadKey();

// Переживёт ли ключ перезапуск и деплой. Переменная окружения переживает
// всегда, файл — пока он лежит на постоянном диске. Пока ответ отрицательный,
// шифровать им что-либо долгоживущее нельзя: расшифровать будет нечем.
function keyIsPersistent() {
  return keySource === 'env' || keySource === 'disk';
}

// Отпечаток ключа: по нему видно, что ключ сменился, — а значит всё, что было
// зашифровано прежним, больше не читается. Сам ключ по отпечатку не восстановить.
function keyFingerprint() {
  return crypto.createHmac('sha256', KEY).update('key-fingerprint-v1').digest('hex').slice(0, 32);
}

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

// ---------- Секреты в базе ----------
// Пароль почты, токен Telegram-бота, секрет Google и токены доступа лежат в
// таблице настроек. Снимок базы уезжает на компьютер владельца и в резервные
// копии, поэтому в открытом виде хранить их нельзя: одна утечка файла базы
// открывала бы разом почту, бота и всё остальное.

const SECRET_PREFIX = 'enc:v1:';

function encryptSecret(text) {
  return SECRET_PREFIX + encryptBuffer(Buffer.from(String(text), 'utf8')).toString('base64');
}

// Значение без приставки — сохранённое ещё в открытом виде, отдаём как есть.
// Так старая база продолжает работать без единой ручной операции.
function decryptSecret(stored, label = '') {
  const value = String(stored ?? '');
  if (!value.startsWith(SECRET_PREFIX)) return value;
  try {
    return decryptBuffer(Buffer.from(value.slice(SECRET_PREFIX.length), 'base64')).toString('utf8');
  } catch (_) {
    // Ключ сменился. Роняет только эту настройку, а не весь сайт: без пароля
    // почты письма не уходят, но заявки принимаются как обычно.
    console.error(`[secure-store] не удалось расшифровать настройку ${label || '(без имени)'} — сменился ключ?`);
    return '';
  }
}

function isEncryptedSecret(stored) {
  return String(stored ?? '').startsWith(SECRET_PREFIX);
}

module.exports = {
  encryptBuffer, decryptBuffer, sealData, verifySeal, hashBuffer,
  encryptSecret, decryptSecret, isEncryptedSecret, keyIsPersistent, keyFingerprint,
};
