// Автоматическое получение базовых курсов.
// Источник: open.er-api.com (бесплатно, без ключа) — курсы валют к USD.
// USDT считается равным USD (1:1).

const { getSetting, setSetting } = require('./db');

const REFRESH_MS = 15 * 60 * 1000; // раз в 15 минут

let baseRates = null;   // { THB: 36.2, RUB: 79.5, CNY: 7.1, USD: 1, USDT: 1, ... }
let updatedAt = null;

// Восстановление после перезапуска
try {
  const saved = getSetting('base_rates');
  if (saved) {
    const parsed = JSON.parse(saved);
    baseRates = parsed.rates;
    updatedAt = parsed.updatedAt;
  }
} catch (_) { /* игнорируем битые данные */ }

async function refreshRates() {
  const res = await fetch('https://open.er-api.com/v6/latest/USD');
  if (!res.ok) throw new Error(`rates API HTTP ${res.status}`);
  const data = await res.json();
  if (data.result !== 'success' || !data.rates) throw new Error('rates API: bad payload');
  baseRates = { ...data.rates, USDT: 1 };
  updatedAt = new Date().toISOString();
  setSetting('base_rates', JSON.stringify({ rates: baseRates, updatedAt }));
  return { updatedAt };
}

function startAutoRefresh() {
  refreshRates().catch(err => console.error('[rates] первичная загрузка не удалась:', err.message));
  setInterval(() => {
    refreshRates().catch(err => console.error('[rates] обновление не удалось:', err.message));
  }, REFRESH_MS).unref();
}

// Кросс-курс: сколько to_cur даёт 1 единица from_cur (без наценки)
function crossRate(fromCur, toCur) {
  if (!baseRates) return null;
  const from = baseRates[fromCur];
  const to = baseRates[toCur];
  if (!from || !to) return null;
  return to / from;
}

// Итоговый курс направления с учётом наценки или ручного курса
function directionRate(dir) {
  if (dir.manual_rate != null && dir.manual_rate > 0) {
    return { rate: dir.manual_rate, source: 'manual', base: crossRate(dir.from_cur, dir.to_cur) };
  }
  const base = crossRate(dir.from_cur, dir.to_cur);
  if (base == null) return { rate: null, source: 'none', base: null };
  const rate = base * (1 - dir.markup_pct / 100);
  return { rate, source: 'auto', base };
}

function ratesInfo() {
  return { updatedAt, hasRates: !!baseRates };
}

module.exports = { refreshRates, startAutoRefresh, directionRate, crossRate, ratesInfo };
