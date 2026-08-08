// Автоматическое получение базовых курсов.
// Официальные курсы: open.er-api.com (бесплатно, без ключа) — валюты к USD.
// Реальные рыночные курсы THB и RUB берутся у агента (Bitkub и стакан Bybit P2P),
// потому что официальный курс рубля далёк от того, по которому идут сделки.
// USDT считается равным USD (1:1).

const { getSetting, setSetting } = require('./db');

const agent = require('./agent');

const REFRESH_MS = 15 * 60 * 1000; // раз в 15 минут

let baseRates = null;   // { THB: 36.2, RUB: 79.5, CNY: 7.1, USD: 1, USDT: 1, ... }
let updatedAt = null;
let marketInfo = { used: false, usdt_thb: null, rub_usdt: null, at: null, error: null };
let marketMargins = null;   // { qr, tbank, global } — проценты, заданные в боте
// Готовые цены клиенту по направлениям, присланные ботом: { RUB_THB: 0.369, ... }
let clientRates = null;

// Восстановление после перезапуска
try {
  const saved = getSetting('base_rates');
  if (saved) {
    const parsed = JSON.parse(saved);
    baseRates = parsed.rates;
    updatedAt = parsed.updatedAt;
  }
} catch (_) { /* игнорируем битые данные */ }

// Цены, присланные ботом, действуют и сразу после перезапуска: они не зависят
// от того, удалось ли сходить за справочными курсами.
try { applyPushedBoard(); } catch (_) { /* пустой или битый набор */ }

// Последний набор курсов, присланный ботом оператора
function pushedBoard() {
  try {
    const saved = getSetting('agent_board');
    return saved ? JSON.parse(saved) : null;
  } catch (_) {
    return null;
  }
}

// Курсы, присланные ботом, живут до следующей проверки оператора и не зависят
// от того, доступен ли агент снаружи.
function applyPushedBoard() {
  const board = pushedBoard();
  if (!board) return false;
  // Цены клиенту приходят готовыми — сайт их не пересчитывает
  clientRates = board.client && typeof board.client === 'object' ? board.client : null;
  if (baseRates) {
    if (board.usdt_thb) baseRates.THB = board.usdt_thb;
    if (board.rub_usdt) baseRates.RUB = board.rub_usdt;
    if (board.cny_per_usdt) baseRates.CNY = board.cny_per_usdt;
  }
  marketMargins = board.margins || null;
  marketInfo = {
    used: true,
    source: 'bot',
    usdt_thb: board.usdt_thb ?? null,
    rub_usdt: board.rub_usdt ?? null,
    margins: marketMargins,
    at: board.received_at || null,
    error: null,
  };
  if (baseRates) setSetting('base_rates', JSON.stringify({ rates: baseRates, updatedAt: new Date().toISOString() }));
  return true;
}

// Подмена официальных курсов THB и RUB рыночными данными агента.
// Курсы у агента выражены в единицах за 1 USDT, а базовая таблица — за 1 USD,
// и поскольку USDT считается равным USD, значения подставляются напрямую.
async function applyMarketRates(rates) {
  // Присланный ботом набор важнее опроса: оператор подтвердил его вручную
  const board = pushedBoard();
  if (board && (board.usdt_thb || board.rub_usdt)) {
    if (board.usdt_thb) rates.THB = board.usdt_thb;
    if (board.rub_usdt) rates.RUB = board.rub_usdt;
    if (board.cny_per_usdt) rates.CNY = board.cny_per_usdt;
    clientRates = board.client && typeof board.client === 'object' ? board.client : null;
    marketMargins = board.margins || null;
    marketInfo = {
      used: true, source: 'bot',
      usdt_thb: board.usdt_thb ?? null, rub_usdt: board.rub_usdt ?? null,
      margins: marketMargins, at: board.received_at || null, error: null,
    };
    return rates;
  }
  if (!agent.isConfigured()) {
    marketInfo = { used: false, usdt_thb: null, rub_usdt: null, at: null, error: null };
    return rates;
  }
  try {
    const m = await agent.fetchRates();
    if (m.usdt_thb) rates.THB = m.usdt_thb;
    if (m.rub_usdt) rates.RUB = m.rub_usdt;
    // Маржу задаёт оператор в боте — сайт берёт её оттуда, чтобы цифра была одна
    marketMargins = m.margins || null;
    marketInfo = {
      source: 'agent',
      used: !!(m.usdt_thb || m.rub_usdt),
      usdt_thb: m.usdt_thb ?? null,
      rub_usdt: m.rub_usdt ?? null,
      margins: marketMargins,
      at: new Date().toISOString(),
      error: (m.warnings && m.warnings.length) ? m.warnings.join('; ') : null,
    };
  } catch (e) {
    // Агент недоступен — остаёмся на официальных курсах и наценках из админки
    marketMargins = null;
    marketInfo = { used: false, usdt_thb: null, rub_usdt: null, at: null, error: e.message };
    console.error('[rates] агент недоступен, используем официальные курсы:', e.message);
  }
  return rates;
}

async function refreshRates() {
  const res = await fetch('https://open.er-api.com/v6/latest/USD');
  if (!res.ok) throw new Error(`rates API HTTP ${res.status}`);
  const data = await res.json();
  if (data.result !== 'success' || !data.rates) throw new Error('rates API: bad payload');
  baseRates = await applyMarketRates({ ...data.rates, USDT: 1 });
  updatedAt = new Date().toISOString();
  setSetting('base_rates', JSON.stringify({ rates: baseRates, updatedAt }));
  return { updatedAt, market: marketInfo };
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

// Цена клиенту по направлению, посчитанная оператором в боте.
// Где направление обслуживают несколько каналов, бот уже выбрал самый дешёвый
// для клиента, поэтому здесь ничего не пересчитывается.
function pushedRate(dir) {
  if (!clientRates) return null;
  const value = Number(clientRates[`${dir.from_cur}_${dir.to_cur}`]);
  return Number.isFinite(value) && value > 0 ? value : null;
}

// Итоговый курс направления.
// Порядок один и тот же везде: ручной курс из админки, затем цена оператора.
// Своего курса сайт не выдумывает: справочные курсы валют не имеют отношения
// к тому, почём стол реально покупает и продаёт, и по ним легко уйти в минус.
function directionRate(dir) {
  const base = crossRate(dir.from_cur, dir.to_cur);
  if (dir.manual_rate != null && dir.manual_rate > 0) {
    return { rate: dir.manual_rate, source: 'manual', base };
  }
  const pushed = pushedRate(dir);
  if (pushed != null) return { rate: pushed, source: 'bot', base };
  // Направление, которое стол не котирует, честно считается «по запросу»
  return { rate: null, source: 'on_request', base };
}

function ratesInfo() {
  // Возраст цены — это момент проверки курса оператором, а не время,
  // когда сайт последний раз ходил за справочными курсами
  const at = (clientRates && marketInfo.at) || updatedAt;
  return { updatedAt: at, hasRates: !!(clientRates || baseRates), market: marketInfo };
}

module.exports = { refreshRates, startAutoRefresh, directionRate, crossRate, ratesInfo, applyPushedBoard };
