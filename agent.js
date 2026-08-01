// Связь с Python-агентом (расчёт сделок и реальные рыночные курсы).
// Агент работает отдельным сервисом и отвечает только на чтение:
// он ничего не пишет клиентам и не совершает торговых операций.
// Если агент недоступен, сайт продолжает работать на прежней логике.

const { getSetting } = require('./db');

// Запас по времени рассчитан на бесплатный тариф Render: уснувший сервис
// просыпается около минуты, и запрос не должен обрываться раньше.
const TIMEOUT_MS = 60000;

function agentConfig() {
  const url = (getSetting('agent_url') || '').trim().replace(/\/+$/, '');
  const token = getSetting('agent_token') || '';
  if (!url || !token) return null;
  return { url, token };
}

function isConfigured() {
  return !!agentConfig();
}

async function agentFetch(path, options = {}) {
  const cfg = agentConfig();
  if (!cfg) throw new Error('Агент не настроен');
  const res = await fetch(cfg.url + path, {
    ...options,
    headers: { 'X-Agent-Token': cfg.token, ...(options.headers || {}) },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Агент ответил ${res.status}`);
  return data;
}

// Рыночные курсы: 1 USDT в THB (Bitkub) и в RUB (стакан Bybit P2P)
async function fetchRates({ withBybit = true } = {}) {
  return agentFetch('/rates' + (withBybit ? '' : '?no_bybit=1'));
}

// Расчёт одной сделки: отчёт оператору и черновик ответа клиенту
async function calcDeal(payload) {
  return agentFetch('/deal', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

async function health() {
  const cfg = agentConfig();
  if (!cfg) throw new Error('Агент не настроен');
  const res = await fetch(cfg.url + '/health', { signal: AbortSignal.timeout(TIMEOUT_MS) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Агент ответил ${res.status}`);
  return data;
}

// Перевод направления сайта в направление, понятное правилам агента
function directionForAgent(fromCur, toCur) {
  if (fromCur === 'RUB' && toCur === 'THB') return 'rub_to_thb';
  if (fromCur === 'THB' && toCur === 'RUB') return 'thb_to_rub';
  if (fromCur === 'USDT' && toCur === 'THB') return 'usdt_to_thb';
  if (fromCur === 'THB' && toCur === 'USDT') return 'thb_to_usdt';
  return null;
}

module.exports = { fetchRates, calcDeal, health, isConfigured, directionForAgent };
