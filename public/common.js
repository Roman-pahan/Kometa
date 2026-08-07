// Общие функции для всех страниц

async function api(url, method = 'GET', body) {
  const res = await fetch(url, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Ошибка ${res.status}`);
  return data;
}

// ---------- Учёт рекламного трафика ----------
// Страница сообщает серверу, что её открыли, и что нажали на кнопку.
// Внешний вид и поведение сайта при этом не меняются: если запрос не прошёл,
// посетитель этого не замечает.
function trackEvent(event) {
  try {
    const ref = new URLSearchParams(location.search).get('ref') || '';
    // keepalive нужен для клика по ссылке: браузер иначе бросает запрос при уходе
    fetch('/api/track', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ref, event, path: location.pathname }),
      keepalive: true,
    }).catch(() => {});
  } catch (_) { /* счётчик не должен мешать работе страницы */ }
}

// Кнопки, по которым видно намерение: расчёт обмена и уход в Telegram
function trackClicks() {
  document.addEventListener('click', (e) => {
    const el = e.target.closest('a, button');
    if (!el) return;
    const href = (el.getAttribute('href') || '');
    if (/t\.me\//.test(href)) return trackEvent('telegram_click');
    if (['createOrderBtn', 'submitOrderBtn', 'recapSendBtn'].includes(el.id) || href === '#calc') {
      trackEvent('exchange_click');
    }
  }, true);
}

// Запускается на каждой странице сайта, кроме админки
if (!location.pathname.startsWith('/admin')) {
  trackEvent('visit');
  document.addEventListener('DOMContentLoaded', trackClicks);
}

const STATUS_LABELS = {
  new: 'Новая',
  processing: 'В работе',
  awaiting_payment: 'Ожидает оплаты',
  done: 'Выполнена',
  cancelled: 'Отменена',
};

function fmtAmount(n) {
  return Number(n).toLocaleString('ru-RU', { maximumFractionDigits: 2 });
}

function fmtRate(r) {
  if (r == null) return '—';
  if (r >= 100) return Number(r).toLocaleString('ru-RU', { maximumFractionDigits: 2 });
  if (r >= 1) return Number(r).toLocaleString('ru-RU', { maximumFractionDigits: 4 });
  return Number(r).toLocaleString('ru-RU', { maximumFractionDigits: 6 });
}

// Валюты на сайте показываются значками, а не кодами
const CUR_SIGNS = { RUB: '₽', THB: '฿', USDT: '₮', CNY: '¥', USD: '$', EUR: '€' };
function cur(code) {
  return CUR_SIGNS[String(code || '').toUpperCase()] || code;
}

// Курс всегда пишется той стороной, где число больше единицы: «1 ฿ = 2,43 ₽»
// читается, а «1 ₽ = 0,412111 ฿» — нет.
function rateText(dir) {
  if (dir.rate == null) return 'уточняйте';
  if (dir.rate >= 1) return `1 ${cur(dir.from_cur)} = ${fmtRate(dir.rate)} ${cur(dir.to_cur)}`;
  return `1 ${cur(dir.to_cur)} = ${fmtRate(1 / dir.rate)} ${cur(dir.from_cur)}`;
}

function fmtDate(s) {
  // SQLite отдаёт UTC "YYYY-MM-DD HH:MM:SS"
  const d = new Date(s.replace(' ', 'T') + 'Z');
  return d.toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// Подстановка названия сайта в логотип и заголовок вкладки
async function applySiteName() {
  try {
    const { site_name } = await api('/api/site');
    if (!site_name) return;
    document.querySelectorAll('#siteName, #footerName').forEach(el => { el.textContent = site_name; });
    document.title = document.title.replace('Kometa Exchange', site_name);
  } catch (_) { /* оставляем то, что в разметке */ }
}

// Отрисовка шапки с учётом авторизации
async function renderHeader(active) {
  let me = null;
  applySiteName();
  try { me = (await api('/api/me')).user; } catch (_) {}
  const nav = document.getElementById('nav');
  if (!nav) return me;
  const link = (href, text, key) =>
    `<a href="${href}" class="${active === key ? 'active' : ''}">${text}</a>`;
  let html = link('/', 'Обмен', 'index');
  if (me) {
    html += link('/cabinet.html', 'Мои заявки', 'cabinet');
    if (!me.is_admin) html += link('/chat.html', 'Чат 🔒', 'chat');
    if (me.is_admin) html += link('/admin.html', 'Админка', 'admin');
    html += `<span class="muted small">${esc(me.email)}</span>`;
    html += `<button class="btn small" id="logoutBtn">Выйти</button>`;
  } else {
    html += `<a href="/auth.html" class="btn small primary">Войти</a>`;
  }
  nav.innerHTML = html;
  const btn = document.getElementById('logoutBtn');
  if (btn) btn.onclick = async () => { await api('/api/logout', 'POST', {}); location.href = '/'; };
  return me;
}

function showMsg(el, text, kind = 'error') {
  el.className = 'msg ' + kind;
  el.textContent = text;
}
function hideMsg(el) { el.className = 'msg'; el.textContent = ''; }
