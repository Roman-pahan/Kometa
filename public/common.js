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
    document.querySelectorAll('#siteName').forEach(el => { el.textContent = site_name; });
    document.title = document.title.replace('Обмен валют', site_name);
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
