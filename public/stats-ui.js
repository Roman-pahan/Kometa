// Экран статистики рекламного трафика.
//
// Один и тот же модуль рисует вкладку в админке и кабинет маркетолога:
// разница только в праве заводить и править рекламные ссылки.
// Все цифры приходят с сервера — здесь только отображение.

function initStats(container, { manage = false } = {}) {
  container.innerHTML = `
    <div class="card">
      <div class="flex" style="flex-wrap:wrap; gap:10px">
        <button class="btn small" data-period="today">Сегодня</button>
        <button class="btn small" data-period="yesterday">Вчера</button>
        <button class="btn small" data-period="7">7 дней</button>
        <button class="btn small" data-period="30">30 дней</button>
        <button class="btn small" data-period="all">Всё время</button>
        <span class="grow"></span>
        <label class="muted small">с <input type="date" class="statsFrom" style="width:150px"></label>
        <label class="muted small">по <input type="date" class="statsTo" style="width:150px"></label>
        <select class="statsRef" style="width:auto; min-width:180px"></select>
        <button class="btn small primary statsApply">Показать</button>
        ${manage ? '<button class="btn small success newSourceBtn">Создать рекламную ссылку</button>' : ''}
      </div>
      <p class="muted small mt statsPeriodNote"></p>
      <div class="stat-tiles mt statsTiles"></div>
    </div>

    <div class="card mt">
      <div class="flex"><h2 style="font-size:18px">Посещения по дням</h2>
        <span class="grow"></span>
        <button class="btn small chartAsTable">Таблицей</button></div>
      <div class="statsChart"></div>
    </div>

    <div class="card mt">
      <div class="table-wrap">
        <table class="pin-actions">
          <thead>
            <tr>
              <th>Канал</th><th>ref</th><th>Ссылка</th>
              <th data-sort="visits">Посещений</th>
              <th data-sort="visitors">Уникальных</th>
              <th data-sort="repeat">Повторных</th>
              <th data-sort="today">Сегодня</th>
              <th data-sort="last7">7 дней</th>
              <th data-sort="last30">30 дней</th>
              <th data-sort="first_visit">Первый переход</th>
              <th data-sort="last_visit">Последний</th>
              <th></th>
            </tr>
          </thead>
          <tbody class="statsBody"></tbody>
        </table>
      </div>
      <p class="muted mt statsEmpty" style="display:none">Переходов пока не было.</p>
    </div>

    <div class="card mt">
      <div class="flex"><h2 style="font-size:18px">Переходы по каждой ссылке</h2>
        <span class="grow"></span>
        <button class="btn small refScale">Своя шкала у каждой</button></div>
      <p class="muted small mt refScaleNote"></p>
      <div class="refCharts mt"></div>
    </div>

    <div class="card mt sourceDetail" style="display:none"></div>

    ${manage ? `
      <!-- Создание и правка рекламной ссылки -->
      <div class="modal" id="sourceModal" role="dialog" aria-modal="true" aria-labelledby="sourceModalTitle">
        <div class="modal-card">
          <h3 id="sourceModalTitle">Создать рекламную ссылку</h3>
          <div class="grid2 mt">
            <label class="field"><span>Название Telegram-канала *</span><input id="srcTitle" placeholder="Русские в Таиланде"></label>
            <label class="field"><span>Значение ref *</span><input id="srcRef" placeholder="ru_thailand"></label>
          </div>
          <label class="field"><span>Комментарий</span><input id="srcComment" placeholder="Пост в канале, закреп на сутки"></label>
          <div class="grid2">
            <label class="field"><span>Стоимость рекламы, ₽</span><input id="srcCost" type="number" step="any" placeholder="необязательно"></label>
            <label class="field"><span>Дата размещения</span><input id="srcPlaced" type="date"></label>
          </div>
          <label class="check" id="srcEnabledRow" style="display:none">
            <input type="checkbox" id="srcEnabled" checked><span>Источник активен</span>
          </label>
          <p class="muted small" id="srcLinkPreview"></p>
          <div class="msg" id="srcMsg"></div>
          <div class="modal-actions">
            <button class="btn" type="button" id="srcCancel">Отмена</button>
            <button class="btn success" type="button" id="srcSave">Сохранить</button>
          </div>
        </div>
      </div>
    ` : ''}
  `;

  const $ = selector => container.querySelector(selector);
  const $$ = selector => container.querySelectorAll(selector);

  let data = { summary: null, sources: [], daily: [] };
  let sort = { key: 'visits', desc: true };
  let editing = null;

  // Дата в местном времени в виде YYYY-MM-DD со сдвигом на нужное число дней
  const localDate = (shiftDays = 0) => {
    const d = new Date(Date.now() + shiftDays * 86400000);
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  };
  const period = () => ({ from: $('.statsFrom').value, to: $('.statsTo').value });
  const tile = (label, value) =>
    `<div class="stat-tile"><div class="stat-value">${esc(String(value))}</div><div class="stat-label">${esc(label)}</div></div>`;

  async function load() {
    const { from, to } = period();
    const ref = $('.statsRef').value;
    const query = new URLSearchParams();
    if (from) query.set('from', from);
    if (to) query.set('to', to);
    if (ref && ref !== '__all__') query.set('ref', ref === '__direct__' ? '' : ref);
    data = await api('/api/admin/stats' + (query.toString() ? '?' + query : ''));
    renderTiles();
    renderChart();
    renderRefCharts();
    renderTable();
    renderRefFilter();
    $('.statsPeriodNote').textContent = (from || to)
      ? `Период: ${from || 'начало'} — ${to || 'сегодня'}`
      : 'Период: за всё время';
  }

  function renderTiles() {
    const s = data.summary;
    $('.statsTiles').innerHTML = [
      tile('Всего посещений', s.visits),
      tile('Уникальных посетителей', s.visitors),
      tile('Сегодня', s.today),
      tile('За 7 дней', s.last7),
      tile('За 30 дней', s.last30),
      tile('По рекламным ссылкам', s.from_ads),
      tile('Прямой трафик', s.direct),
    ].join('');
  }

  // ---------- Гистограмма по дням ----------
  //
  // Три ряда на каждый день: всего посещений, уникальных посетителей и переходов
  // в Telegram. Ряды стоят рядом, а не друг на друге: это не части одного целого,
  // а вложенные величины — уникальных всегда не больше, чем посещений.
  //
  // Числа над столбиками намеренно не пишутся: на трёх рядах за месяц это сотня
  // цифр, которые никто не читает. Значения даёт ось, наведение и вид таблицей.
  const SERIES = [
    { key: 'visits', cls: 's-visits', keyCls: 'k-visits', label: 'Всего посещений' },
    { key: 'visitors', cls: 's-visitors', keyCls: 'k-visitors', label: 'Уникальных' },
    { key: 'telegram_clicks', cls: 's-telegram', keyCls: 'k-telegram', label: 'Переходы в Telegram' },
  ];

  const num = value => Number(value) || 0;

  // Верх шкалы округляется до круглого числа, чтобы подписи оси читались
  function axisTop(peak) {
    if (peak <= 4) return Math.max(peak, 1);
    const step = Math.pow(10, Math.floor(Math.log10(peak)));
    return Math.ceil(peak / (step / 2)) * (step / 2);
  }

  function legend() {
    return '<div class="chart-legend">' + SERIES.map(series =>
      `<span class="chart-key"><i class="${series.keyCls}"></i>${series.label}</span>`).join('') + '</div>';
  }

  function buildChart(days, emptyText, options = {}) {
    if (!days.length) return `<p class="muted small">${emptyText}</p>`;
    const peak = Math.max(...days.flatMap(d => SERIES.map(s => num(d[s.key]))), 1);
    const top = options.top || axisTop(peak);
    // Три линии сетки: ноль, середина и верх шкалы
    const ticks = [0, top / 2, top];

    const axis = ticks.map(value =>
      `<span style="bottom:${value / top * 100}%">${fmtAmount(value)}</span>`).join('');
    const grid = ticks.map(value =>
      `<div class="chart-gridline" style="bottom:${value / top * 100}%"></div>`).join('');

    const columns = days.map(d => {
      const values = SERIES.map(series => num(d[series.key]));
      const bars = SERIES.map((series, i) =>
        `<div class="chart-bar ${series.cls}" style="height:${values[i] / top * 100}%"></div>`).join('');
      // Значения едут в data-атрибуте: подсказка собирается из них при наведении
      return `<div class="chart-group" data-day="${esc(d.day)}" data-values="${values.join(',')}">${bars}</div>`;
    }).join('');

    const labels = days.map(d => `<span class="chart-xlabel">${esc(d.day.slice(5))}</span>`).join('');

    return `<div class="chart-wrap">${options.legend === false ? '' : legend()}
      <div class="chart-plot">
        <div class="chart-axis">${axis}</div>
        <div class="chart-scroll"><div class="chart-canvas">
          <div class="chart-grid">${grid}</div>
          <div class="chart-days">${columns}</div>
          <div class="chart-xlabels">${labels}</div>
        </div></div>
      </div>
      <div class="chart-tip"></div>
    </div>`;
  }

  // Подсказка при наведении: день и все три значения сразу
  function wireChart(root) {
    root.querySelectorAll('.chart-wrap').forEach(wireOneChart);
  }

  function wireOneChart(wrap) {
    const tip = wrap.querySelector('.chart-tip');
    if (!tip) return;
    wrap.querySelectorAll('.chart-group').forEach(group => {
      group.onmouseenter = () => {
        const values = group.dataset.values.split(',');
        tip.innerHTML = `<b>${esc(group.dataset.day)}</b>` + SERIES.map((series, i) =>
          `<span class="chart-key"><i class="${series.keyCls}"></i><em>${series.label}:</em>&nbsp;${values[i]}</span><br>`).join('');
        tip.style.display = 'block';
      };
      group.onmousemove = event => {
        const box = wrap.getBoundingClientRect();
        const left = event.clientX - box.left + 14;
        // У правого края подсказка разворачивается влево, чтобы не уезжать за карточку
        tip.style.left = Math.min(left, box.width - tip.offsetWidth - 8) + 'px';
        tip.style.top = Math.max(0, event.clientY - box.top - tip.offsetHeight - 12) + 'px';
      };
      group.onmouseleave = () => { tip.style.display = 'none'; };
    });
  }

  // Тот же набор цифр таблицей: график для взгляда, таблица для точности
  function buildDailyTable(days) {
    if (!days.length) return '<p class="muted small">За выбранный период переходов не было.</p>';
    return `<div class="table-wrap"><table>
      <thead><tr><th>День</th>${SERIES.map(s => `<th>${s.label}</th>`).join('')}</tr></thead>
      <tbody>${days.map(d => `<tr><td>${esc(d.day)}</td>${
        SERIES.map(s => `<td>${num(d[s.key])}</td>`).join('')}</tr>`).join('')}</tbody>
    </table></div>`;
  }

  // ---------- Отдельный график на каждую ссылку ----------
  //
  // Шкала по умолчанию общая на все ссылки: только тогда высоту столбиков
  // можно сравнивать между каналами. Кнопка переключает на свою шкалу у
  // каждой — так видно форму спроса у мелкого канала рядом с крупным.
  let refChartsOwnScale = false;

  function renderRefCharts() {
    const box = $('.refCharts');
    const rows = data.daily_by_ref || [];
    if (!rows.length) {
      box.innerHTML = '<p class="muted small">Переходов пока не было.</p>';
      $('.refScaleNote').textContent = '';
      return;
    }

    // Раскладываем строки по ссылкам
    const byRef = new Map();
    for (const row of rows) {
      if (!byRef.has(row.ref)) byRef.set(row.ref, []);
      byRef.get(row.ref).push(row);
    }

    // Название ссылки берём из таблицы источников, чтобы подписи совпадали
    const titleOf = ref => {
      const known = (data.sources || []).find(s => s.ref === ref);
      if (known) return known.title;
      return ref === '' ? 'Прямой трафик' : ref;
    };

    const panels = [...byRef.entries()].map(([ref, days]) => ({
      ref, days,
      total: days.reduce((sum, d) => sum + num(d.visits), 0),
      visitors: days.reduce((sum, d) => sum + num(d.visitors), 0),
      telegram: days.reduce((sum, d) => sum + num(d.telegram_clicks), 0),
    })).sort((a, b) => b.total - a.total);

    // Верх общей шкалы — по самому высокому дню среди всех ссылок
    const peak = Math.max(...rows.flatMap(d => SERIES.map(s => num(d[s.key]))), 1);
    const shared = axisTop(peak);

    $('.refScaleNote').textContent = refChartsOwnScale
      ? 'У каждой ссылки своя шкала: видно форму, но высоту столбиков между ссылками сравнивать нельзя.'
      : 'Шкала общая для всех ссылок — высоту столбиков можно сравнивать между собой.';
    $('.refScale').textContent = refChartsOwnScale ? 'Общая шкала' : 'Своя шкала у каждой';

    box.innerHTML = legend() + panels.map(panel => `
      <div class="ref-panel">
        <div class="flex">
          <b>${esc(titleOf(panel.ref))}</b>
          <span class="muted small">${panel.ref ? esc(panel.ref) : 'без метки'}</span>
          <span class="grow"></span>
          <span class="muted small">посещений ${panel.total} · уникальных ${panel.visitors} · в Telegram ${panel.telegram}</span>
        </div>
        ${buildChart(panel.days, 'Переходов за период не было.', { legend: false, top: refChartsOwnScale ? null : shared })}
      </div>`).join('');
    wireChart(box);
  }

  let chartAsTable = false;

  function renderChart() {
    const days = data.daily || [];
    const box = $('.statsChart');
    box.innerHTML = chartAsTable
      ? buildDailyTable(days)
      : buildChart(days, 'За выбранный период переходов не было.');
    if (!chartAsTable) wireChart(box);
    $('.chartAsTable').textContent = chartAsTable ? 'Графиком' : 'Таблицей';
  }

  function renderRefFilter() {
    const select = $('.statsRef');
    const current = select.value || '__all__';
    select.innerHTML = ['<option value="__all__">Все источники</option>', '<option value="__direct__">Прямой трафик</option>']
      .concat(data.sources.filter(s => s.ref).map(s => `<option value="${esc(s.ref)}">${esc(s.title)} (${esc(s.ref)})</option>`))
      .join('');
    select.value = [...select.options].some(o => o.value === current) ? current : '__all__';
  }

  function renderTable() {
    const rows = [...data.sources].sort((a, b) => {
      const x = a[sort.key], y = b[sort.key];
      const cmp = x == null ? -1 : y == null ? 1 : x > y ? 1 : x < y ? -1 : 0;
      return sort.desc ? -cmp : cmp;
    });
    $('.statsEmpty').style.display = rows.length ? 'none' : 'block';
    $('.statsBody').innerHTML = rows.map(r => `
      <tr data-ref="${esc(r.ref)}">
        <td>${esc(r.title)}${r.enabled ? '' : ' <span class="muted small">(выключен)</span>'}</td>
        <td class="muted small">${esc(r.ref || '—')}</td>
        <td class="muted small">${r.link ? `<button class="btn small copyLink" data-link="${esc(r.link)}">Скопировать</button>` : '—'}</td>
        <td><b>${r.visits}</b></td>
        <td>${r.visitors}</td>
        <td>${r.repeat}</td>
        <td>${r.today}</td>
        <td>${r.last7}</td>
        <td>${r.last30}</td>
        <td class="muted small">${r.first_visit ? fmtDate(r.first_visit) : '—'}</td>
        <td class="muted small">${r.last_visit ? fmtDate(r.last_visit) : '—'}</td>
        <td>
          <button class="btn small detailBtn">Подробно</button>
          ${manage && r.known && r.ref ? '<button class="btn small editBtn">Изменить</button>' : ''}
          ${manage && r.ref ? '<button class="btn small danger deleteBtn">Удалить</button>' : ''}
        </td>
      </tr>
    `).join('');

    $$('.copyLink').forEach(btn => {
      btn.onclick = async () => {
        try { await navigator.clipboard.writeText(btn.dataset.link); btn.textContent = 'Скопировано'; }
        catch (_) { prompt('Скопируйте ссылку', btn.dataset.link); }
        setTimeout(() => { btn.textContent = 'Скопировать'; }, 1500);
      };
    });
    $$('.detailBtn').forEach(btn => { btn.onclick = () => showDetail(btn.closest('tr').dataset.ref); });
    $$('.editBtn').forEach(btn => { btn.onclick = () => openModal(btn.closest('tr').dataset.ref); });

    // Удаление необратимо и уносит с собой всю статистику по ссылке,
    // поэтому в вопросе названы и канал, и то, что именно пропадёт.
    $$('.deleteBtn').forEach(btn => {
      btn.onclick = async () => {
        const row = btn.closest('tr');
        const ref = row.dataset.ref;
        const source = (data.sources || []).find(s => s.ref === ref);
        const known = source && source.known;
        const name = known ? `«${source.title}»` : `с меткой ${ref}`;
        if (!window.confirm(
          `Удалить ссылку ${name}?\n\n` +
          'Вместе с ней будут стёрты все её записи о посещениях за всё время.\n' +
          'Отменить это нельзя.\n\n' +
          'Если по этой метке уже ходили с вашего браузера, она вернётся при следующем\n' +
          'вашем заходе: метка помнится в браузере 30 дней. Почистите куки сайта.'
        )) return;
        try {
          const result = await api('/api/admin/sources/' + encodeURIComponent(ref), 'DELETE');
          alert(`Ссылка ${name} удалена. Записей стёрто: ${result.deleted_visits}.`);
          await load();
        } catch (e) { alert(e.message); }
      };
    });
  }

  function dailyChart(daily) {
    return buildChart(daily, 'Переходов за период не было.');
  }

  async function showDetail(ref) {
    const { from, to } = period();
    const query = new URLSearchParams();
    if (from) query.set('from', from);
    if (to) query.set('to', to);
    const d = await api(`/api/admin/stats/source/${encodeURIComponent(ref || 'direct')}` + (query.toString() ? '?' + query : ''));
    const box = $('.sourceDetail');
    const money = value => value == null ? '—' : fmtAmount(value) + ' ₽';
    box.style.display = 'block';
    box.innerHTML = `
      <div class="flex"><h2 style="font-size:18px">${esc(d.title)}${d.ref ? ` <span class="muted small">${esc(d.ref)}</span>` : ''}</h2>
        <span class="grow"></span><button class="btn small closeDetail">Закрыть</button></div>
      ${d.link ? `<p class="muted small">${esc(d.link)}</p>` : ''}
      <div class="stat-tiles mt">
        ${tile('Посещений', d.visits)}
        ${tile('Уникальных', d.visitors)}
        ${tile('Повторных', d.repeat)}
        ${tile('Нажали обмен', d.exchange_clicks)}
        ${tile('Ушли в Telegram', d.telegram_clicks)}
        ${tile('Доля нажавших обмен', d.exchange_rate + '%')}
        ${tile('Доля ушедших в Telegram', d.telegram_rate + '%')}
        ${tile('Стоимость рекламы', money(d.cost))}
        ${tile('Цена посетителя', money(d.cost_per_visitor))}
        ${tile('Цена перехода в Telegram', money(d.cost_per_telegram))}
      </div>
      <h2 style="font-size:16px" class="mt">Посещения по дням</h2>
      ${dailyChart(d.daily)}
    `;
    // Подсказка нужна и здесь: график тот же, просто по одному источнику
    wireChart(box);
    box.querySelector('.closeDetail').onclick = () => { box.style.display = 'none'; };
    box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // ---------- Создание и правка ссылок: только у администратора ----------
  function modal() { return document.getElementById('sourceModal'); }

  function openModal(ref) {
    editing = null;
    const box = modal();
    hideMsg(document.getElementById('srcMsg'));
    document.getElementById('srcEnabledRow').style.display = ref ? 'flex' : 'none';
    if (ref) {
      api('/api/admin/sources').then(({ sources }) => {
        editing = sources.find(s => s.ref === ref) || null;
        if (!editing) return;
        document.getElementById('sourceModalTitle').textContent = 'Изменить источник';
        document.getElementById('srcTitle').value = editing.title;
        document.getElementById('srcRef').value = editing.ref;
        document.getElementById('srcRef').disabled = true;
        document.getElementById('srcComment').value = editing.comment || '';
        document.getElementById('srcCost').value = editing.cost ?? '';
        document.getElementById('srcPlaced').value = editing.placed_on || '';
        document.getElementById('srcEnabled').checked = !!editing.enabled;
        document.getElementById('srcLinkPreview').textContent = 'Ссылка: ' + `${location.origin}/?ref=${editing.ref}`;
      });
    } else {
      document.getElementById('sourceModalTitle').textContent = 'Создать рекламную ссылку';
      ['srcTitle', 'srcRef', 'srcComment', 'srcCost', 'srcPlaced'].forEach(id => { document.getElementById(id).value = ''; });
      document.getElementById('srcRef').disabled = false;
      document.getElementById('srcLinkPreview').textContent = '';
    }
    box.classList.add('open');
  }

  if (manage) {
    $('.newSourceBtn').onclick = () => openModal(null);
    document.getElementById('srcCancel').onclick = () => modal().classList.remove('open');
    document.getElementById('srcRef').oninput = e => {
      const value = e.target.value.trim().toLowerCase().replace(/[^a-z0-9_\-]/g, '');
      document.getElementById('srcLinkPreview').textContent = value ? `Ссылка: ${location.origin}/?ref=${value}` : '';
    };
    document.getElementById('srcSave').onclick = async () => {
      const msg = document.getElementById('srcMsg');
      hideMsg(msg);
      const payload = {
        title: document.getElementById('srcTitle').value,
        comment: document.getElementById('srcComment').value,
        cost: document.getElementById('srcCost').value,
        placed_on: document.getElementById('srcPlaced').value,
      };
      try {
        if (editing) {
          payload.enabled = document.getElementById('srcEnabled').checked;
          await api('/api/admin/sources/' + editing.id, 'PATCH', payload);
        } else {
          payload.ref = document.getElementById('srcRef').value;
          const created = await api('/api/admin/sources', 'POST', payload);
          try { await navigator.clipboard.writeText(created.link); } catch (_) { /* скопирует вручную */ }
        }
        modal().classList.remove('open');
        await load();
      } catch (e) { showMsg(msg, e.message); }
    };
  }

  $$('[data-period]').forEach(btn => {
    btn.onclick = () => {
      const kind = btn.dataset.period;
      const from = $('.statsFrom'), to = $('.statsTo');
      if (kind === 'today') { from.value = localDate(0); to.value = localDate(0); }
      else if (kind === 'yesterday') { from.value = localDate(-1); to.value = localDate(-1); }
      else if (kind === '7') { from.value = localDate(-6); to.value = localDate(0); }
      else if (kind === '30') { from.value = localDate(-29); to.value = localDate(0); }
      else { from.value = ''; to.value = ''; }
      load().catch(e => alert(e.message));
    };
  });
  $('.statsApply').onclick = () => load().catch(e => alert(e.message));
  // Переключение график/таблица: те же цифры, разный способ смотреть
  $('.chartAsTable').onclick = () => { chartAsTable = !chartAsTable; renderChart(); };
  $('.refScale').onclick = () => { refChartsOwnScale = !refChartsOwnScale; renderRefCharts(); };
  $('.statsRef').onchange = () => load().catch(e => alert(e.message));
  $$('th[data-sort]').forEach(th => {
    th.style.cursor = 'pointer';
    th.onclick = () => {
      const key = th.dataset.sort;
      sort = { key, desc: sort.key === key ? !sort.desc : true };
      renderTable();
    };
  });

  return { load };
}
