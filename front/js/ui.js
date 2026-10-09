(function () {
  // Garante o @keyframes slideInToast uma única vez (para páginas que não o tenham
  // no próprio <style>). Idempotente.
  function ensureToastKeyframes() {
    if (document.getElementById('_ui_toast_kf')) return;
    const s = document.createElement('style');
    s.id = '_ui_toast_kf';
    s.textContent = '@keyframes slideInToast{from{transform:translateX(40px);opacity:0}to{transform:translateX(0);opacity:1}}';
    document.head.appendChild(s);
  }

  function showToast(msg, type = 'info') {
    ensureToastKeyframes();
    let c = document.getElementById('_tc');
    if (!c) {
      c = document.createElement('div');
      c.id = '_tc';
      c.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:8px;';
      document.body.appendChild(c);
    }
    const colors = { success:'#10b981', error:'#ef4444', warning:'#f59e0b', info:'#3b82f6' };
    const t = document.createElement('div');
    t.style.cssText = `background:${colors[type]||colors.info};color:#fff;padding:12px 18px;border-radius:12px;font-size:13px;font-weight:600;animation:slideInToast 0.3s ease;box-shadow:0 4px 20px rgba(0,0,0,0.3);max-width:320px;`;
    t.textContent = msg;
    c.appendChild(t);
    setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity 0.3s'; setTimeout(() => t.remove(), 300); }, 3500);
  }

  function setLoading(btn, isLoading) {
    if (!btn) return;
    if (isLoading) {
      if (btn.dataset.uiLoading === '1') return;
      btn.dataset.uiLoading = '1';
      btn._uiOrigHtml = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '<span class="inline-block w-4 h-4 border-2 border-white/40 border-t-white rounded-full animate-spin align-[-2px]"></span>';
    } else {
      if (btn.dataset.uiLoading !== '1') return;
      btn.disabled = false;
      if (btn._uiOrigHtml != null) btn.innerHTML = btn._uiOrigHtml;
      delete btn.dataset.uiLoading;
      delete btn._uiOrigHtml;
    }
  }

  function ensureModalKeyframes() {
    if (document.getElementById('_ui_modal_kf')) return;
    const s = document.createElement('style');
    s.id = '_ui_modal_kf';
    s.textContent = '@keyframes modalIn{from{opacity:0;transform:scale(0.96)}to{opacity:1;transform:scale(1)}}';
    document.head.appendChild(s);
  }

  // showConfirm({title, message, confirmText, cancelText, danger}) -> Promise<boolean>
  // Substitui o confirm() nativo. Aceita string como atalho: showConfirm('texto').
  function showConfirm(opts) {
    ensureModalKeyframes();
    if (typeof opts === 'string') opts = { message: opts };
    opts = opts || {};
    const title = opts.title || 'Confirmar ação';
    const message = opts.message || '';
    const confirmText = opts.confirmText || 'Confirmar';
    const cancelText = opts.cancelText || 'Cancelar';
    const danger = !!opts.danger;

    return new Promise((resolve) => {
      const back = document.createElement('div');
      back.className = 'modal-backdrop';
      back.style.cssText = 'position:fixed;inset:0;z-index:10000;display:flex;align-items:center;justify-content:center;padding:16px;background:rgba(5,11,20,0.7);backdrop-filter:blur(8px);';

      const panel = document.createElement('div');
      panel.className = 'modal-panel';
      panel.setAttribute('role', 'dialog');
      panel.setAttribute('aria-modal', 'true');
      panel.style.cssText = 'max-width:420px;width:100%;padding:24px;animation:modalIn 0.2s ease-out;';

      const h = document.createElement('div');
      h.style.cssText = 'font-size:18px;font-weight:700;color:var(--text-primary,#e2e8f0);';
      h.textContent = title;

      const p = document.createElement('div');
      p.style.cssText = 'margin-top:8px;font-size:14px;line-height:1.5;color:var(--text-secondary,#94a3b8);white-space:pre-line;';
      p.textContent = message;

      const row = document.createElement('div');
      row.style.cssText = 'margin-top:20px;display:flex;gap:10px;justify-content:flex-end;';

      const btnCancel = document.createElement('button');
      btnCancel.type = 'button';
      btnCancel.textContent = cancelText;
      btnCancel.style.cssText = 'padding:9px 16px;border-radius:10px;font-size:13px;font-weight:600;cursor:pointer;border:1px solid var(--line-strong,rgba(148,163,184,0.25));background:transparent;color:var(--text-secondary,#94a3b8);';

      const btnOk = document.createElement('button');
      btnOk.type = 'button';
      btnOk.textContent = confirmText;
      const okBg = danger ? 'var(--rose,#ef4444)' : 'var(--accent,#3b82f6)';
      btnOk.style.cssText = `padding:9px 16px;border-radius:10px;font-size:13px;font-weight:600;cursor:pointer;border:none;background:${okBg};color:#fff;`;

      row.appendChild(btnCancel);
      row.appendChild(btnOk);
      panel.appendChild(h);
      panel.appendChild(p);
      panel.appendChild(row);
      back.appendChild(panel);
      document.body.appendChild(back);
      btnOk.focus();

      function close(result) {
        document.removeEventListener('keydown', onKey);
        back.remove();
        resolve(result);
      }
      function onKey(e) {
        if (e.key === 'Escape') { e.preventDefault(); close(false); }
        else if (e.key === 'Enter') { e.preventDefault(); close(true); }
      }
      btnCancel.addEventListener('click', () => close(false));
      btnOk.addEventListener('click', () => close(true));
      back.addEventListener('click', (e) => { if (e.target === back) close(false); });
      document.addEventListener('keydown', onKey);
    });
  }

  // updatePager({page, count, limit, prevBtn, nextBtn, infoEl, noun}) -> {page, hasPrev, hasNext}
  // Atualiza o estado dos botoes prev/next e o texto de info de paginacao.
  // Modelo "pagina cheia": ha proxima enquanto count >= limit. prevBtn/nextBtn/
  // infoEl podem ser id (string) ou o proprio elemento.
  function updatePager(o) {
    o = o || {};
    const el = (x) => (typeof x === 'string' ? document.getElementById(x) : x);
    const page = o.page || 1;
    const count = o.count || 0;
    const limit = o.limit || 50;
    const noun = o.noun || 'registro';
    const prevBtn = el(o.prevBtn);
    const nextBtn = el(o.nextBtn);
    const infoEl = el(o.infoEl);
    // hasMore explícito (vindo do backend) evita o "próxima página vazia" quando
    // o total é múltiplo exato do limite; sem ele, cai no palpite count>=limit.
    const hasNext = (o.hasMore != null) ? !!o.hasMore : (count >= limit);
    if (prevBtn) prevBtn.disabled = page <= 1;
    if (nextBtn) nextBtn.disabled = !hasNext;
    if (infoEl) infoEl.textContent = `Página ${page} — ${count} ${noun}${count !== 1 ? 's' : ''}`;
    return { page, hasPrev: page > 1, hasNext };
  }

  function syncBadge(status, error, at) {
    const st = status || 'pending';
    const cls = st === 'success' ? 'chip-emerald' : (st === 'error' ? 'chip-rose' : 'chip-slate');
    const label = st === 'success' ? 'Sync OK' : (st === 'error' ? 'Sync erro' : 'Sync pendente');
    // Monta o tooltip com o horário do último sync (UTC→America/Recife) e o erro,
    // quando houver. `at` é opcional — chamadas antigas (status, error) seguem OK.
    const parts = [];
    if (at) {
      try {
        const s = String(at);
        const iso = /[zZ]|[+\-]\d\d:?\d\d$/.test(s) ? s : s + 'Z';
        const d = new Date(iso);
        if (!isNaN(d.getTime())) parts.push('Último sync: ' + d.toLocaleString('pt-BR', { timeZone: 'America/Recife' }));
      } catch (e) { /* data inválida: ignora */ }
    }
    if (error) parts.push(String(error));
    const title = parts.length ? ` title="${parts.join(' — ').replace(/"/g, '&quot;')}"` : '';
    return `<span${title} class="text-xs font-semibold px-1.5 py-0.5 rounded ${cls}">${label}</span>`;
  }

  function exportCsv(filename, rows, headers) {
    const esc = (v) => {
      const s = v == null ? '' : String(v);
      return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    };
    const matrix = [];
    if (headers && headers.length) matrix.push(headers);
    for (const r of (rows || [])) {
      matrix.push(Array.isArray(r) ? r : (headers ? headers.map(h => r[h]) : Object.values(r)));
    }
    const csv = matrix.map(row => row.map(esc).join(',')).join('\r\n');
    const blob = new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename.endsWith('.csv') ? filename : filename + '.csv';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // ── Temas / Aparência ──────────────────────────────────────────────────────
  // Cada tema é uma string de classes para o <html>: a 1ª é o modo (dark/light,
  // que mantém o Tailwind dark: e os tokens-base); a 2ª (.t-*) é a paleta.
  const THEMES = [
    { cls: 'dark',         name: 'Azul',      mode: 'escuro',     dot: '#5EB4C7', bg: '#08101C' },
    { cls: 'light',        name: 'Azul',      mode: 'claro',      dot: '#0891B2', bg: '#F4F7FB' },
    { cls: 'dark t-rosa',  name: 'Rosa',      mode: 'escuro',     dot: '#E8709E', bg: '#160A12' },
    { cls: 'light t-rosa', name: 'Rosa',      mode: 'claro',      dot: '#D6336C', bg: '#FFF5F9' },
    { cls: 'dark t-mono',  name: 'Preto',     mode: 'mono',       dot: '#E5E5E7', bg: '#0A0A0B' },
    { cls: 'light t-mono', name: 'Branco',    mode: 'mono',       dot: '#111113', bg: '#FFFFFF' },
    { cls: 'dark t-roxo',  name: 'Roxo',      mode: 'escuro',     dot: '#9B7BE8', bg: '#120A1E' },
    { cls: 'light t-lav',  name: 'Lavanda',   mode: 'claro',      dot: '#7C6BC4', bg: '#F3F0FB' },
    { cls: 'dark t-esm',   name: 'Esmeralda', mode: 'escuro',     dot: '#4FBF9B', bg: '#06140F' },
    { cls: 'dark t-amb',   name: 'Âmbar',     mode: 'pôr-do-sol', dot: '#D99A4E', bg: '#150F08' },
  ];
  function currentTheme() { return localStorage.getItem('atlas-theme') || 'dark'; }
  function applyTheme(cls) {
    const h = document.documentElement;
    const embed = h.classList.contains('embed');
    h.className = cls + (embed ? ' embed' : '');
    localStorage.setItem('atlas-theme', cls);
    if (window.lucide) lucide.createIcons();
  }
  function openThemePicker() {
    ensureModalKeyframes();
    const cur = currentTheme();
    const back = document.createElement('div');
    back.style.cssText = 'position:fixed;inset:0;z-index:10000;display:flex;align-items:center;justify-content:center;padding:16px;background:rgba(5,11,20,0.7);backdrop-filter:blur(8px);';
    const panel = document.createElement('div');
    panel.style.cssText = 'max-width:460px;width:100%;background:var(--bg-surface);border:1px solid var(--line-strong);border-radius:16px;padding:20px;animation:modalIn 0.2s ease-out;box-shadow:var(--shadow-lg);';
    const grid = THEMES.map(t => {
      const sel = t.cls === cur, lightBg = t.cls.indexOf('light') >= 0;
      const tx = lightBg ? '#1a1a1a' : '#ffffff', tm = lightBg ? '#6b6b70' : '#aaaaaa';
      return `<button type="button" data-cls="${t.cls}" style="text-align:left;cursor:pointer;background:${t.bg};border:2px solid ${sel ? t.dot : 'transparent'};border-radius:12px;padding:12px;display:flex;align-items:center;gap:10px;outline:1px solid rgba(128,128,128,.18)">
        <span style="width:24px;height:24px;border-radius:50%;background:${t.dot};box-shadow:0 0 8px 1px ${t.dot};flex-shrink:0"></span>
        <span style="min-width:0;flex:1"><span style="display:block;font:600 13px 'Space Grotesk';color:${tx}">${t.name}</span><span style="display:block;font-size:11px;color:${tm}">${t.mode}</span></span>
        ${sel ? '<span style="color:' + t.dot + ';font-size:13px;font-weight:700">✓</span>' : ''}
      </button>`;
    }).join('');
    panel.innerHTML = `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
        <div><div style="font:700 16px 'Space Grotesk';color:var(--text-primary)">Aparência</div><div style="font-size:12px;color:var(--text-muted)">Tema de cores do app</div></div>
        <button type="button" id="_tpClose" style="background:transparent;border:1px solid var(--line-strong);border-radius:8px;color:var(--text-secondary);cursor:pointer;width:30px;height:30px;font-size:14px">✕</button>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">${grid}</div>`;
    back.appendChild(panel);
    document.body.appendChild(back);
    function close() { document.removeEventListener('keydown', onKey); back.remove(); }
    function onKey(e) { if (e.key === 'Escape') close(); }
    back.addEventListener('click', e => { if (e.target === back) close(); });
    document.addEventListener('keydown', onKey);
    panel.querySelector('#_tpClose').addEventListener('click', close);
    panel.querySelectorAll('button[data-cls]').forEach(b => b.addEventListener('click', () => { applyTheme(b.dataset.cls); close(); }));
  }

  window.UI = window.UI || {};
  window.UI.showToast = showToast;
  window.UI.showConfirm = showConfirm;
  window.UI.setLoading = setLoading;
  window.UI.updatePager = updatePager;
  window.UI.syncBadge = syncBadge;
  window.UI.exportCsv = exportCsv;
  window.AtlasTheme = { THEMES, apply: applyTheme, current: currentTheme, open: openThemePicker };
  // Todos os botões de tema das telas chamam toggleAtlasTheme(); aqui ele passa a
  // abrir o seletor de temas (em vez de só alternar dark/light).
  window.toggleAtlasTheme = openThemePicker;
})();
