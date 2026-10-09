/**
 * HorusPicker — combobox com busca para escolher provedor.
 *
 * Com 104 provedores o <select> nativo obriga a rolar a lista inteira. Este
 * componente envolve o próprio <select> (que continua sendo a fonte de verdade:
 * `sel.value` e o evento `change` seguem funcionando), então as telas não
 * precisam mudar a lógica de carregamento — só chamar HorusPicker.enhance().
 *
 * Teclado: ↑/↓ navega, Enter escolhe, Esc fecha, digitar filtra.
 */
(function () {
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  function ensureStyles() {
    if (document.getElementById('horus-picker-styles')) return;
    const s = document.createElement('style');
    s.id = 'horus-picker-styles';
    s.textContent = `
      .apk { position:relative; display:inline-block; }
      .apk-btn { display:flex; align-items:center; gap:8px; height:38px; padding:0 12px;
        border-radius:10px; background:var(--bg-elev,#0f1724); border:1px solid var(--line-strong,#233047);
        color:var(--text-primary,#e6edf7); font-size:13px; cursor:pointer; min-width:240px;
        justify-content:space-between; font-family:inherit; transition:border-color .15s; }
      .apk-btn:hover { border-color:var(--cyan,#22d3ee); }
      .apk-btn:focus-visible { outline:2px solid var(--cyan,#22d3ee); outline-offset:1px; }
      .apk-btn .apk-label { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
      .apk-btn .apk-meta { color:var(--text-muted,#8fa4c2); font-size:11px; flex-shrink:0; }
      .apk-pop { position:absolute; z-index:200; top:calc(100% + 6px); left:0; min-width:100%;
        width:max-content; max-width:min(420px,92vw); background:var(--bg-elev,#0f1724);
        border:1px solid var(--line-strong,#233047); border-radius:12px; box-shadow:0 18px 40px rgba(0,0,0,.45);
        padding:8px; display:none; }
      .apk-pop[data-open="1"] { display:block; }
      .apk-search { width:100%; height:34px; padding:0 10px; border-radius:8px; font-family:inherit;
        background:var(--bg-deep,#0b1220); border:1px solid var(--line-strong,#233047);
        color:var(--text-primary,#e6edf7); font-size:13px; margin-bottom:6px; }
      .apk-search:focus { outline:none; border-color:var(--cyan,#22d3ee); }
      .apk-list { max-height:300px; overflow-y:auto; margin:0; padding:0; list-style:none; }
      .apk-opt { padding:8px 10px; border-radius:8px; cursor:pointer; display:flex; gap:10px;
        align-items:baseline; justify-content:space-between; font-size:13px;
        color:var(--text-primary,#e6edf7); }
      .apk-opt[aria-selected="true"] { background:color-mix(in oklab,var(--cyan,#22d3ee) 16%,transparent); }
      .apk-opt.apk-active { background:color-mix(in oklab,var(--cyan,#22d3ee) 26%,transparent); }
      .apk-opt .apk-o-meta { color:var(--text-muted,#8fa4c2); font-size:11px; flex-shrink:0; }
      .apk-opt mark { background:color-mix(in oklab,var(--cyan,#22d3ee) 38%,transparent);
        color:inherit; border-radius:3px; padding:0 1px; }
      .apk-empty { padding:14px 10px; color:var(--text-muted,#8fa4c2); font-size:12px; text-align:center; }
      @media (max-width:640px) {
        .apk { display:block; width:100%; }
        .apk-btn { min-width:0; width:100%; }
        .apk-pop { max-width:100%; width:100%; }
      }
    `;
    document.head.appendChild(s);
  }

  /** Destaca o trecho casado, escapando o resto. */
  function highlight(text, query) {
    const safe = esc(text);
    if (!query) return safe;
    const i = text.toLowerCase().indexOf(query.toLowerCase());
    if (i < 0) return safe;
    const a = esc(text.slice(0, i));
    const b = esc(text.slice(i, i + query.length));
    const c = esc(text.slice(i + query.length));
    return `${a}<mark>${b}</mark>${c}`;
  }

  /**
   * @param {HTMLSelectElement} sel  select já populado com <option>
   * @param {{placeholder?:string}} [opts]
   */
  function enhance(sel, opts) {
    if (!sel || sel.dataset.apkReady === '1') return;
    ensureStyles();
    opts = opts || {};
    sel.dataset.apkReady = '1';
    sel.style.display = 'none';

    const wrap = document.createElement('div');
    wrap.className = 'apk';
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'apk-btn';
    btn.setAttribute('aria-haspopup', 'listbox');
    btn.setAttribute('aria-expanded', 'false');
    const pop = document.createElement('div');
    pop.className = 'apk-pop';
    const search = document.createElement('input');
    search.className = 'apk-search';
    search.type = 'text';
    search.placeholder = opts.placeholder || 'Digite para buscar o provedor…';
    search.setAttribute('aria-label', 'Buscar provedor');
    const list = document.createElement('ul');
    list.className = 'apk-list';
    list.setAttribute('role', 'listbox');

    pop.append(search, list);
    sel.parentNode.insertBefore(wrap, sel);
    wrap.append(btn, sel, pop);

    let active = -1;   // índice na lista filtrada
    let items = [];    // [{value, label, meta}]

    function readOptions() {
      return Array.from(sel.options).map(o => {
        // Convenção das telas: "Nome · 123 VLANs" → separa rótulo e métrica.
        const parts = o.textContent.split(' · ');
        return { value: o.value, label: parts[0] || o.textContent, meta: parts[1] || '' };
      });
    }

    function syncButton() {
      const cur = items.find(i => i.value === sel.value) || items[0];
      btn.innerHTML = cur
        ? `<span class="apk-label">${esc(cur.label)}</span><span class="apk-meta">${esc(cur.meta)}</span>`
        : `<span class="apk-label" style="color:var(--text-muted)">Nenhum provedor</span>`;
    }

    function renderList() {
      const q = search.value.trim();
      const ql = q.toLowerCase();
      const filtered = ql ? items.filter(i => i.label.toLowerCase().includes(ql)) : items;
      if (!filtered.length) {
        list.innerHTML = `<li class="apk-empty">Nenhum provedor encontrado para “${esc(q)}”.</li>`;
        active = -1;
        return;
      }
      if (active < 0 || active >= filtered.length) {
        const cur = filtered.findIndex(i => i.value === sel.value);
        active = cur >= 0 ? cur : 0;
      }
      list.innerHTML = filtered.map((i, idx) => `
        <li class="apk-opt${idx === active ? ' apk-active' : ''}" role="option"
            aria-selected="${i.value === sel.value}" data-value="${esc(i.value)}" data-idx="${idx}">
          <span>${highlight(i.label, q)}</span>
          ${i.meta ? `<span class="apk-o-meta">${esc(i.meta)}</span>` : ''}
        </li>`).join('');
      const act = list.querySelector('.apk-active');
      if (act) act.scrollIntoView({ block: 'nearest' });
    }

    function open() {
      items = readOptions();
      pop.dataset.open = '1';
      btn.setAttribute('aria-expanded', 'true');
      search.value = '';
      active = -1;
      renderList();
      search.focus();
    }

    function close() {
      pop.dataset.open = '0';
      btn.setAttribute('aria-expanded', 'false');
    }

    function choose(value) {
      if (value == null) return;
      sel.value = value;
      syncButton();
      close();
      btn.focus();
      sel.dispatchEvent(new Event('change', { bubbles: true }));
    }

    btn.addEventListener('click', () => (pop.dataset.open === '1' ? close() : open()));
    search.addEventListener('input', () => { active = -1; renderList(); });
    list.addEventListener('click', (e) => {
      const li = e.target.closest('.apk-opt');
      if (li) choose(li.dataset.value);
    });

    search.addEventListener('keydown', (e) => {
      const opts_ = Array.from(list.querySelectorAll('.apk-opt'));
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        if (!opts_.length) return;
        active = e.key === 'ArrowDown'
          ? Math.min(active + 1, opts_.length - 1)
          : Math.max(active - 1, 0);
        renderList();
      } else if (e.key === 'Enter') {
        e.preventDefault();
        const el = opts_[active] || opts_[0];
        if (el) choose(el.dataset.value);
      } else if (e.key === 'Escape') {
        e.preventDefault();
        close();
        btn.focus();
      }
    });

    document.addEventListener('click', (e) => {
      if (!wrap.contains(e.target)) close();
    });

    // Telas repopulam o <select> ao trocar de contexto: mantém o botão em dia.
    new MutationObserver(() => { items = readOptions(); syncButton(); })
      .observe(sel, { childList: true });

    items = readOptions();
    syncButton();
  }

  window.HorusPicker = { enhance };
})();
