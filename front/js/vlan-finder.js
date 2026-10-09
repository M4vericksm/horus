/**
 * HorusVlanFinder — busca uma VLAN em TODOS os provedores.
 *
 * Responde "onde essa VLAN passa": uma VLAN 100 que nasce num provedor, transita
 * por outro e termina num terceiro aparece como uma trilha, agrupada por
 * provedor e com os ativos onde foi extraída.
 *
 * Uso: HorusVlanFinder.open()  — ou com termo inicial: .open('100')
 */
(function () {
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  let box, input, results, timer, lastQuery = '', seq = 0;
  // Provedores escolhidos para o modo transporte. Set preserva a ordem de
  // inserção, que representa a sequência do circuito.
  const selecionados = new Set();

  /** Base da API. Só o dashboard declara API_BASE no escopo do script; as demais
   *  telas usam HorusData. Por isso o componente deriva a base por conta própria
   *  (mesma fórmula do dashboard) em vez de depender de uma global. */
  function apiBase() {
    try {
      if (typeof API_BASE === 'string' && API_BASE) return API_BASE;
    } catch (e) { /* não declarada nesta tela */ }
    return `http://${location.hostname}:${window.API_PORT || '8000'}/api`;
  }

  function ensureStyles() {
    if (document.getElementById('horus-vf-styles')) return;
    const s = document.createElement('style');
    s.id = 'horus-vf-styles';
    s.textContent = `
      .vf-back { position:fixed; inset:0; z-index:300; background:rgba(5,11,20,.72);
        backdrop-filter:blur(8px); display:flex; align-items:flex-start;
        justify-content:center; padding:8vh 18px 18px; }
      .vf-panel { width:min(860px,100%); max-height:80vh; display:flex; flex-direction:column;
        background:var(--bg-elev,#0f1724); border:1px solid var(--line-strong,#233047);
        border-radius:16px; box-shadow:0 24px 60px rgba(0,0,0,.5); overflow:hidden; }
      .vf-head { padding:16px 18px 12px; border-bottom:1px solid var(--line,#1b2537); }
      .vf-title { font:600 14px 'Space Grotesk',system-ui,sans-serif;
        color:var(--text-primary,#e6edf7); margin-bottom:3px; }
      .vf-sub { font-size:11.5px; color:var(--text-muted,#8fa4c2); }
      .vf-input { width:100%; height:42px; margin-top:12px; padding:0 14px; border-radius:10px;
        background:var(--bg-deep,#0b1220); border:1px solid var(--line-strong,#233047);
        color:var(--text-primary,#e6edf7); font-size:14px; font-family:inherit; }
      .vf-input:focus { outline:none; border-color:var(--cyan,#22d3ee); }
      .vf-body { overflow-y:auto; padding:12px 18px 18px; }
      .vf-status { padding:26px 10px; text-align:center; color:var(--text-muted,#8fa4c2); font-size:12.5px; }
      .vf-hop { border:1px solid var(--line,#1b2537); border-radius:12px; padding:12px 14px; margin-bottom:10px;
        background:color-mix(in oklab,var(--cyan,#22d3ee) 4%,transparent); }
      .vf-hop-h { display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:8px; }
      .vf-hop-name { font:600 13.5px 'Space Grotesk',system-ui,sans-serif;
        color:var(--text-primary,#e6edf7); display:flex; align-items:center; gap:8px; }
      .vf-badge { font-size:10px; font-weight:700; letter-spacing:.4px; text-transform:uppercase;
        padding:2px 7px; border-radius:999px; background:color-mix(in oklab,var(--cyan,#22d3ee) 20%,transparent);
        color:var(--cyan,#22d3ee); }
      .vf-badge.edge { background:color-mix(in oklab,#f59e0b 20%,transparent); color:#f59e0b; }
      .vf-open { font-size:11.5px; color:var(--cyan,#22d3ee); text-decoration:none; flex-shrink:0; }
      .vf-open:hover { text-decoration:underline; }
      .vf-asset { display:flex; align-items:baseline; gap:8px; padding:5px 0; font-size:12.5px;
        color:var(--text-secondary,#b8c7dd); border-top:1px dashed var(--line,#1b2537); }
      .vf-asset:first-of-type { border-top:none; }
      .vf-vid { font-weight:700; color:var(--cyan,#22d3ee); font-variant-numeric:tabular-nums; }
      .vf-host { font-weight:600; color:var(--text-primary,#e6edf7); }
      .vf-dim { color:var(--text-muted,#8fa4c2); font-size:11.5px; }
      .vf-arrow { text-align:center; color:var(--text-muted,#8fa4c2); font-size:15px; line-height:1; margin:-4px 0 6px; }
      /* Com dezenas de provedores a lista de chips empurrava o resultado para
         fora da tela: limita a altura e rola dentro do próprio bloco. */
      .vf-chips { display:flex; flex-wrap:wrap; gap:6px; margin-bottom:10px;
        max-height:76px; overflow-y:auto; padding-right:4px; }
      .vf-chips-h { font-size:11px; color:var(--text-muted,#8fa4c2); margin-bottom:5px; }
      .vf-chip { font-size:11px; padding:4px 9px; border-radius:999px; cursor:pointer;
        font-family:inherit; background:transparent; color:var(--text-muted,#8fa4c2);
        border:1px solid var(--line-strong,#233047); }
      .vf-chip:hover { border-color:var(--cyan,#22d3ee); color:var(--text-primary,#e6edf7); }
      .vf-chip.on { background:color-mix(in oklab,var(--cyan,#22d3ee) 20%,transparent);
        border-color:var(--cyan,#22d3ee); color:var(--cyan,#22d3ee); font-weight:600; }
      .vf-chip.clear { border-style:dashed; }
      .vf-warn { margin-bottom:10px; padding:9px 12px; border-radius:9px; font-size:11.5px;
        background:color-mix(in oklab,#f59e0b 10%,transparent); border:1px solid color-mix(in oklab,#f59e0b 28%,transparent);
        color:#f59e0b; }
      @media (max-width:640px) {
        .vf-back { padding:4vh 10px 10px; }
        .vf-panel { max-height:88vh; }
        .vf-hop-h { flex-direction:column; align-items:flex-start; gap:4px; }
        .vf-asset { flex-wrap:wrap; }
      }
    `;
    document.head.appendChild(s);
  }

  function build() {
    ensureStyles();
    box = document.createElement('div');
    box.className = 'vf-back';
    box.innerHTML = `
      <div class="vf-panel" role="dialog" aria-modal="true" aria-label="Buscar VLAN entre provedores">
        <div class="vf-head">
          <div class="vf-title">Buscar VLAN em todos os provedores</div>
          <div class="vf-sub">Número busca o <b>VID exato</b> (100 não traz 1100). Texto busca nome/descrição. Clique nos provedores para isolar um transporte.</div>
          <input class="vf-input" type="text" placeholder="VID ou nome da VLAN…" aria-label="Termo de busca">
        </div>
        <div class="vf-body"><div class="vf-status">Digite para buscar.</div></div>
      </div>`;
    input = box.querySelector('.vf-input');
    results = box.querySelector('.vf-body');

    box.addEventListener('click', (e) => { if (e.target === box) close(); });
    document.addEventListener('keydown', onKey);
    input.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(() => search(input.value.trim()), 260);
    });
    document.body.appendChild(box);
  }

  function onKey(e) {
    if (e.key === 'Escape' && box && box.isConnected) { e.preventDefault(); close(); }
  }

  function status(msg) {
    results.innerHTML = `<div class="vf-status">${esc(msg)}</div>`;
  }

  async function search(q) {
    if (q === lastQuery) return;
    lastQuery = q;
    if (!q) { status('Digite para buscar.'); return; }
    const mine = ++seq;
    status('Buscando…');
    try {
      const res = await fetch(`${apiBase()}/vlans/search?q=${encodeURIComponent(q)}`);
      if (mine !== seq) return;               // resposta obsoleta (digitação rápida)
      if (!res.ok) { status('Falha na busca (HTTP ' + res.status + ').'); return; }
      render(await res.json());
    } catch (err) {
      if (mine === seq) status('Erro de conexão: ' + err.message);
    }
  }

  function render(data) {
    if (!data.results || !data.results.length) {
      status(`Nenhuma VLAN encontrada para “${data.query}”.`);
      return;
    }
    const plural = data.client_count > 1 ? 'provedores' : 'provedor';
    const head = `<div class="vf-sub" style="margin-bottom:10px">
      ${data.total} ocorrência${data.total !== 1 ? 's' : ''} em ${data.client_count} ${plural}</div>`;
    const warn = data.truncated
      ? `<div class="vf-warn">Resultado grande: exibindo apenas as primeiras ocorrências. Refine a busca.</div>` : '';

    // Modo transporte: com provedores selecionados, mostra só eles — na ordem
    // em que foram clicados, que é a ordem do circuito (origem → trânsito → destino).
    const sel = [...selecionados].filter(id => data.results.some(g => g.client_id === id));
    const visiveis = sel.length
      ? sel.map(id => data.results.find(g => g.client_id === id)).filter(Boolean)
      : data.results;

    const chips = data.results.map(g => `
      <button type="button" class="vf-chip${selecionados.has(g.client_id) ? ' on' : ''}"
              data-cid="${g.client_id}">${esc(g.client_name)}${
        selecionados.has(g.client_id) ? ` <b>${[...selecionados].indexOf(g.client_id) + 1}</b>` : ''}</button>`).join('');
    const barra = `
      <div class="vf-chips-h">Clique nos provedores para montar o transporte na ordem do circuito${
        data.results.length > 14 ? ` · ${data.results.length} provedores, role para ver todos` : ''}</div>
      <div class="vf-chips">${chips}${
        sel.length ? `<button type="button" class="vf-chip clear" data-cid="clear">limpar</button>` : ''}</div>`;

    const hops = visiveis.map((g, idx) => {
      const arrow = idx > 0 ? `<div class="vf-arrow">↓</div>` : '';
      const isEdge = g.occurrences.some(o => o.is_edge_router);
      const vids = g.vids.slice(0, 6).join(', ') + (g.vids.length > 6 ? '…' : '');
      const assets = g.occurrences.slice(0, 12).map(o => `
        <div class="vf-asset">
          <span class="vf-vid">${o.vid}</span>
          <span class="vf-host">${esc(o.asset_hostname || '— sem ativo —')}</span>
          ${o.name ? `<span class="vf-dim">${esc(o.name)}</span>` : ''}
          ${o.is_edge_router ? '<span class="vf-badge edge">borda</span>' : ''}
          ${o.vlan_type ? `<span class="vf-dim">${esc(o.vlan_type)}</span>` : ''}
        </div>`).join('');
      const more = g.occurrences.length > 12
        ? `<div class="vf-dim" style="padding-top:6px">+${g.occurrences.length - 12} outra(s) ocorrência(s)</div>` : '';
      return `${arrow}
        <div class="vf-hop">
          <div class="vf-hop-h">
            <div class="vf-hop-name">${esc(g.client_name)}
              <span class="vf-badge${isEdge ? ' edge' : ''}">VLAN ${esc(vids)}</span>
            </div>
            <a class="vf-open" href="vlans.html?client_id=${g.client_id}">abrir provedor →</a>
          </div>
          ${assets}${more}
        </div>`;
    }).join('');

    const resumoSel = sel.length
      ? `<div class="vf-sub" style="margin-bottom:8px">Transporte: ${sel.length} provedor(es) na ordem selecionada.</div>`
      : '';
    results.innerHTML = head + warn + barra + resumoSel + hops;

    results.querySelectorAll('.vf-chip').forEach(btn => {
      btn.onclick = () => {
        const cid = btn.dataset.cid;
        if (cid === 'clear') selecionados.clear();
        else {
          const id = Number(cid);
          // Set preserva ordem de inserção: é a sequência do circuito.
          if (selecionados.has(id)) selecionados.delete(id); else selecionados.add(id);
        }
        render(data);
      };
    });
  }

  function open(initial) {
    if (!box || !box.isConnected) build();
    lastQuery = '';
    input.value = initial || '';
    input.focus();
    input.select();
    if (initial) search(initial);
    else status('Digite para buscar.');
  }

  function close() {
    if (box && box.isConnected) box.remove();
    document.removeEventListener('keydown', onKey);
    lastQuery = '';
  }

  window.HorusVlanFinder = { open, close };
})();
