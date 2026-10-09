// admin-nav.js — injeta o link "Usuários" na barra lateral APENAS para o admin.
// Funciona tanto na sidebar inline (logs/dashboard/admin_clients) quanto na
// renderizada por nav.js (vlans/topologia/ips). Idempotente: nunca duplica.
// A verdade vem do backend (/api/me → is_admin); o flag em localStorage só
// evita o flicker entre páginas.
(function () {
  const API_BASE = `http://${window.location.hostname}:${window.API_PORT || '8000'}/api`;

  function injectLink() {
    if (localStorage.getItem('atlas-is-admin') !== '1') return;
    const active = /usuarios\.html$/.test(window.location.pathname);
    document.querySelectorAll('aside.sidebar nav, #sidebar nav').forEach((nav) => {
      if (nav.querySelector('[data-navkey="users"]')) return;
      const a = document.createElement('a');
      a.href = 'usuarios.html';
      a.className = 'nav-btn' + (active ? ' active' : '');
      a.setAttribute('data-navkey', 'users');
      a.innerHTML = '<i data-lucide="users" style="width:15px;height:15px;"></i><span>Usuários</span>';
      nav.appendChild(a);
    });
    if (window.lucide) lucide.createIcons();
  }

  function probe() {
    const tok = (window.AtlasAPI && AtlasAPI.getSessionToken && AtlasAPI.getSessionToken())
      || localStorage.getItem('atlas-api-key') || '';
    if (!tok) return;
    fetch(`${API_BASE}/me`, { headers: { 'X-API-Key': tok } })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (!d) return;
        localStorage.setItem('atlas-is-admin', d.is_admin ? '1' : '0');
        window.AtlasIsAdmin = !!d.is_admin;
        if (d.is_admin) injectLink();
      })
      .catch(() => {});
  }

  // 1) injeta já com o flag em cache (sem flicker); 2) confirma no backend;
  // 3) re-injeta após o nav.js renderizar (que substitui o innerHTML da sidebar).
  document.addEventListener('DOMContentLoaded', injectLink);
  window.addEventListener('load', () => { injectLink(); setTimeout(injectLink, 400); });
  probe();
})();
