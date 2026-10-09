// nav.js — barra lateral compartilhada das telas novas (VLANs/Topologia/IPs).
// As telas antigas mantêm a sidebar inline; aqui é a fonte única para as novas.
window.HorusNav = (function () {
  const ITEMS = [
    { key: 'dash',    href: 'dashboard.html',     icon: 'layout-dashboard', label: 'Visão geral' },
    { key: 'logs',    href: 'logs.html',          icon: 'activity',         label: 'Atividade' },
    { key: 'clients', href: 'admin_clients.html', icon: 'folder-tree',      label: 'Grupos e ativos' },
    { key: 'vlans',   href: 'vlans.html',         icon: 'layers-3',         label: 'VLANs' },
    { key: 'topo',    href: 'topologia.html',     icon: 'share-2',          label: 'Topologia' },
    { key: 'ips',     href: 'ips.html',           icon: 'globe',            label: 'IPs' },
  ];

  function render(activeKey, mountId) {
    const aside = document.getElementById(mountId || 'sidebar');
    if (!aside) return;
    const nav = ITEMS.map(it => `
      <a href="${it.href}" class="nav-btn${it.key === activeKey ? ' active' : ''}">
        <i data-lucide="${it.icon}" style="width:15px;height:15px;"></i><span>${it.label}</span>
      </a>`).join('');
    aside.innerHTML = `
      <div style="display:flex;align-items:center;gap:12px;padding:22px 20px;border-bottom:1px solid var(--line);">
        <img src="assets/horus-logo.png" width="36" height="36" alt="Horus" class="octo-idle"/>
        <span class="brand" style="font-size:28px;color:var(--text-primary);line-height:1;">Horus</span>
      </div>
      <nav style="flex:1;padding:14px 0;">${nav}</nav>
      <div style="padding:12px 14px;border-top:1px solid var(--line);display:flex;align-items:center;gap:10px;">
        <div style="width:32px;height:32px;border-radius:8px;background:var(--bg-elev);display:flex;align-items:center;justify-content:center;flex-shrink:0;">
          <i data-lucide="user" style="width:14px;height:14px;color:var(--text-secondary);"></i>
        </div>
        <div style="flex:1;min-width:0;">
          <p style="font:600 12px 'Space Grotesk';color:var(--text-primary);margin:0;">Administrador</p>
          <p style="font-size:11px;color:var(--text-muted);margin:0;">Sistema</p>
        </div>
        <button onclick="toggleHorusTheme()" class="icon-btn" title="Alternar tema"><i data-lucide="sun-moon" style="width:15px;height:15px;"></i></button>
        <button onclick="HorusAPI.logout()" class="icon-btn" title="Sair"><i data-lucide="log-out" style="width:15px;height:15px;"></i></button>
      </div>`;
    if (window.lucide) lucide.createIcons();
  }

  return { render, ITEMS };
})();
