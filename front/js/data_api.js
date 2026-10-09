// data_api.js — camada de dados das telas novas (VLANs / Topologia / IPs).
//
// Read-only: só faz GET na API que já existe e remodela as respostas num formato
// pronto para render. Auth e redirect no 401 são tratados pelo installAuthFetch()
// de js/api.js — aqui só usamos fetch normal.
//
// Endpoints usados:
//   GET /api/clients                     -> grupos (provedores)
//   GET /api/clients/{id}/topology       -> nós, enlaces, VLANs, IPs (interfaces)
//   GET /api/clients/{id}/vlans-enriched -> subnets por VLAN
//
// Expõe window.HorusData.{ loadGroups, loadGroup, CAT_META, helpers }.
window.HorusData = (function () {
  function apiBase() {
    return "http://" + window.location.hostname + ":" + (window.API_PORT || "8000") + "/api";
  }

  async function api(path) {
    var res = await fetch(apiBase() + path);   // X-API-Key e 401 via installAuthFetch
    if (!res.ok) {
      var detail = "";
      try { detail = JSON.stringify(await res.json()); } catch (e) {}
      var err = new Error("HTTP " + res.status + " em " + path + " " + detail);
      err.status = res.status;
      throw err;
    }
    return res.status === 204 ? null : res.json();
  }

  // ── metadados visuais por categoria (ícone lucide + cor) ──────────────────────
  var CAT_META = {
    borda:      { label: "Borda",      icon: "git-branch", color: "var(--magenta)" },
    core:       { label: "Core",       icon: "cpu",        color: "var(--cyan)" },
    agregacao:  { label: "Agregação",  icon: "network",    color: "var(--cyan)" },
    olt:        { label: "OLT",        icon: "split",      color: "var(--emerald)" },
    acesso:     { label: "Acesso",     icon: "router",     color: "var(--emerald)" },
    infra:      { label: "Infra",      icon: "server",     color: "var(--text-muted)" },
    cliente:    { label: "Cliente",    icon: "users",      color: "var(--text-muted)" },
    transporte: { label: "Transporte", icon: "cable",      color: "var(--text-muted)" },
    servico:    { label: "Serviço",    icon: "radio",      color: "var(--text-muted)" },
  };

  // ── helpers de IP ─────────────────────────────────────────────────────────────
  function ipToInt(ip) {
    var p = String(ip).split(".");
    if (p.length !== 4) return null;
    return ((+p[0]) * 16777216 + (+p[1]) * 65536 + (+p[2]) * 256 + (+p[3])) >>> 0;
  }
  function intToIp(n) { return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join("."); }
  function networkOf(ip, mask) {
    var n = ipToInt(ip); if (n == null || mask == null) return null;
    var m = mask >= 32 ? 0xffffffff : (mask <= 0 ? 0 : (0xffffffff << (32 - mask)) >>> 0);
    return intToIp((n & m) >>> 0);
  }
  function broadcastOf(ip, mask) {
    var n = ipToInt(ip); if (n == null || mask == null) return null;
    var m = mask >= 32 ? 0xffffffff : (mask <= 0 ? 0 : (0xffffffff << (32 - mask)) >>> 0);
    return intToIp(((n & m) | (~m >>> 0)) >>> 0);
  }
  function gatewayOf(ip, mask) {  // convenção comum: primeiro host utilizável
    var net = networkOf(ip, mask); if (net == null) return null;
    if (mask >= 31) return net;
    return intToIp((ipToInt(net) + 1) >>> 0);
  }
  function hostCount(mask) {
    if (mask == null) return 0;
    if (mask >= 31) return mask === 31 ? 2 : 1;
    return Math.pow(2, 32 - mask) - 2;
  }
  function isPrivate(ip) {
    var n = ipToInt(ip); if (n == null) return false;
    var inR = function (a, b) { return n >= ipToInt(a) && n <= ipToInt(b); };
    return inR("10.0.0.0", "10.255.255.255") || inR("172.16.0.0", "172.31.255.255") ||
           inR("192.168.0.0", "192.168.255.255") || inR("100.64.0.0", "100.127.255.255");
  }
  function scopeOf(ip) { return isPrivate(ip) ? "privado" : "publico"; }

  var CAT_ALIASES = {
    borda: "borda", edge: "borda", router: "borda", core: "core", nucleo: "core",
    agregacao: "agregacao", aggregation: "agregacao", agg: "agregacao", distribuicao: "agregacao",
    olt: "olt", acesso: "acesso", access: "acesso", switch: "acesso",
  };
  function mapCat(c) { return c ? (CAT_ALIASES[String(c).toLowerCase()] || "acesso") : "acesso"; }
  function vlanCat(name, desc) {
    var s = ((name || "") + " " + (desc || "")).toLowerCase();
    if (/pppoe|client|empresar|dedicad|l2/.test(s)) return "cliente";
    if (/transport|core|enlace|uplink|backbone|trunk/.test(s)) return "transporte";
    if (/gerenc|mgmt|manage|oob|infra|loopback/.test(s)) return "infra";
    if (/iptv|voip|cftv|multicast|servic|service|tv/.test(s)) return "servico";
    return "servico";
  }

  var CAT_ROW = { borda: 0, core: 1, agregacao: 2, olt: 3, acesso: 3 };
  function layoutNodes(nodes) {
    var byRow = {};
    nodes.forEach(function (n) { var r = CAT_ROW[n.cat] != null ? CAT_ROW[n.cat] : 3; n.row = r; (byRow[r] = byRow[r] || []).push(n); });
    Object.keys(byRow).forEach(function (r) { byRow[r].forEach(function (n, i) { n.col = i; }); });
    return nodes;
  }

  function freeRanges(usedVids, lo, hi) {
    lo = lo || 1; hi = hi || 4094;
    var used = {}; usedVids.forEach(function (v) { used[v] = true; });
    var ranges = [], start = null, nextFree = null;
    for (var v = lo; v <= hi + 1; v++) {
      var free = v <= hi && !used[v];
      if (free && nextFree == null) nextFree = v;
      if (free && start == null) start = v;
      else if (!free && start != null) { ranges.push({ from: start, to: v - 1, count: v - start }); start = null; }
    }
    ranges.sort(function (a, b) { return b.count - a.count; });
    return { ranges: ranges.slice(0, 6), nextFree: nextFree };
  }

  // conta VIDs distintos — a lista vem com repetição (mesmo VID em várias portas)
  function uniqueCount(vids) {
    var seen = {}, n = 0;
    (vids || []).forEach(function (v) { if (!seen[v]) { seen[v] = true; n++; } });
    return n;
  }

  // ── monta o modelo de dados a partir das respostas da API ────────────────────
  // enrichedError: mensagem de falha de /vlans-enriched (opcional). A tela precisa
  // saber que as subnets por VLAN não vieram, senão "sem subnet" vira mentira —
  // o operador lê "essa VLAN não tem IP" quando na verdade a chamada morreu.
  function build(topo, vlansEnriched, enrichedError) {
    var nodes = (topo.nodes || []).map(function (n) {
      return {
        id: n.id, label: n.hostname, cat: mapCat(n.category),
        mgmt: n.ip_address || "—", ifaces: (n.interfaces || []).length,
        vids: (n.vlans || []).map(function (v) { return v.vid; }),
        subnets: (n.subnets || []).map(function (s) { return s.network + "/" + s.mask; }),
        _interfaces: n.interfaces || [], vendor: n.vendor || null,
      };
    });
    layoutNodes(nodes);

    var edges = (topo.edges || []).map(function (e) {
      return { a: e.source, b: e.target, iface: e.label || "", vids: e.shared_vlans || [] };
    });

    var ipHosts = [];
    nodes.forEach(function (n) {
      (n._interfaces || []).forEach(function (ifc) {
        if (!ifc.ip_address) return;
        var vid = (ifc.vlans && ifc.vlans[0]) ? ifc.vlans[0].vid : null;
        ipHosts.push({
          ip: ifc.ip_address,
          block: (ifc.mask != null ? networkOf(ifc.ip_address, ifc.mask) + "/" + ifc.mask : ifc.ip_address),
          mask: ifc.mask != null ? ifc.mask : null,
          edge: n.label, iface: ifc.name, vid: vid,
          use: ifc.description || (ifc.is_management ? "Gerência" : ""),
          status: "uso", scope: scopeOf(ifc.ip_address),
        });
      });
    });

    var blockMap = {};
    function ensureBlock(prefix, edge, mask, desc) {
      if (!blockMap[prefix]) blockMap[prefix] = {
        prefix: prefix, edge: edge || "—", mask: mask,
        total: hostCount(mask), used: 0, scope: scopeOf(prefix.split("/")[0]), desc: desc || "",
      };
      return blockMap[prefix];
    }
    (topo.subnet_summary || []).forEach(function (s) { ensureBlock(s.network + "/" + s.mask, s.asset_hostname, s.mask, s.description || ""); });
    ipHosts.forEach(function (h) { var b = ensureBlock(h.block, h.edge, +(String(h.block).split("/")[1] || 24), h.use); b.used += 1; });
    var ipBlocks = Object.keys(blockMap).map(function (k) { return blockMap[k]; })
      .sort(function (a, b) { return (b.scope === "publico") - (a.scope === "publico") || a.prefix.localeCompare(b.prefix); });

    var subnetsByVid = {};
    (vlansEnriched || []).forEach(function (v) {
      if (!subnetsByVid[v.vid]) subnetsByVid[v.vid] = [];
      (v.subnets || []).forEach(function (s) {
        var cidr = s.network + "/" + s.mask;
        if (subnetsByVid[v.vid].indexOf(cidr) < 0) subnetsByVid[v.vid].push(cidr);
      });
    });

    var summary = topo.vlan_summary || [];
    var vlans = summary.map(function (v) {
      return {
        vid: v.vid, name: v.name || ("VLAN " + v.vid), desc: v.description || "",
        assets: (v.asset_hostnames || []).length || v.interface_count || 0,
        subnets: subnetsByVid[v.vid] || [], cat: vlanCat(v.name, v.description),
        hosts: v.asset_hostnames || [],
        // Propaga o tipo (routed/vsi/l2vc/native...) que a API devolve. Sem isto
        // o badge de tipo nunca aparece e o cabeçalho rotula tudo como "L2".
        vlan_type: v.vlan_type || null,
      };
    }).sort(function (a, b) { return a.vid - b.vid; });

    var nodeByHost = {}; nodes.forEach(function (n) { nodeByHost[n.label] = n; });
    var vlanPaths = {};
    summary.forEach(function (v) {
      var hosts = (v.asset_hostnames || []).slice();
      if (hosts.length < 2) return;
      hosts.sort(function (a, b) {
        var ra = CAT_ROW[(nodeByHost[a] || {}).cat]; ra = ra == null ? 3 : ra;
        var rb = CAT_ROW[(nodeByHost[b] || {}).cat]; rb = rb == null ? 3 : rb;
        return ra - rb;
      });
      vlanPaths[v.vid] = hosts.map(function (h, i) {
        var n = nodeByHost[h] || {};
        var ifs = (n._interfaces || []).filter(function (ifc) { return (ifc.vlans || []).some(function (x) { return x.vid === v.vid; }); })
          .map(function (ifc) { return ifc.name; });
        return { host: h, cat: (n.cat || "acesso"), ifaces: ifs.join(", ") || "—",
                 role: i === 0 ? "origem" : (i === hosts.length - 1 ? "destino" : "meio") };
      });
    });

    // VID é único por domínio L2, não por cliente. Agregar os VIDs de dezenas de
    // equipamentos independentes satura 1–4094 e faz a tela dizer "nenhuma VLAN
    // livre" mesmo com milhares livres em cada equipamento (maior provedor da base: 58 ativos,
    // 4.094 VIDs distintos no agregado, 3.630 livres só no NE40 de borda).
    // Por isso: agregado (= livre em TODOS os ativos, critério certo para uma VLAN
    // de transporte fim-a-fim) E por equipamento (critério certo para VLAN local).
    var fr = freeRanges(vlans.map(function (v) { return v.vid; }), 1, 4094);

    var freeByAsset = nodes.map(function (n) {
      var f = freeRanges(n.vids || [], 1, 4094);
      var usedCount = uniqueCount(n.vids || []);
      return {
        id: n.id, label: n.label, cat: n.cat,
        usedCount: usedCount, freeCount: 4094 - usedCount,
        ranges: f.ranges, nextFree: f.nextFree,
      };
    }).sort(function (a, b) { return b.freeCount - a.freeCount; });

    return {
      vlans: vlans, freeRanges: fr.ranges, nextFree: fr.nextFree, vlanPaths: vlanPaths,
      freeByAsset: freeByAsset,
      ipBlocks: ipBlocks, ipHosts: ipHosts, nodes: nodes, edges: edges,
      catMeta: CAT_META, stats: topo.stats || {},
      enrichedError: enrichedError || null,
    };
  }

  async function loadGroups() {
    var clients = await api("/clients");
    return (clients || []).map(function (c) {
      return { id: c.id, name: c.name, cidr: c.ip || "",
               asset_count: c.asset_count || 0, vlan_count: c.vlan_count || 0, subnet_count: c.subnet_count || 0 };
    });
  }

  // /topology sem catch: se ele cai, a tela não tem o que mostrar e o erro sobe.
  // /vlans-enriched com catch, mas o motivo da falha é PRESERVADO em vez de
  // descartado: ele só traz as subnets por VLAN, então derrubar a tela inteira
  // por causa dele seria pior — o que não pode é a tela fingir que carregou.
  async function loadGroup(clientId) {
    var id = encodeURIComponent(String(clientId));
    var enrichedError = null;
    var r = await Promise.all([
      api("/clients/" + id + "/topology"),
      api("/clients/" + id + "/vlans-enriched").catch(function (e) {
        enrichedError = (e && e.message) ? e.message : "falha desconhecida";
        return [];
      }),
    ]);
    return build(r[0] || {}, r[1] || [], enrichedError);
  }

  // Caminho (trace) de uma VLAN: pontas com config + enlaces inferidos.
  // Retorna { vid, name, description, endpoints[], links[], stats } cru da API.
  async function loadVlanTrace(clientId, vid) {
    var id = encodeURIComponent(String(clientId));
    return api("/clients/" + id + "/vlans/" + encodeURIComponent(String(vid)) + "/trace");
  }

  // Config bruta da VLAN por ativo (direto das linhas Vlan, independe de interface).
  // Retorna [{ asset_id, hostname, vendor, category, vlan_type, name, config }].
  async function loadVlanConfigs(clientId, vid) {
    var id = encodeURIComponent(String(clientId));
    return api("/clients/" + id + "/vlans/" + encodeURIComponent(String(vid)) + "/configs");
  }

  // ── reconstrução de config de porta, por fabricante ───────────────────────────
  // Usada pelas telas de VLANs/Topologia quando o texto bruto da porta não foi
  // capturado (nenhum driver guarda o bloco L2 access/trunk — só os casos
  // roteado/VSI/L2VC). Sem isto, o fallback antigo mostrava sempre sintaxe Cisco
  // ("switchport mode trunk") mesmo para Huawei/MikroTik/Juniper, que nunca
  // tiveram esse comando — um bloco fabricado sendo confundido com config real.
  //
  // Compacta VIDs contíguos em faixas, no separador que cada fabricante usa de
  // fato (Cisco/Datacom: "100,200-300" · Huawei: "100 200 to 300").
  function compressVids(vids, rangeSep, joiner) {
    var s = (vids || []).slice().sort(function (a, b) { return a - b; });
    var out = [], i = 0;
    while (i < s.length) {
      var start = s[i], end = s[i];
      while (i + 1 < s.length && s[i + 1] === end + 1) { end = s[++i]; }
      out.push(start === end ? String(start) : (start + rangeSep + end));
      i++;
    }
    return out.join(joiner);
  }

  // Marcador de comentário do fabricante. "!" é sintaxe Cisco/IOS; colar "! foo"
  // num RouterOS ou num Junos dá erro de parse, então um bloco "reconstruído"
  // cheio de "!" não cola justamente nos fabricantes que já corrigimos no resto.
  function commentLine(vendor, text, indent) {
    var v = (vendor || "").trim().toLowerCase();
    var mark = (v === "huawei" || v === "mikrotik" || v === "juniper") ? "#" : "!";
    return (indent === false ? "" : " ") + mark + " " + text;
  }

  // Cabeçalho do bloco. Cisco/Datacom/Huawei têm modo de configuração de
  // interface — "interface X" seguido de linhas indentadas. MikroTik e Juniper
  // não têm: cada comando é auto-contido e já carrega o nome da interface
  // dentro dele (/interface bridge vlan add ... untagged=ether1,
  // set interfaces ge-0/0/0 ...). Abrir com "interface X" nesses dois produzia
  // um bloco que não cola no equipamento, mesmo com o corpo já correto.
  function reconstructInterfaceHeaderLines(vendor, ifaceName, description) {
    var v = (vendor || "").trim().toLowerCase();
    var ifc = ifaceName || "unknown";
    var lines = [];
    if (v === "mikrotik") {
      if (description) lines.push('/interface set [find name=' + ifc + '] comment="' + description + '"');
    } else if (v === "juniper") {
      if (description) lines.push(' set interfaces ' + ifc + ' description "' + description + '"');
    } else {
      // Fabricante não modelado cai aqui de propósito: "interface <nome>" é
      // convenção quase universal e serve de âncora de contexto. O que nunca
      // se inventa é o corpo (switchport & cia.) — esse vira comentário neutro.
      lines.push("interface " + ifc);
      if (description) lines.push(" description " + description);
    }
    return lines;
  }

  // buckets = { access: [vid,...], native: vid|null, trunk: [vid,...] }
  // Retorna as linhas do corpo (sem o cabeçalho "interface X", que cada tela
  // já monta do seu jeito) na sintaxe real do fabricante. Fabricante sem
  // sintaxe de porta modelada nunca recebe comando inventado — vira comentário
  // neutro em vez de parecer um comando real do equipamento.
  function reconstructPortVlanLines(vendor, ifaceName, buckets) {
    var v = (vendor || "").trim().toLowerCase();
    var access = buckets.access || [], native = buckets.native, trunk = buckets.trunk || [];
    var lines = [];

    if (v === "cisco" || v === "datacom") {
      if (access.length) lines.push(" switchport mode access", " switchport access vlan " + compressVids(access, "-", ","));
      if (trunk.length || native != null) {
        lines.push(" switchport mode trunk");
        if (native != null) lines.push(" switchport trunk native vlan " + native);
        if (trunk.length) lines.push(" switchport trunk allowed vlan " + compressVids(trunk, "-", ","));
      }
    } else if (v === "huawei") {
      if (access.length) lines.push(" port link-type access", " port default vlan " + access[0]);
      if (trunk.length || native != null) {
        lines.push(" port link-type trunk");
        if (trunk.length) lines.push(" port trunk allow-pass vlan " + compressVids(trunk, " to ", " "));
        if (native != null) lines.push(" port trunk pvid vlan " + native);
      }
    } else if (v === "mikrotik") {
      // RouterOS associa VLAN à porta via bridge — não existe comando "na interface".
      var ifc = ifaceName || "ether1";
      access.forEach(function (vid) {
        lines.push("/interface bridge vlan add bridge=bridge1 vlan-ids=" + vid + " untagged=" + ifc);
      });
      if (trunk.length) lines.push("/interface bridge vlan add bridge=bridge1 vlan-ids=" + compressVids(trunk, "-", ",") + " tagged=" + ifc);
    } else if (v === "juniper") {
      var mode = trunk.length ? "trunk" : "access";
      lines.push(" set interfaces " + (ifaceName || "ge-0/0/0") + " unit 0 family ethernet-switching interface-mode " + mode);
      access.concat(trunk).forEach(function (vid) {
        lines.push(" set interfaces " + (ifaceName || "ge-0/0/0") + " unit 0 family ethernet-switching vlan members " + vid);
      });
    } else {
      var partes = [];
      if (access.length) partes.push("acesso na VLAN " + access.join(", "));
      if (trunk.length) partes.push("trunk permitindo VLAN " + compressVids(trunk, "-", ","));
      if (native != null) partes.push("nativa VLAN " + native);
      lines.push(" ! " + (partes.join("; ") || "modo não identificado") +
                 "  (sintaxe de porta de \"" + (vendor || "fabricante desconhecido") + "\" não modelada — sem comando exato)");
    }
    return lines;
  }

  function cidrToMaskDotted(bits) {
    if (bits == null) return "";
    var m = bits >= 32 ? 0xffffffff : (bits <= 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0);
    return intToIp(m >>> 0);
  }

  // Mesmo problema do reconstructPortVlanLines, mas para VLAN roteada (SVI/PTP):
  // 'routed' é atribuído por Cisco, Datacom, Huawei, Juniper E MikroTik — cada um
  // com sintaxe própria — e o fallback antigo sempre montava "interface VlanifX",
  // que só existe em Huawei.
  function reconstructRoutedInterfaceLines(vendor, vid, ep) {
    var v = (vendor || "").trim().toLowerCase();
    ep = ep || {};
    var ip = ep.host_ip, mask = ep.mask, desc = ep.description, ifaceName = ep.interface;
    var lines = [];

    if (v === "huawei") {
      lines.push("interface Vlanif" + vid);
      if (desc) lines.push(" description " + desc);
      if (ip) lines.push(" ip address " + ip + (mask != null ? " " + cidrToMaskDotted(mask) : ""));
    } else if (v === "cisco" || v === "datacom") {
      lines.push("interface " + (ifaceName || ("Vlan" + vid)));
      if (desc) lines.push(" description " + desc);
      lines.push(" encapsulation dot1Q " + vid);
      if (ip) lines.push(" ip address " + ip + (mask != null ? " " + cidrToMaskDotted(mask) : ""));
    } else if (v === "juniper") {
      var phys = ifaceName || "ge-0/0/0";
      lines.push(" set interfaces " + phys + " unit " + vid + " vlan-id " + vid);
      if (desc) lines.push(" set interfaces " + phys + " unit " + vid + " description \"" + desc + "\"");
      if (ip) lines.push(" set interfaces " + phys + " unit " + vid + " family inet address " + ip + (mask != null ? "/" + mask : ""));
    } else if (v === "mikrotik") {
      var parent = ifaceName || "ether1";
      lines.push("/interface vlan add name=vlan" + vid + " vlan-id=" + vid + " interface=" + parent);
      if (ip) lines.push("/ip address add address=" + ip + (mask != null ? "/" + mask : "") + " interface=vlan" + vid);
    } else {
      lines.push(" ! VLAN " + vid + " roteada" + (ip ? " com IP " + ip + (mask != null ? "/" + mask : "") : "") +
                 "  (sintaxe de \"" + (vendor || "fabricante desconhecido") + "\" não modelada)");
    }
    return lines;
  }

  // Mesma lógica da linha de IP dentro de reconstructRoutedInterfaceLines, mas
  // isolada porque a Topologia usa numa interface qualquer (não só rotas SVI).
  function reconstructIpAddressLine(vendor, ip, mask, ifaceName) {
    if (!ip) return null;
    var v = (vendor || "").trim().toLowerCase();
    if (v === "mikrotik") return "/ip address add address=" + ip + (mask != null ? "/" + mask : "") + " interface=" + (ifaceName || "ether1");
    if (v === "huawei" || v === "cisco" || v === "datacom") return " ip address " + ip + (mask != null ? " " + cidrToMaskDotted(mask) : "");
    if (v === "juniper") return " set interfaces " + (ifaceName || "ge-0/0/0") + " family inet address " + ip + (mask != null ? "/" + mask : "");
    return " ! ip " + ip + (mask != null ? "/" + mask : "") + "  (formato de \"" + (vendor || "fabricante desconhecido") + "\" não modelado)";
  }

  return {
    loadGroups: loadGroups, loadGroup: loadGroup, loadVlanTrace: loadVlanTrace, loadVlanConfigs: loadVlanConfigs,
    CAT_META: CAT_META, build: build,
    helpers: { ipToInt: ipToInt, networkOf: networkOf, broadcastOf: broadcastOf, gatewayOf: gatewayOf,
               hostCount: hostCount, scopeOf: scopeOf, vlanCat: vlanCat, freeRanges: freeRanges,
               uniqueCount: uniqueCount,
               commentLine: commentLine,
               reconstructInterfaceHeaderLines: reconstructInterfaceHeaderLines,
               reconstructPortVlanLines: reconstructPortVlanLines,
               reconstructRoutedInterfaceLines: reconstructRoutedInterfaceLines,
               reconstructIpAddressLine: reconstructIpAddressLine },
  };
})();
