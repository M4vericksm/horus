(function () {
  const SESSION_KEY = 'horus-api-key';

  function getSessionToken() {
    return localStorage.getItem(SESSION_KEY) || '';
  }

  function clearSession() {
    localStorage.removeItem(SESSION_KEY);
  }

  function requireSession() {
    const token = getSessionToken();
    if (!token) window.location.href = 'login.html';
    return token;
  }

  // Encerra a sessão: avisa o backend (que incrementa token_version e revoga
  // server-side todos os tokens deste usuário) e limpa o estado local. Melhor
  // esforço — se o POST falhar, ainda limpamos o local e vamos para o login.
  async function logout() {
    const token = getSessionToken();
    if (token) {
      try {
        const base = `http://${location.hostname}:${window.API_PORT || '8000'}/api`;
        await fetch(`${base}/logout`, { method: 'POST', headers: { 'X-API-Key': token } });
      } catch (e) { /* ignora: revogação é best-effort, segue limpando o local */ }
    }
    clearSession();
    try { localStorage.removeItem('horus-is-admin'); } catch (e) {}
    window.location.href = 'login.html';
  }

  // Evita que múltiplos 401 paralelos disparem redirects simultâneos (race guard).
  let _authRedirecting = false;

  function installAuthFetch() {
    if (window.fetch.__horusAuthFetch) return;

    const nativeFetch = window.fetch.bind(window);
    const authFetch = async (input, init = {}) => {
      const url = typeof input === 'string' ? input : input.url;
      const isApiRequest = url && url.includes('/api/');

      if (isApiRequest) {
        const headers = new Headers(init.headers || (input && input.headers) || {});
        const token = getSessionToken();
        if (token) headers.set('X-API-Key', token);
        init = { ...init, headers };
      }

      const response = await nativeFetch(input, init);
      if (response.status === 401 && isApiRequest && !_authRedirecting) {
        _authRedirecting = true;
        clearSession();
        window.location.href = 'login.html?expired=1';
      }
      return response;
    };

    authFetch.__horusAuthFetch = true;
    window.fetch = authFetch;
  }

  window.HorusAPI = window.HorusAPI || {};
  window.HorusAPI.getSessionToken = getSessionToken;
  window.HorusAPI.clearSession = clearSession;
  window.HorusAPI.requireSession = requireSession;
  window.HorusAPI.installAuthFetch = installAuthFetch;
  window.HorusAPI.logout = logout;
})();
