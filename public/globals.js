(function () {
  window.API_URL = window.API_URL || 'https://mstelecom-api.duckdns.org';

  function getToken() {
    return localStorage.getItem('adminToken') ||
      localStorage.getItem('token') ||
      localStorage.getItem('ms_token') ||
      localStorage.getItem('authToken') ||
      '';
  }

  function authHeaders(contentType) {
    var headers = { Authorization: 'Bearer ' + getToken() };
    if (contentType !== false) {
      headers['Content-Type'] = 'application/json';
    }
    return headers;
  }

  function isEmptyBearer(value) {
    return !value || /^Bearer\s*(null|undefined)?$/i.test(String(value).trim());
  }

  function authenticatedFetch(url, options) {
    options = options || {};
    var headers = new Headers(options.headers || {});
    var token = getToken();
    if (token && isEmptyBearer(headers.get('Authorization'))) {
      headers.set('Authorization', 'Bearer ' + token);
    }
    return window.__msNativeFetch(url, Object.assign({}, options, { headers: headers }))
      .then(function (response) {
        if (response.status === 401) {
          console.error('API 401 Unauthorized', { url: url, status: response.status });
          response.clone().text().then(function (body) {
            console.error('API 401 response', { url: url, status: response.status, body: body });
          }).catch(function () {});
          if (!window.__msAuthRedirecting) {
            window.__msAuthRedirecting = true;
            alert('Sessão expirada. Faça login novamente.');
            localStorage.removeItem('adminToken');
            localStorage.removeItem('token');
            localStorage.removeItem('ms_token');
            localStorage.removeItem('authToken');
            setTimeout(function () { window.location.href = 'login.html'; }, 500);
          }
        }
        return response;
      });
  }

  if (!window.__msNativeFetch) {
    window.__msNativeFetch = window.fetch.bind(window);
    window.fetch = function (url, options) {
      var target = typeof url === 'string' ? url : (url && url.url) || '';
      if (target.indexOf(window.API_URL + '/api/') === 0) {
        return authenticatedFetch(url, options);
      }
      return window.__msNativeFetch(url, options);
    };
  }

  window.getAdminToken = getToken;
  window.authenticatedFetch = authenticatedFetch;
  window.authHeaders = window.authHeaders || authHeaders;

  function ensureScrollbarStyle() {
    if (document.getElementById('globalCustomScrollbarStyle')) return;
    var style = document.createElement('style');
    style.id = 'globalCustomScrollbarStyle';
    style.textContent = '' +
      '.custom-scrollbar::-webkit-scrollbar{width:4px;}' +
      '.custom-scrollbar::-webkit-scrollbar-track{background:#1e293b;border-radius:10px;}' +
      '.custom-scrollbar::-webkit-scrollbar-thumb{background:#3b82f6;border-radius:10px;}';
    document.head.appendChild(style);
  }

  function applyScrollbarClasses() {
    var selectors = [
      'nav.overflow-y-auto',
      '#sidebar nav',
      '.sidebar nav',
      '#profileModal .overflow-y-auto',
      '#modalPerfil .overflow-y-auto'
    ];
    selectors.forEach(function (sel) {
      document.querySelectorAll(sel).forEach(function (el) {
        el.classList.add('custom-scrollbar');
      });
    });
  }

  function updateSessionInfo() {
    var userStr = localStorage.getItem('user');
    var sessionStart = localStorage.getItem('session_start');
    if (!sessionStart) {
      sessionStart = new Date().toISOString();
      localStorage.setItem('session_start', sessionStart);
    }

    var username = 'Administrador';
    if (userStr) {
      try {
        var parsed = JSON.parse(userStr);
        username = parsed.username || username;
      } catch (_e) {}
    }

    var sessionUserSpan = document.getElementById('sessionUser');
    var sessionStartSpan = document.getElementById('sessionStart');
    var userNameSpan = document.getElementById('userName');

    if (sessionUserSpan) sessionUserSpan.innerText = username;
    if (userNameSpan) userNameSpan.innerText = username;

    if (sessionStartSpan) {
      try {
        sessionStartSpan.innerText = new Date(sessionStart).toLocaleTimeString('pt-BR');
      } catch (_e) {
        sessionStartSpan.innerText = '-';
      }
    }
  }

  function updateSessionIp() {
    var el = document.getElementById('sessionIp');
    if (!el) return Promise.resolve();

    return fetch(window.API_URL + '/api/test-ip', { headers: authHeaders(false) })
      .then(function (res) {
        if (!res.ok) throw new Error('ip_request_failed');
        return res.json();
      })
      .then(function (data) {
        el.innerText = (data && data.ip) || '-';
      })
      .catch(function () {
        el.innerText = '-';
      });
  }

  function initMobileMenu() {
    var toggle = document.getElementById('menuToggle');
    var sidebar = document.getElementById('sidebar');
    var overlay = document.getElementById('menuOverlay');

    if (!toggle || !sidebar || !overlay) return;

    var open = function () {
      sidebar.classList.remove('hidden');
      overlay.classList.remove('hidden');
    };

    var close = function () {
      sidebar.classList.add('hidden');
      overlay.classList.add('hidden');
    };

    toggle.addEventListener('click', function () {
      if (sidebar.classList.contains('hidden')) open();
      else close();
    });

    overlay.addEventListener('click', close);
  }

  function ensureRecentAccessBlock() {
    var sidebar = document.getElementById('sidebar');
    if (!sidebar) return;

    var marker = sidebar.querySelector('[data-recent-accesses]');
    if (marker) return;

    var footerCandidate = null;
    var children = sidebar.querySelectorAll(':scope > div');
    if (children.length > 0) {
      footerCandidate = children[children.length - 1];
    }

    if (!footerCandidate || !footerCandidate.classList.contains('border-t')) {
      footerCandidate = document.createElement('div');
      sidebar.appendChild(footerCandidate);
    }

    footerCandidate.className = 'p-4 border-t border-gray-800 bg-black/30';
    footerCandidate.setAttribute('data-recent-accesses', '1');
    footerCandidate.innerHTML = '' +
      '<div class="flex items-center justify-between mb-3">' +
      '<p class="text-[9px] font-bold text-gray-500 uppercase tracking-wider">Acessos Recentes</p>' +
      '<div class="w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></div>' +
      '</div>' +
      '<div class="space-y-2 text-[10px] font-mono">' +
      '<div class="flex justify-between text-gray-500"><span>Admin Master</span><span id="sessionIp" class="text-cyan-400">-</span></div>' +
      '<div class="flex justify-between text-gray-500"><span>VPS Node</span><span class="text-gray-600">40.233.118.238</span></div>' +
      '</div>';
  }

  function removeLegacyProfileModals() {
    var legacySelectors = [
      '#modalPerfil',
      '#profileModal'
    ];

    legacySelectors.forEach(function (sel) {
      var nodes = document.querySelectorAll(sel);
      nodes.forEach(function (node) {
        if (node && node.getAttribute('data-global-profile-modal') !== '1') {
          node.remove();
        }
      });
    });
  }

  function ensureProfileModal() {
    if (document.getElementById('profileModal')) return;

    var modal = document.createElement('div');
    modal.id = 'profileModal';
    modal.className = 'fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-[200] hidden p-2';
    modal.setAttribute('data-global-profile-modal', '1');
    modal.innerHTML = '' +
      '<div class="bg-[#0f1119] rounded-3xl w-full max-w-sm max-h-[85vh] flex flex-col border border-gray-700 shadow-2xl">' +
      '<div class="flex justify-between items-center p-4 border-b border-gray-800 shrink-0">' +
      '<h2 class="text-lg font-bold text-white flex items-center gap-2"><i data-lucide="user-cog" class="w-5 h-5 text-blue-500"></i> Meu Perfil</h2>' +
      '<button type="button" onclick="closeProfileModal()" class="p-2 hover:bg-gray-800 rounded-lg"><i data-lucide="x" class="w-5 h-5 text-gray-400"></i></button>' +
      '</div>' +
      '<div class="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar">' +
      '<div><label class="block text-xs font-bold text-gray-500 uppercase mb-2">Usuário</label><input type="text" id="profileUsername" class="w-full bg-gray-900 border border-gray-700 rounded-xl px-4 py-2 text-sm"></div>' +
      '<div><label class="block text-xs font-bold text-gray-500 uppercase mb-2">E-mail</label><input type="email" id="profileEmail" class="w-full bg-gray-900 border border-gray-700 rounded-xl px-4 py-2 text-sm"></div>' +
      '<div class="border-t border-gray-800 pt-4 mt-2">' +
      '<p class="text-xs font-bold text-yellow-500 mb-3">Alterar Senha</p>' +
      '<div class="space-y-3">' +
      '<div><label class="block text-xs font-bold text-gray-500 uppercase mb-2">Senha Atual</label><input type="password" id="profileCurrentPassword" class="w-full bg-gray-900 border border-gray-700 rounded-xl px-4 py-2 text-sm"></div>' +
      '<div><label class="block text-xs font-bold text-gray-500 uppercase mb-2">Nova Senha</label><input type="password" id="profileNewPassword" class="w-full bg-gray-900 border border-gray-700 rounded-xl px-4 py-2 text-sm"></div>' +
      '<div><label class="block text-xs font-bold text-gray-500 uppercase mb-2">Confirmar Nova Senha</label><input type="password" id="profileConfirmPassword" class="w-full bg-gray-900 border border-gray-700 rounded-xl px-4 py-2 text-sm"></div>' +
      '</div></div></div>' +
      '<div class="p-4 border-t border-gray-800 flex justify-end gap-2 shrink-0">' +
      '<button type="button" onclick="closeProfileModal()" class="px-4 py-2 bg-gray-800 rounded-lg text-sm">Cancelar</button>' +
      '<button type="button" onclick="saveProfile()" class="px-4 py-2 bg-gradient-to-r from-blue-600 to-cyan-500 rounded-lg text-sm font-bold">Salvar Alterações</button>' +
      '</div></div>';

    document.body.appendChild(modal);
  }

  function openProfileModal() {
    var userStr = localStorage.getItem('user');
    if (userStr) {
      try {
        var user = JSON.parse(userStr);
        var usernameInput = document.getElementById('profileUsername');
        var emailInput = document.getElementById('profileEmail');
        if (usernameInput) usernameInput.value = user.username || '';
        if (emailInput) emailInput.value = user.email || '';
      } catch (_e) {}
    }

    var currentPassword = document.getElementById('profileCurrentPassword');
    var newPassword = document.getElementById('profileNewPassword');
    var confirmPassword = document.getElementById('profileConfirmPassword');
    if (currentPassword) currentPassword.value = '';
    if (newPassword) newPassword.value = '';
    if (confirmPassword) confirmPassword.value = '';

    var modal = document.getElementById('profileModal');
    if (modal) modal.classList.remove('hidden');

    if (typeof lucide !== 'undefined') {
      lucide.createIcons();
    }
  }

  function closeProfileModal() {
    var modal = document.getElementById('profileModal');
    if (modal) modal.classList.add('hidden');
  }

  function saveProfile() {
    var username = (document.getElementById('profileUsername') || {}).value || '';
    var email = (document.getElementById('profileEmail') || {}).value || '';
    var currentPassword = (document.getElementById('profileCurrentPassword') || {}).value || '';
    var newPassword = (document.getElementById('profileNewPassword') || {}).value || '';
    var confirmPassword = (document.getElementById('profileConfirmPassword') || {}).value || '';

    if (newPassword && newPassword !== confirmPassword) {
      alert('As novas senhas nao coincidem');
      return Promise.resolve();
    }

    if (newPassword && !currentPassword) {
      alert('Digite a senha atual para alterar');
      return Promise.resolve();
    }

    return fetch(window.API_URL + '/api/profile', {
      method: 'PUT',
      headers: authHeaders(),
      body: JSON.stringify({
        username: username,
        email: email,
        current_password: currentPassword || null,
        new_password: newPassword || null
      })
    })
      .then(function (res) {
        return res.json().then(function (data) {
          return { ok: res.ok, data: data };
        });
      })
      .then(function (result) {
        if (!result.ok) {
          alert(result.data.error || 'Erro ao atualizar perfil');
          return;
        }

        alert('Perfil atualizado com sucesso!');
        var user = {};
        try {
          user = JSON.parse(localStorage.getItem('user') || '{}');
        } catch (_e) {}
        user.username = username;
        user.email = email;
        localStorage.setItem('user', JSON.stringify(user));
        updateSessionInfo();
        closeProfileModal();
      })
      .catch(function () {
        alert('Erro ao atualizar perfil');
      });
  }

  function logout() {
    return fetch(window.API_URL + '/api/auth/logout', {
      method: 'POST',
      headers: authHeaders()
    })
      .catch(function () {
        return null;
      })
      .finally(function () {
        localStorage.removeItem('adminToken');
        localStorage.removeItem('token');
        localStorage.removeItem('ms_token');
        localStorage.removeItem('authToken');
        localStorage.removeItem('user');
        localStorage.removeItem('session_start');
        window.location.href = 'login.html';
      });
  }

  window.getToken = getToken;
  window.authHeaders = authHeaders;
  window.updateSessionInfo = updateSessionInfo;
  window.updateSessionIp = updateSessionIp;
  window.openProfileModal = openProfileModal;
  window.closeProfileModal = closeProfileModal;
  window.saveProfile = saveProfile;
  window.logout = logout;

  // Backward-compatible aliases used by legacy pages.
  window.openModalPerfil = openProfileModal;
  window.closeModalPerfil = closeProfileModal;
  window.salvarPerfil = saveProfile;
  window.sair = logout;

  document.addEventListener('DOMContentLoaded', function () {
    ensureScrollbarStyle();
    removeLegacyProfileModals();
    ensureProfileModal();
    ensureRecentAccessBlock();
    applyScrollbarClasses();
    updateSessionInfo();
    updateSessionIp();

    if (typeof lucide !== 'undefined') {
      lucide.createIcons();
    }
  });
})();
