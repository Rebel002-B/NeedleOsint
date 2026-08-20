/* Public client for the Needle authentication Worker. No secrets belong here. */
(function () {
  const API_ORIGIN = 'https://needle-login.user2l1x.workers.dev';
  async function api(path, options = {}) {
    const response = await fetch(API_ORIGIN + path, { credentials: 'include', ...options, headers: { 'content-type': 'application/json', ...(options.headers || {}) } });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || 'Request failed.');
    return result;
  }
  const nextPage = () => encodeURIComponent(location.pathname.split('/').pop() || 'index.html');
  window.NeedleAuth = {
    api,
    getPublicConfig: () => api('/api/public-config'),
    register: (email, password, turnstileToken) => api('/api/auth/register', { method: 'POST', body: JSON.stringify({ email, password, turnstileToken }) }),
    login: (email, password, turnstileToken) => api('/api/auth/login', { method: 'POST', body: JSON.stringify({ email, password, turnstileToken }) }),
    verify: token => api('/api/auth/verify', { method: 'POST', body: JSON.stringify({ token }) }),
    current: async () => (await api('/api/auth/me')).user,
    logout: () => api('/api/auth/logout', { method: 'POST', body: '{}' }),
    async requireUser() { const user = await this.current(); if (!user) { location.replace('login.html?next=' + nextPage()); return null; } return user; },
    async requireAdmin() { const user = await this.requireUser(); if (!user || user.role !== 'admin') { location.replace('403.html'); return null; } return user; },
    listUsers: () => api('/api/admin/users').then(result => result.users),
    updateUser: (id, update) => api('/api/admin/users/' + encodeURIComponent(id) + '/restriction', { method: 'POST', body: JSON.stringify(update) })
  };
})();
