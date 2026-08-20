
(function () {
  const API_ORIGIN = 'https://needle-login.user2l1x.workers.dev';
  async function api(path, options = {}) {
    const headers = { ...(options.headers || {}) };
    if (options.body) headers['content-type'] = 'application/json';
    const response = await fetch(API_ORIGIN + path, { credentials: 'include', ...options, headers: { 'content-type': 'application/json', ...(options.headers || {}) } });
    const response = await fetch(API_ORIGIN + path, { credentials: 'include', ...options, headers });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || 'Request failed.');
    return result;
