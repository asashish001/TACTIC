import {
  getAccessToken,
  getRefreshToken,
  setSession,
  clearSession,
  showLoginModal
} from './auth.js?v=1';

export let jwtToken = getAccessToken();

export function setJwtToken(token) {
  jwtToken = token;
}

export async function api(method, url, data, isRetry = false) {
  let token = getAccessToken();
  jwtToken = token;

  if (!token) {
    const refreshTok = getRefreshToken();
    if (refreshTok) {
      try {
        const refreshRes = await fetch('/api/auth/refresh', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: refreshTok })
        });
        if (refreshRes.ok) {
          const authData = await refreshRes.json();
          setSession(authData.access_token, authData.refresh_token);
          token = authData.access_token;
          jwtToken = token;
        } else {
          clearSession();
          showLoginModal('Session expired. Please sign in to continue.');
          throw new Error('Authentication required.');
        }
      } catch (err) {
        clearSession();
        showLoginModal('Session expired. Please sign in to continue.');
        throw err;
      }
    } else {
      showLoginModal('Authentication required. Please sign in.');
      throw new Error('Authentication required. Please sign in.');
    }
  }

  const headers = { 'Authorization': `Bearer ${token}` };
  if (data) headers['Content-Type'] = 'application/json';
  const options = { method, headers };
  if (data) options.body = JSON.stringify(data);

  const response = await fetch(url, options);
  if (!response.ok) {
    if (response.status === 401 && !isRetry) {
      // Access token expired, attempt refresh token rotation
      const refreshTok = getRefreshToken();
      if (refreshTok) {
        try {
          const refreshRes = await fetch('/api/auth/refresh', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refresh_token: refreshTok })
          });
          if (refreshRes.ok) {
            const authData = await refreshRes.json();
            setSession(authData.access_token, authData.refresh_token);
            jwtToken = authData.access_token;
            return await api(method, url, data, true);
          }
        } catch (_) {}
      }
      clearSession();
      showLoginModal('Your session has expired. Please sign in again.');
      throw new Error('Session expired. Please log in again.');
    }

    const errorBody = await response.text();
    let errorDetail = response.statusText;
    try {
      const errJson = JSON.parse(errorBody);
      if (errJson.detail) {
        errorDetail = Array.isArray(errJson.detail)
          ? errJson.detail.map(d => d.msg || d).join(', ')
          : errJson.detail;
      }
    } catch (_) {
      if (errorBody) errorDetail = errorBody;
    }
    throw new Error(`API Error: ${errorDetail}`);
  }

  return await response.json();
}
