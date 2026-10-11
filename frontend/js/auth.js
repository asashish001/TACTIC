// Authentication & Session Management Module for TACTIC

import { showToast } from './ui.js';

const ACCESS_TOKEN_KEY = 'tactic_access_token';
const REFRESH_TOKEN_KEY = 'tactic_refresh_token';
const USER_KEY = 'tactic_user';

let currentAccessToken = localStorage.getItem(ACCESS_TOKEN_KEY) || null;
let currentRefreshToken = localStorage.getItem(REFRESH_TOKEN_KEY) || null;
let cachedUser = null;

try {
  const storedUser = localStorage.getItem(USER_KEY);
  if (storedUser) {
    cachedUser = JSON.parse(storedUser);
  }
} catch (_) {
  cachedUser = null;
}

export function getAccessToken() {
  return currentAccessToken;
}

export function getRefreshToken() {
  return currentRefreshToken;
}

export function getCurrentUser() {
  return cachedUser;
}

export function isAuthenticated() {
  return !!(currentAccessToken || currentRefreshToken);
}

export function setSession(accessToken, refreshToken, user = null) {
  if (accessToken) {
    currentAccessToken = accessToken;
    localStorage.setItem(ACCESS_TOKEN_KEY, accessToken);
  }
  if (refreshToken) {
    currentRefreshToken = refreshToken;
    localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
  }
  if (user) {
    cachedUser = user;
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  }
  updateUserUI();
}

export function clearSession() {
  currentAccessToken = null;
  currentRefreshToken = null;
  cachedUser = null;
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
  updateUserUI();
}

export async function login(username, password) {
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || 'Login failed. Please check your credentials.');
  }

  const tokens = await res.json();
  currentAccessToken = tokens.access_token;
  currentRefreshToken = tokens.refresh_token;
  localStorage.setItem(ACCESS_TOKEN_KEY, tokens.access_token);
  localStorage.setItem(REFRESH_TOKEN_KEY, tokens.refresh_token);

  // Fetch current user details
  const user = await fetchCurrentUser();
  setSession(tokens.access_token, tokens.refresh_token, user);
  return { tokens, user };
}

export async function register(username, fullName, password) {
  const res = await fetch('/api/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username,
      full_name: fullName,
      password,
      role: 'investigator'
    })
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    let msg = errorData.detail;
    if (Array.isArray(msg)) {
      msg = msg.map(m => m.msg || m).join(', ');
    }
    throw new Error(msg || 'Registration failed. Please check inputs.');
  }

  return await res.json();
}

export async function logout() {
  const refreshTok = currentRefreshToken;
  clearSession();
  
  if (refreshTok) {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshTok })
      });
    } catch (_) {}
  }

  showLoginModal('You have been signed out.');
  showToast('Signed out successfully.', 'info');
}

export async function refreshSessionTokens() {
  if (!currentRefreshToken) {
    throw new Error('No refresh token available');
  }

  const res = await fetch('/api/auth/refresh', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: currentRefreshToken })
  });

  if (!res.ok) {
    clearSession();
    throw new Error('Session expired. Please log in again.');
  }

  const data = await res.json();
  setSession(data.access_token, data.refresh_token);
  return data;
}

export async function fetchCurrentUser() {
  if (!currentAccessToken) return null;
  try {
    const res = await fetch('/api/users/me', {
      headers: { 'Authorization': `Bearer ${currentAccessToken}` }
    });
    if (res.ok) {
      const user = await res.json();
      cachedUser = user;
      localStorage.setItem(USER_KEY, JSON.stringify(user));
      updateUserUI();
      return user;
    }
  } catch (err) {
    console.warn('Could not fetch user profile:', err);
  }
  return cachedUser;
}

export function showLoginModal(message = '', prefillUsername = '') {
  const modal = document.getElementById('auth-modal');
  if (!modal) return;

  const errorEl = document.getElementById('auth-error-msg');
  if (errorEl) {
    if (message) {
      errorEl.textContent = message;
      errorEl.style.display = 'block';
    } else {
      errorEl.style.display = 'none';
    }
  }

  if (prefillUsername) {
    const usernameInput = document.getElementById('login-username');
    if (usernameInput) usernameInput.value = prefillUsername;
  }

  modal.classList.remove('hidden');
  modal.style.display = 'flex';
  if (typeof lucide !== 'undefined') {
    lucide.createIcons({ root: modal });
  }
}

export function hideLoginModal() {
  const modal = document.getElementById('auth-modal');
  if (modal) {
    modal.classList.add('hidden');
    modal.style.display = 'none';
  }
}

export function updateUserUI() {
  const user = cachedUser;
  
  // Sidebar elements
  const userContainer = document.getElementById('sidebar-user-profile');
  const userNameEl = document.getElementById('sidebar-user-name');
  const userRoleEl = document.getElementById('sidebar-user-role');
  const userAvatarEl = document.getElementById('sidebar-user-avatar');

  if (user) {
    if (userContainer) userContainer.style.display = 'flex';
    if (userNameEl) userNameEl.textContent = user.full_name || user.username;
    if (userRoleEl) {
      userRoleEl.textContent = (user.role || 'Investigator').toUpperCase();
      userRoleEl.className = `badge badge-${user.role === 'admin' ? 'danger' : 'info'}`;
    }
    if (userAvatarEl) {
      const initials = (user.full_name || user.username || 'U')
        .split(' ')
        .map(n => n[0])
        .join('')
        .slice(0, 2)
        .toUpperCase();
      userAvatarEl.textContent = initials;
    }
  } else {
    if (userContainer) userContainer.style.display = 'none';
  }

  // Session lock overlay user info
  const lockUserAvatar = document.getElementById('lock-user-avatar');
  const lockUserName = document.getElementById('lock-user-name');
  if (user) {
    if (lockUserName) lockUserName.textContent = user.full_name || user.username;
    if (lockUserAvatar) {
      const initials = (user.full_name || user.username || 'U')
        .split(' ')
        .map(n => n[0])
        .join('')
        .slice(0, 2)
        .toUpperCase();
      lockUserAvatar.textContent = initials;
    }
  }

  // Settings page profile card
  const settingsUsername = document.getElementById('profile-username');
  const settingsFullName = document.getElementById('profile-fullname');
  const settingsRole = document.getElementById('profile-role');
  const settingsTimezone = document.getElementById('profile-timezone');
  if (user) {
    if (settingsUsername) settingsUsername.textContent = user.username || '—';
    if (settingsFullName) settingsFullName.textContent = user.full_name || '—';
    if (settingsRole) settingsRole.textContent = (user.role || 'investigator').toUpperCase();
    if (settingsTimezone) settingsTimezone.textContent = user.timezone || 'UTC';
  }
}

export function setupAuth() {
  const modal = document.getElementById('auth-modal');
  if (!modal) return;

  // Tabs
  const tabLogin = document.getElementById('auth-tab-login');
  const tabRegister = document.getElementById('auth-tab-register');
  const formLogin = document.getElementById('auth-login-form');
  const formRegister = document.getElementById('auth-register-form');
  const errorMsg = document.getElementById('auth-error-msg');
  const successMsg = document.getElementById('auth-success-msg');

  function switchTab(isLogin) {
    if (errorMsg) errorMsg.style.display = 'none';
    if (successMsg) successMsg.style.display = 'none';
    if (isLogin) {
      tabLogin?.classList.add('active');
      tabRegister?.classList.remove('active');
      formLogin?.classList.remove('hidden');
      formRegister?.classList.add('hidden');
    } else {
      tabLogin?.classList.remove('active');
      tabRegister?.classList.add('active');
      formLogin?.classList.add('hidden');
      formRegister?.classList.remove('hidden');
    }
  }

  tabLogin?.addEventListener('click', () => switchTab(true));
  tabRegister?.addEventListener('click', () => switchTab(false));

  // Password visibility toggles
  document.querySelectorAll('.btn-toggle-password').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-target');
      const input = document.getElementById(targetId);
      if (input) {
        const isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';
        const icon = btn.querySelector('i');
        if (icon) {
          icon.setAttribute('data-lucide', isPassword ? 'eye-off' : 'eye');
          if (typeof lucide !== 'undefined') {
            lucide.createIcons({ root: btn });
          }
        }
      }
    });
  });

  // Demo auto-fill button
  const btnDemoFill = document.getElementById('btn-auth-demo-fill');
  if (btnDemoFill) {
    btnDemoFill.addEventListener('click', () => {
      const userInput = document.getElementById('login-username');
      const passInput = document.getElementById('login-password');
      if (userInput) userInput.value = 'admin';
      if (passInput) passInput.value = 'ChangeMe123!';
      showToast('Admin credentials filled.', 'info');
    });
  }

  // Registration password validator live checks
  const regPasswordInput = document.getElementById('register-password');
  if (regPasswordInput) {
    regPasswordInput.addEventListener('input', () => {
      const val = regPasswordInput.value;
      const ruleLen = document.getElementById('rule-len');
      const ruleUpper = document.getElementById('rule-upper');
      const ruleLower = document.getElementById('rule-lower');
      const ruleNum = document.getElementById('rule-num');
      const ruleSpecial = document.getElementById('rule-special');

      if (ruleLen) ruleLen.classList.toggle('valid', val.length >= 8);
      if (ruleUpper) ruleUpper.classList.toggle('valid', /[A-Z]/.test(val));
      if (ruleLower) ruleLower.classList.toggle('valid', /[a-z]/.test(val));
      if (ruleNum) ruleNum.classList.toggle('valid', /\d/.test(val));
      if (ruleSpecial) ruleSpecial.classList.toggle('valid', /[^a-zA-Z0-9]/.test(val));
    });
  }

  // Login Submit
  formLogin?.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (errorMsg) errorMsg.style.display = 'none';
    if (successMsg) successMsg.style.display = 'none';

    const username = document.getElementById('login-username')?.value.trim();
    const password = document.getElementById('login-password')?.value;
    const submitBtn = formLogin.querySelector('button[type="submit"]');

    if (!username || !password) {
      if (errorMsg) {
        errorMsg.textContent = 'Please enter both username and password.';
        errorMsg.style.display = 'block';
      }
      return;
    }

    try {
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i data-lucide="loader" class="spin"></i> Authenticating...';
        if (typeof lucide !== 'undefined') lucide.createIcons({ root: submitBtn });
      }

      const { user } = await login(username, password);
      hideLoginModal();
      showToast(`Welcome back, ${user.full_name || user.username}!`, 'success');

      // Refresh cases list or views if available
      if (window.loadCases) window.loadCases();
      if (window.loadDashboard) window.loadDashboard();
      if (window.loadSettings) window.loadSettings();

    } catch (err) {
      if (errorMsg) {
        errorMsg.textContent = err.message || 'Authentication failed.';
        errorMsg.style.display = 'block';
      }
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i data-lucide="log-in"></i> Sign In to Workstation';
        if (typeof lucide !== 'undefined') lucide.createIcons({ root: submitBtn });
      }
    }
  });

  // Register Submit
  formRegister?.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (errorMsg) errorMsg.style.display = 'none';
    if (successMsg) successMsg.style.display = 'none';

    const username = document.getElementById('register-username')?.value.trim();
    const fullName = document.getElementById('register-fullname')?.value.trim();
    const password = document.getElementById('register-password')?.value;
    const submitBtn = formRegister.querySelector('button[type="submit"]');

    if (!username || !fullName || !password) {
      if (errorMsg) {
        errorMsg.textContent = 'Please fill out all required fields.';
        errorMsg.style.display = 'block';
      }
      return;
    }

    try {
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i data-lucide="loader" class="spin"></i> Creating Account...';
        if (typeof lucide !== 'undefined') lucide.createIcons({ root: submitBtn });
      }

      await register(username, fullName, password);
      
      // Switch back to login tab with success note
      switchTab(true);
      if (successMsg) {
        successMsg.textContent = `Account created successfully for @${username}! You may now sign in.`;
        successMsg.style.display = 'block';
      }
      const loginUserInput = document.getElementById('login-username');
      if (loginUserInput) loginUserInput.value = username;
      const loginPassInput = document.getElementById('login-password');
      if (loginPassInput) {
        loginPassInput.value = '';
        loginPassInput.focus();
      }

    } catch (err) {
      if (errorMsg) {
        errorMsg.textContent = err.message || 'Registration failed.';
        errorMsg.style.display = 'block';
      }
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i data-lucide="user-plus"></i> Register Investigator Account';
        if (typeof lucide !== 'undefined') lucide.createIcons({ root: submitBtn });
      }
    }
  });

  // Sidebar Logout Button
  const btnLogout = document.getElementById('btn-sidebar-logout');
  if (btnLogout) {
    btnLogout.addEventListener('click', (e) => {
      e.preventDefault();
      logout();
    });
  }

  // Sidebar Manual Lock Button
  const btnLockSidebar = document.getElementById('btn-sidebar-lock');
  if (btnLockSidebar) {
    btnLockSidebar.addEventListener('click', (e) => {
      e.preventDefault();
      const overlay = document.getElementById('session-lock-overlay');
      if (overlay) {
        overlay.style.display = 'flex';
        updateUserUI();
        if (typeof lucide !== 'undefined') lucide.createIcons({ root: overlay });
      }
    });
  }

  // Lock Screen Unlock via Password
  const btnUnlock = document.getElementById('btn-unlock-session');
  const inputUnlockPass = document.getElementById('lock-session-password');
  const unlockError = document.getElementById('lock-unlock-error');
  
  if (btnUnlock && inputUnlockPass) {
    btnUnlock.addEventListener('click', async () => {
      if (!cachedUser) {
        // No cached user, just hide overlay and show login modal
        const overlay = document.getElementById('session-lock-overlay');
        if (overlay) overlay.style.display = 'none';
        showLoginModal();
        return;
      }

      const password = inputUnlockPass.value;
      if (!password) {
        if (unlockError) {
          unlockError.textContent = 'Please enter your password.';
          unlockError.style.display = 'block';
        }
        return;
      }

      try {
        btnUnlock.disabled = true;
        btnUnlock.innerHTML = '<i data-lucide="loader" class="spin"></i> Verifying...';
        if (typeof lucide !== 'undefined') lucide.createIcons({ root: btnUnlock });

        await login(cachedUser.username, password);

        // Success - dismiss lock screen
        inputUnlockPass.value = '';
        if (unlockError) unlockError.style.display = 'none';
        const overlay = document.getElementById('session-lock-overlay');
        if (overlay) overlay.style.display = 'none';
        showToast('Workstation unlocked.', 'success');

      } catch (err) {
        if (unlockError) {
          unlockError.textContent = err.message || 'Incorrect password.';
          unlockError.style.display = 'block';
        }
      } finally {
        btnUnlock.disabled = false;
        btnUnlock.innerHTML = '<i data-lucide="key"></i> Unlock Session';
        if (typeof lucide !== 'undefined') lucide.createIcons({ root: btnUnlock });
      }
    });

    inputUnlockPass.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        btnUnlock.click();
      }
    });
  }

  // Lock Screen Switch Account / Logout
  const btnLockLogout = document.getElementById('btn-lock-logout');
  if (btnLockLogout) {
    btnLockLogout.addEventListener('click', () => {
      const overlay = document.getElementById('session-lock-overlay');
      if (overlay) overlay.style.display = 'none';
      logout();
    });
  }

  // Settings Change Password Form
  const formChangePass = document.getElementById('form-change-password');
  if (formChangePass) {
    formChangePass.addEventListener('submit', async (e) => {
      e.preventDefault();
      const currentPass = document.getElementById('current-password')?.value;
      const newPass = document.getElementById('new-password')?.value;
      const confirmPass = document.getElementById('confirm-password')?.value;
      const statusEl = document.getElementById('change-password-status');

      if (statusEl) statusEl.style.display = 'none';

      if (newPass !== confirmPass) {
        if (statusEl) {
          statusEl.textContent = 'New passwords do not match.';
          statusEl.className = 'status-banner danger';
          statusEl.style.display = 'block';
        }
        return;
      }

      try {
        const res = await fetch('/api/users/me/change-password', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${currentAccessToken}`
          },
          body: JSON.stringify({
            current_password: currentPass,
            new_password: newPass
          })
        });

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.detail || 'Password change failed.');
        }

        formChangePass.reset();
        showToast('Password changed successfully! Please log in with your new password.', 'success');
        logout();

      } catch (err) {
        if (statusEl) {
          statusEl.textContent = err.message;
          statusEl.className = 'status-banner danger';
          statusEl.style.display = 'block';
        }
      }
    });
  }

  // Initial check on load
  if (isAuthenticated()) {
    fetchCurrentUser().then(() => {
      hideLoginModal();
    }).catch(() => {
      showLoginModal('Session expired. Please log in.');
    });
  } else {
    showLoginModal();
  }
}
