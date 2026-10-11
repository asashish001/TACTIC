// Idle Session & Workstation Lock Management

import { updateUserUI, isAuthenticated } from './auth.js?v=1';

const IDLE_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes
let idleTimer = null;
let isLocked = false;

export function setupSession() {
  const resetEvents = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll'];
  resetEvents.forEach(evt => {
    document.addEventListener(evt, resetIdleTimer, { passive: true });
  });

  resetIdleTimer();
}

export function resetIdleTimer() {
  if (isLocked) return;

  if (idleTimer) {
    clearTimeout(idleTimer);
  }

  // Only lock if user is authenticated
  if (isAuthenticated()) {
    idleTimer = setTimeout(lockSession, IDLE_TIMEOUT_MS);
  }
}

export function lockSession() {
  if (!isAuthenticated()) return;

  isLocked = true;
  const overlay = document.getElementById('session-lock-overlay');
  if (overlay) {
    overlay.style.display = 'flex';
    updateUserUI();
    const passInput = document.getElementById('lock-session-password');
    if (passInput) {
      passInput.value = '';
      setTimeout(() => passInput.focus(), 100);
    }
    if (typeof lucide !== 'undefined') {
      lucide.createIcons({ root: overlay });
    }
  }
}

export function forceLockSession() {
  lockSession();
}

export function unlockSession() {
  isLocked = false;
  const overlay = document.getElementById('session-lock-overlay');
  if (overlay) {
    overlay.style.display = 'none';
  }
  resetIdleTimer();
}
