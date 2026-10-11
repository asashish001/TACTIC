export function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  
  let icon = 'info';
  if (type === 'success') icon = 'check-circle';
  if (type === 'error') icon = 'alert-circle';

  toast.innerHTML = `
    <i data-lucide="${icon}" style="width: 20px; height: 20px;"></i>
    <div class="toast-content">${message}</div>
  `;

  container.appendChild(toast);
  if (typeof lucide !== 'undefined') lucide.createIcons();

  setTimeout(() => {
    if (toast.parentNode) {
      toast.parentNode.removeChild(toast);
    }
  }, 5000);
}

export function renderEmptyState(icon, title, description, isTable = true, colspan = 5) {
  const html = `
    <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 4rem 1rem; text-align: center; animation: fade-in 0.4s ease-out;">
      <div style="width: 64px; height: 64px; border-radius: 50%; background: rgba(59, 130, 246, 0.1); display: flex; align-items: center; justify-content: center; margin-bottom: 1rem; box-shadow: 0 0 20px rgba(59, 130, 246, 0.15); border: 1px solid rgba(59,130,246,0.2);">
        <i data-lucide="${icon}" style="width: 32px; height: 32px; color: var(--accent);"></i>
      </div>
      <h3 style="color: var(--text-main); font-size: 1.1rem; font-weight: 500; margin-bottom: 0.5rem; letter-spacing: 0.5px;">${title}</h3>
      <p style="color: var(--text-muted); max-width: 350px; margin: 0 auto; line-height: 1.5; font-size: 0.9rem;">${description}</p>
    </div>
  `;
  setTimeout(() => { if (typeof lucide !== 'undefined') lucide.createIcons(); }, 10);
  if (isTable) return `<tr><td colspan="${colspan}" style="border:none;">${html}</td></tr>`;
  return html;
}

let activeContextMenuData = null;

export function setupContextMenu() {
  const menu = document.getElementById('custom-context-menu');
  
  // Hide menu on document click
  document.addEventListener('click', (e) => {
    if (menu && menu.style.display === 'block') {
      menu.style.display = 'none';
    }
  });

  // Action: Send to AI Chat
  document.getElementById('ctx-send-to-chat')?.addEventListener('click', () => {
    if (!activeContextMenuData) return;
    const chatInput = document.getElementById('chat-input');
    if (chatInput) {
      chatInput.value = `Tell me about ${activeContextMenuData.type}: ${activeContextMenuData.label}`;
      // Switch to chat view
      document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
      document.getElementById('nav-chat')?.classList.add('active');
      document.querySelectorAll('.view').forEach(v => { v.classList.add('hidden'); v.style.display = 'none'; });
      const chatView = document.getElementById('view-chat');
      if (chatView) { chatView.classList.remove('hidden'); chatView.style.display = 'flex'; }
      setTimeout(() => chatInput.focus(), 100);
    }
  });

  // Action: Add to Report
  document.getElementById('ctx-add-to-report')?.addEventListener('click', () => {
    showToast(`Added ${activeContextMenuData?.label} to report`, 'success');
  });

  // Action: View Hex
  document.getElementById('ctx-view-hex')?.addEventListener('click', () => {
    showToast(`Hex viewer opened for ${activeContextMenuData?.label}`, 'info');
  });
}

export function showContextMenu(e, contextData) {
  e.preventDefault();
  const menu = document.getElementById('custom-context-menu');
  if (!menu) return;

  activeContextMenuData = contextData;
  
  menu.style.display = 'block';
  // Adjust position to stay within viewport
  let x = e.pageX;
  let y = e.pageY;
  if (x + 220 > window.innerWidth) x -= 220;
  if (y + 150 > window.innerHeight) y -= 150;

  menu.style.left = `${x}px`;
  menu.style.top = `${y}px`;
}

export function hideContextMenu() {
  const menu = document.getElementById('custom-context-menu');
  if (menu) menu.style.display = 'none';
}
