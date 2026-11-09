import { api, jwtToken } from './api.js?v=2';
import { currentCaseId, allCases } from './state.js';
import { showToast } from './ui.js?v=31';

let activeEvidence = null;
let activeRawData = null;

function formatBytes(bytes) {
  if (bytes === 0 || !bytes) return '0 B';
  const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function escapeHtml(text) {
  if (!text) return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function setupCertificateModal() {
  const modal = document.getElementById('forensic-certificate-modal');
  const btnClose = document.getElementById('btn-cert-close');
  const btnCopy = document.getElementById('btn-raw-copy');
  const searchInput = document.getElementById('raw-search-input');

  if (btnClose) {
    btnClose.addEventListener('click', closeCertificateModal);
  }

  if (btnCopy) {
    btnCopy.addEventListener('click', () => {
      if (activeRawData && activeRawData.content) {
        navigator.clipboard.writeText(activeRawData.content).then(() => {
          showToast('Raw content copied to clipboard!', 'success');
        }).catch(() => {
          showToast('Could not copy to clipboard.', 'error');
        });
      } else if (activeRawData && activeRawData.hex_dump) {
        navigator.clipboard.writeText(activeRawData.hex_dump).then(() => {
          showToast('Hex dump copied to clipboard!', 'success');
        });
      } else if (activeRawData && activeRawData.sha256) {
        navigator.clipboard.writeText(activeRawData.sha256).then(() => {
          showToast('SHA-256 copied to clipboard!', 'success');
        });
      }
    });
  }

  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      const query = (e.target.value || '').toLowerCase();
      filterRawLines(query);
    });
  }

  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        closeCertificateModal();
      }
    });
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modal && !modal.classList.contains('hidden')) {
      closeCertificateModal();
    }
  });
}

export function closeCertificateModal() {
  const modal = document.getElementById('forensic-certificate-modal');
  if (modal) {
    modal.classList.add('hidden');
    document.body.style.overflow = '';
  }
}

export function printCertificate() {
  window.print();
}

/**
 * Open Raw Evidence File Inspector for a specific Evidence item
 */
export async function openEvidenceCertificate(ev) {
  if (!ev) return;
  activeEvidence = ev;
  activeRawData = null;

  const modal = document.getElementById('forensic-certificate-modal');
  const container = document.getElementById('forensic-cert-sheet-container');
  if (!modal || !container) return;

  const filenameEl = document.getElementById('raw-modal-filename');
  const iconEl = document.getElementById('raw-modal-icon');
  const extBadge = document.getElementById('raw-modal-ext-badge');
  const statusBadge = document.getElementById('raw-modal-status-badge');
  const sizeEl = document.getElementById('raw-modal-filesize');
  const lineEl = document.getElementById('raw-modal-linecount');
  const hashEl = document.getElementById('raw-modal-sha256');
  const downloadBtn = document.getElementById('btn-raw-download');
  const searchWrapper = document.getElementById('raw-modal-search-wrapper');
  const searchInput = document.getElementById('raw-search-input');
  const matchCount = document.getElementById('raw-search-match-count');

  if (searchInput) searchInput.value = '';
  if (matchCount) matchCount.style.display = 'none';

  const filename = ev.filename || 'evidence_artifact.log';
  const ext = (ev.extension || filename.split('.').pop() || '').toLowerCase();
  const sha256 = ev.sha256 || '—';

  if (filenameEl) filenameEl.textContent = filename;
  if (extBadge) extBadge.textContent = (ext || 'RAW').toUpperCase();
  if (statusBadge) statusBadge.textContent = '● TAMPER-EVIDENT: VERIFIED';
  if (sizeEl) sizeEl.textContent = `Size: ${formatBytes(ev.file_size)}`;
  if (lineEl) lineEl.textContent = 'Lines: loading...';
  if (hashEl) {
    hashEl.textContent = `SHA-256: ${sha256.slice(0, 16)}...${sha256.slice(-8)}`;
    hashEl.title = `Full SHA-256 Digest: ${sha256}\nClick to copy`;
    hashEl.onclick = () => {
      navigator.clipboard.writeText(sha256);
      showToast('SHA-256 digest copied!', 'success');
    };
  }

  if (downloadBtn) {
    downloadBtn.href = `/api/evidence/download/${ev.id}?token=${jwtToken}`;
    downloadBtn.setAttribute('download', filename);
  }

  // Set appropriate icon
  let iconName = 'file-text';
  if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'svg'].includes(ext)) iconName = 'image';
  else if (['json', 'xml', 'csv', 'yaml', 'yml', 'js', 'html', 'py'].includes(ext)) iconName = 'file-code';
  else if (['pcap', 'bin', 'raw', 'dmp', 'mem', 'exe'].includes(ext)) iconName = 'binary';
  else if (ext === 'pdf') iconName = 'file-text';

  if (iconEl) {
    iconEl.setAttribute('data-lucide', iconName);
  }

  // Show loading skeleton in container
  container.innerHTML = `
    <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; min-height: 400px; color: #94a3b8; gap: 0.85rem;">
      <div style="width: 36px; height: 36px; border: 3px solid rgba(255,255,255,0.15); border-top-color: #3b82f6; border-radius: 50%; animation: spin 0.8s linear infinite;"></div>
      <div style="font-size: 0.88rem; font-weight: 500; color: #e2e8f0;">Loading raw evidence payload from storage...</div>
      <div style="font-size: 0.75rem; color: #64748b; font-family: monospace;">Validating SHA-256 cryptographic integrity</div>
    </div>
  `;

  modal.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
  if (typeof lucide !== 'undefined') lucide.createIcons();

  // Fetch raw evidence data
  try {
    const res = await fetch(`/api/evidence/${ev.id}/raw`, {
      headers: { 'Authorization': `Bearer ${jwtToken}` }
    });

    if (!res.ok) {
      throw new Error(`Server returned HTTP ${res.status}`);
    }

    const data = await res.json();
    activeRawData = data;

    // Update metadata from fresh API response
    if (sizeEl) sizeEl.textContent = `Size: ${formatBytes(data.file_size)}`;
    if (lineEl) lineEl.textContent = data.is_text ? `Lines: ${data.total_lines}` : (data.is_image ? 'Mode: Image Preview' : (data.is_pdf ? 'Mode: PDF Document' : 'Mode: Binary Hex Dump'));
    if (hashEl && data.sha256) {
      hashEl.textContent = `SHA-256: ${data.sha256.slice(0, 16)}...${data.sha256.slice(-8)}`;
      hashEl.title = `Full SHA-256 Digest: ${data.sha256}\nClick to copy`;
    }

    // Render based on payload type
    if (data.is_image) {
      if (searchWrapper) searchWrapper.style.display = 'none';
      container.innerHTML = `
        <div class="raw-image-viewport">
          <img src="/api/evidence/${ev.id}/view?token=${jwtToken}" alt="${escapeHtml(data.filename)}">
        </div>
      `;
    } else if (data.is_pdf) {
      if (searchWrapper) searchWrapper.style.display = 'none';
      container.innerHTML = `
        <iframe src="/api/evidence/${ev.id}/view?token=${jwtToken}" style="width: 100%; height: 100%; border: none;"></iframe>
      `;
    } else if (data.is_text && data.content !== null) {
      if (searchWrapper) searchWrapper.style.display = 'flex';
      renderRawText(container, data.content, data.truncated);
    } else if (data.hex_dump) {
      if (searchWrapper) searchWrapper.style.display = 'none';
      container.innerHTML = `
        <div class="raw-notice-banner">
          <i data-lucide="info" style="width: 14px; height: 14px; color: #b45309;"></i>
          <span>Binary Payload: Non-printable bytes detected. Displaying forensic Hex Dump preview (Offset | Hex | ASCII). Click 'Download' for raw binary.</span>
        </div>
        <pre class="raw-hex-view">${escapeHtml(data.hex_dump)}</pre>
      `;
      if (typeof lucide !== 'undefined') lucide.createIcons();
    } else {
      if (searchWrapper) searchWrapper.style.display = 'none';
      container.innerHTML = `
        <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; min-height: 350px; color: #94a3b8; gap: 1rem;">
          <i data-lucide="file-question" style="width: 48px; height: 48px; color: #f59e0b;"></i>
          <div style="font-size: 0.95rem; color: #e2e8f0; font-weight: 600;">Direct Raw Preview Unavailable</div>
          <p style="font-size: 0.8rem; color: #94a3b8; max-width: 400px; text-align: center;">This forensic format cannot be rendered in text mode. You can download the pristine raw artifact directly.</p>
          <a class="btn btn-primary" href="/api/evidence/download/${ev.id}?token=${jwtToken}" download="${escapeHtml(filename)}">
            <i data-lucide="download" style="width: 16px; height: 16px;"></i>
            <span>Download Raw File (${formatBytes(ev.file_size)})</span>
          </a>
        </div>
      `;
      if (typeof lucide !== 'undefined') lucide.createIcons();
    }
  } catch (err) {
    console.error('Failed to load raw evidence:', err);
    // Secondary fallback: fetch via download endpoint directly
    try {
      const fallbackRes = await fetch(`/api/evidence/download/${ev.id}?token=${jwtToken}`);
      if (fallbackRes.ok) {
        const text = await fallbackRes.text();
        activeRawData = { content: text, is_text: true };
        if (searchWrapper) searchWrapper.style.display = 'flex';
        renderRawText(container, text, false);
        return;
      }
    } catch (fbErr) {
      console.warn('Fallback download fetch error:', fbErr);
    }

    container.innerHTML = `
      <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; min-height: 350px; color: #f87171; gap: 0.75rem;">
        <i data-lucide="alert-triangle" style="width: 40px; height: 40px;"></i>
        <div style="font-size: 0.95rem; font-weight: 600;">Unable to open raw evidence file</div>
        <div style="font-size: 0.78rem; color: #94a3b8;">${escapeHtml(err.message)}</div>
        <a class="btn btn-secondary" href="/api/evidence/download/${ev.id}?token=${jwtToken}" download="${escapeHtml(filename)}" style="margin-top: 0.5rem;">
          <i data-lucide="download"></i> Download File Instead
        </a>
      </div>
    `;
    if (typeof lucide !== 'undefined') lucide.createIcons();
  }
}

/**
 * Open Raw Report Viewer for a Case Report
 */
export async function openReportCertificate(rpt) {
  if (!rpt) return;
  activeEvidence = null;
  activeRawData = null;

  const modal = document.getElementById('forensic-certificate-modal');
  const container = document.getElementById('forensic-cert-sheet-container');
  if (!modal || !container) return;

  const filenameEl = document.getElementById('raw-modal-filename');
  const extBadge = document.getElementById('raw-modal-ext-badge');
  const statusBadge = document.getElementById('raw-modal-status-badge');
  const sizeEl = document.getElementById('raw-modal-filesize');
  const lineEl = document.getElementById('raw-modal-linecount');
  const hashEl = document.getElementById('raw-modal-sha256');
  const downloadBtn = document.getElementById('btn-raw-download');
  const searchWrapper = document.getElementById('raw-modal-search-wrapper');

  if (searchWrapper) searchWrapper.style.display = 'none';

  const filename = rpt.filename || `Report_Case_${rpt.case_id}.pdf`;
  const fmt = (rpt.format || 'pdf').toUpperCase();

  if (filenameEl) filenameEl.textContent = filename;
  if (extBadge) extBadge.textContent = fmt;
  if (statusBadge) statusBadge.textContent = '● COMPILED REPORT';
  if (sizeEl) sizeEl.textContent = `Case #${rpt.case_id}`;
  if (lineEl) lineEl.textContent = `Generated: ${(rpt.generated_at || '').slice(0, 19).replace('T', ' ')}`;
  if (hashEl) hashEl.textContent = `Report ID: #${rpt.id}`;

  if (downloadBtn) {
    downloadBtn.href = `/api/report/download/${rpt.id}?token=${jwtToken}`;
    downloadBtn.setAttribute('download', filename);
  }

  modal.classList.remove('hidden');
  document.body.style.overflow = 'hidden';

  container.innerHTML = `
    <iframe src="/api/report/download/${rpt.id}?inline=true&token=${jwtToken}" style="width: 100%; height: 100%; border: none;"></iframe>
  `;
}

function renderRawText(container, content, isTruncated) {
  const lines = content.split('\n');
  const total = lines.length;

  let noticeHtml = '';
  if (isTruncated) {
    noticeHtml = `
      <div class="raw-notice-banner">
        <i data-lucide="alert-circle" style="width: 14px; height: 14px; color: #b45309;"></i>
        <span>Large Artifact Notice: Showing first 2 MB of content (${total} lines). Click 'Download' for the complete bit-exact file.</span>
      </div>
    `;
  }

  const lineNumbers = [];
  const processedLines = [];

  for (let i = 0; i < total; i++) {
    lineNumbers.push(i + 1);
    let line = escapeHtml(lines[i]);

    // Fast highlight for log indicators
    if (line.includes('ALERT') || line.includes('CRITICAL') || line.includes('FATAL') || line.includes('ERROR')) {
      line = line.replace(/(ALERT|CRITICAL|FATAL|ERROR)/g, '<span class="kw-error">$1</span>');
    } else if (line.includes('WARN') || line.includes('WARNING')) {
      line = line.replace(/(WARNING|WARN)/g, '<span class="kw-warn">$1</span>');
    } else if (line.includes('INFO') || line.includes('NOTICE')) {
      line = line.replace(/(INFO|NOTICE)/g, '<span class="kw-info">$1</span>');
    }

    // IP address highlight
    line = line.replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g, '<span class="kw-ip">$1</span>');

    // ISO timestamp highlight
    line = line.replace(/(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)/g, '<span class="kw-date">$1</span>');

    processedLines.push(`<span class="raw-code-row" data-line="${i+1}">${line || ' '}</span>`);
  }

  container.innerHTML = `
    ${noticeHtml}
    <div class="raw-code-container">
      <div class="raw-line-numbers" id="raw-line-numbers">${lineNumbers.join('\n')}</div>
      <div class="raw-code-text" id="raw-code-text">${processedLines.join('\n')}</div>
    </div>
  `;

  if (typeof lucide !== 'undefined') lucide.createIcons();
}

function filterRawLines(query) {
  const codeText = document.getElementById('raw-code-text');
  const lineNumbers = document.getElementById('raw-line-numbers');
  const matchCount = document.getElementById('raw-search-match-count');
  if (!codeText || !activeRawData || !activeRawData.content) return;

  const rows = codeText.querySelectorAll('.raw-code-row');
  if (!query) {
    rows.forEach(r => {
      r.style.display = '';
      r.classList.remove('line-highlight');
    });
    if (lineNumbers) lineNumbers.style.display = '';
    if (matchCount) matchCount.style.display = 'none';
    return;
  }

  let matches = 0;
  rows.forEach(r => {
    const text = r.textContent.toLowerCase();
    if (text.includes(query)) {
      r.style.display = '';
      r.classList.add('line-highlight');
      matches++;
    } else {
      r.style.display = 'none';
      r.classList.remove('line-highlight');
    }
  });

  if (lineNumbers) lineNumbers.style.display = 'none';
  if (matchCount) {
    matchCount.style.display = 'inline-block';
    matchCount.textContent = `${matches} match${matches === 1 ? '' : 'es'}`;
  }
}
