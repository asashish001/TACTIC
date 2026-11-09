import { api, jwtToken } from './api.js?v=2';
import { showToast, renderEmptyState } from './ui.js';
import { currentCaseId } from './state.js';
import { openReportCertificate } from './certificate.js?v=2';

const reportsMap = new Map();

export function setupReports() {
  const reportsList = document.getElementById('reports-list');
  const btnGenerateReport = document.getElementById('btn-generate-report');

  if (reportsList) {
    reportsList.addEventListener('click', (e) => {
      const link = e.target.closest('.report-cert-link, .btn-report-cert-open');
      if (link) {
        e.preventDefault();
        const id = link.getAttribute('data-id');
        const rpt = reportsMap.get(String(id));
        if (rpt) {
          openReportCertificate(rpt);
        }
      }
    });
  }

  window.loadReports = async function () {
    if (!reportsList || !currentCaseId) return;

    try {
      reportsList.innerHTML = `
      <tr class="skeleton-row">
        <td><div class="skeleton-box short"></div></td>
        <td><div class="skeleton-box medium"></div></td>
        <td><div class="skeleton-box short"></div></td>
        <td><div class="skeleton-box"></div></td>
        <td><div class="skeleton-box short"></div></td>
      </tr>
      <tr class="skeleton-row">
        <td><div class="skeleton-box short"></div></td>
        <td><div class="skeleton-box medium"></div></td>
        <td><div class="skeleton-box short"></div></td>
        <td><div class="skeleton-box"></div></td>
        <td><div class="skeleton-box short"></div></td>
      </tr>
    `;
      const response = await api('GET', `/api/report?case_id=${currentCaseId}`);

      if (!response.items || response.items.length === 0) {
        reportsList.innerHTML = renderEmptyState('file-text', 'No Reports Generated', 'Select a case and click "Generate Report" to compile findings.', true, 5);
        return;
      }

      reportsList.innerHTML = '';
      response.items.forEach(rpt => {
        reportsMap.set(String(rpt.id), rpt);
        const tr = document.createElement('tr');
        const tokenStr = jwtToken || '';

        const dateObj = new Date(rpt.generated_at + 'Z');
        const dateStr = dateObj.toLocaleDateString(undefined, { month: 'short', day: '2-digit', year: 'numeric' });
        const timeStr = dateObj.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });

        tr.innerHTML = `
          <td>
            <a href="#" class="report-cert-link" data-id="${rpt.id}" title="Click to view report" style="color: var(--accent); font-weight: 600; cursor: pointer; display: inline-flex; align-items: center; gap: 0.4rem; text-decoration: none;">
              <i data-lucide="file-text" style="width: 15px; height: 15px; color: var(--accent);"></i>
              <span style="text-decoration: underline;">${rpt.filename || `Report #${rpt.id}`}</span>
            </a>
          </td>
          <td><span class="badge" style="font-size: 0.72rem; text-transform: uppercase;">${rpt.format || 'pdf'}</span></td>
          <td>${dateStr} <span style="color:var(--text-muted); font-size:0.85em;">${timeStr}</span></td>
          <td><span class="badge success" style="font-size: 0.72rem;">● Certified</span></td>
          <td>
            <div style="display: flex; align-items: center; gap: 0.35rem;">
              <button class="btn btn-sm btn-report-cert-open" data-id="${rpt.id}" title="View Report Document" style="padding: 0.25rem 0.55rem; font-size: 0.75rem; display: inline-flex; align-items: center; gap: 0.25rem; background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; cursor: pointer; border-radius: 4px;">
                <i data-lucide="eye" style="width: 13px; height: 13px;"></i>
                <span>View Report</span>
              </button>
              <a href="/api/report/download/${rpt.id}?token=${tokenStr}" target="_blank" class="btn btn-secondary" style="padding: 0.25rem 0.6rem; font-size: 0.75rem; display:inline-flex; align-items:center; text-decoration:none;">
                <i data-lucide="download" style="width:13px;height:13px;"></i> <span style="margin-left:4px;">Download</span>
              </a>
            </div>
          </td>
        `;
        reportsList.appendChild(tr);
      });
      if (typeof lucide !== 'undefined') lucide.createIcons();
    } catch (err) {
      console.error(err);
      reportsList.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--danger);">Failed to load reports.</td></tr>';
    }
  };

  const btnGenerateDocx = document.getElementById('btn-generate-report-docx');
  const btnGeneratePdf = document.getElementById('btn-generate-report-pdf');

  async function handleGenerateReport(format, button) {
    if (!currentCaseId) {
      showToast("Please open a case to generate a report.", 'error');
      return;
    }
    
    if (btnGenerateDocx) btnGenerateDocx.disabled = true;
    if (btnGeneratePdf) btnGeneratePdf.disabled = true;

    const prevHtml = button.innerHTML;
    button.innerHTML = '<i data-lucide="loader" class="lucide-spin" style="width:18px;height:18px;"></i><span>Generating...</span>';
    if (typeof lucide !== 'undefined') lucide.createIcons();

    try {
      const created = await api('POST', '/api/report', { case_id: currentCaseId, format: format });
      await window.loadReports();
      if (created) {
        openReportCertificate(created);
      }
    } catch (err) {
      showToast("Failed to generate report: " + err.message, 'error');
    } finally {
      if (btnGenerateDocx) btnGenerateDocx.disabled = false;
      if (btnGeneratePdf) btnGeneratePdf.disabled = false;
      button.innerHTML = prevHtml;
      if (typeof lucide !== 'undefined') lucide.createIcons();
    }
  }

  if (btnGenerateDocx) {
    btnGenerateDocx.addEventListener('click', () => handleGenerateReport('docx', btnGenerateDocx));
  }
  if (btnGeneratePdf) {
    btnGeneratePdf.addEventListener('click', () => handleGenerateReport('pdf', btnGeneratePdf));
  }
}
