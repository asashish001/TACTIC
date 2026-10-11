import { api } from './api.js?v=2';
import { showToast, renderEmptyState } from './ui.js';
import { currentCaseId } from './state.js';

let lastDashboardUpdate = null;
let freshnessInterval = null;

function updateFreshnessIndicator() {
    if (!lastDashboardUpdate) return;
    const el = document.getElementById('data-freshness');
    if (!el) return;
    const diffMs = new Date() - lastDashboardUpdate;
    const diffMins = Math.floor(diffMs / 60000);
    if (diffMins === 0) {
        el.textContent = 'Last Updated: Just now';
    } else {
        el.textContent = `Last Updated: ${diffMins} min${diffMins > 1 ? 's' : ''} ago`;
    }
}

export function setupDashboard() {
    window.loadDashboardData = async function() {
    try {
      let dashboardUrl = '/api/dashboard';
      if (currentCaseId) {
        dashboardUrl += `?case_id=${currentCaseId}`;
      }
      const response = await fetch(dashboardUrl);
      if (!response.ok) throw new Error('Failed to fetch dashboard data');
      const data = await response.json();
      
      lastDashboardUpdate = new Date();
      updateFreshnessIndicator();
      if (!freshnessInterval) {
          freshnessInterval = setInterval(updateFreshnessIndicator, 60000);
      }
      
      const summaryText = document.getElementById('dashboard-summary-text');
      if (summaryText) {
          summaryText.textContent = 'Click "Generate Summary" in the top right to generate an AI triage report for this case.';
          summaryText.style.fontStyle = 'italic';
          summaryText.style.color = 'var(--text-color)';
      }

      if (document.getElementById('stat-active-threats')) {
        document.getElementById('stat-active-threats').textContent = data.stats.active_threats.toLocaleString();
        document.getElementById('stat-processed-artifacts').textContent = data.stats.processed_artifacts.toLocaleString();
        document.getElementById('stat-ai-detections').textContent = data.stats.ai_detections.toLocaleString();
        
        if (document.getElementById('stat-critical-alerts')) {
            document.getElementById('stat-critical-alerts').textContent = data.stats.critical_alerts.toLocaleString();
            document.getElementById('stat-analysis-jobs').textContent = data.stats.analysis_jobs.toLocaleString();
            
            // Format bytes
            let bytes = data.stats.total_evidence_size;
            let formatted = '0 B';
            if (bytes > 0) {
                const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'], i = Math.floor(Math.log(bytes) / Math.log(k));
                formatted = parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
            }
            document.getElementById('stat-evidence-size').textContent = formatted;
        }
      }

      const tbody = document.getElementById('alerts-table-body');
      if (tbody) {
        tbody.innerHTML = ''; // clear loading state
        if (data.recent_alerts && data.recent_alerts.length > 0) {
          data.recent_alerts.forEach(alert => {
            const tr = document.createElement('tr');

            let badgeClass = 'success';
            const sev = alert.severity.toLowerCase();
            if (sev === 'critical') badgeClass = 'danger';
            else if (sev === 'high') badgeClass = 'danger';
            else if (sev === 'medium') badgeClass = 'warning';

            tr.style.cursor = 'pointer';
            tr.innerHTML = `
              <td><span class="badge ${badgeClass}">${alert.severity.toUpperCase()}</span></td>
              <td>${alert.time}</td>
              <td>${alert.source}</td>
              <td>${alert.description}</td>
              <td><span class="badge">${alert.status}</span></td>
            `;

            tr.addEventListener('click', () => {
              const modal = document.getElementById('finding-details-modal');
              const content = document.getElementById('finding-details-content');
              
              if (!modal || !content) return;

              let detailsHtml = '';
              try {
                const parsedDetails = typeof alert.details === 'string' ? JSON.parse(alert.details) : alert.details;
                detailsHtml = `<pre style="background: rgba(0,0,0,0.3); padding: 1rem; border-radius: 0.5rem; overflow-x: auto; overflow-y: auto; max-height: 300px; font-size: 0.85rem;">${JSON.stringify(parsedDetails, null, 2)}</pre>`;
              } catch (e) {
                detailsHtml = `<div>${alert.details || 'None'}</div>`;
              }

              content.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                  <div>
                    <div style="font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em;">Title</div>
                    <div style="font-size: 1.1rem; font-weight: 600; color: white;">${alert.title || alert.description}</div>
                  </div>
                  ${alert.confidence ? `<div style="text-align: right; padding-left: 1rem;">
                    <div style="font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em;">AI Confidence</div>
                    <div style="font-size: 1.5rem; font-weight: 700; color: ${alert.confidence >= 0.8 ? '#ef4444' : alert.confidence >= 0.5 ? '#f59e0b' : '#3b82f6'};">${Math.round(alert.confidence * 100)}%</div>
                  </div>` : ''}
                </div>
                <div>
                  <div style="font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em;">Description & Reasoning</div>
                  <div style="background: rgba(0,0,0,0.2); padding: 1rem; border-radius: 0.5rem; line-height: 1.5; border: 1px solid rgba(255,255,255,0.05);">
                    <p style="margin-bottom: 0.5rem; color: #38bdf8; font-weight: 600;">Evidence Source: ${alert.evidence_filename || 'Unknown Source'}</p>
                    <p style="margin-bottom: 0.5rem;">${alert.full_description || alert.description || ''}</p>
                    <p style="color: #94a3b8;">${alert.reason || ''}</p>
                  </div>
                </div>
                <div>
                  <div style="font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em;">Recommendation</div>
                  <div style="color: #cbd5e1; background: rgba(16, 185, 129, 0.1); border-left: 3px solid #10b981; padding: 1rem; border-radius: 0 0.5rem 0.5rem 0; line-height: 1.5;">${alert.recommendation || 'No specific recommendation provided.'}</div>
                </div>
                <div>
                  <div style="font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em;">Technical Details</div>
                  ${detailsHtml}
                </div>
              `;

              const modalContentContainer = modal.querySelector('.modal-content');
              if (modalContentContainer) {
                modalContentContainer.style.maxHeight = '70vh';
                modalContentContainer.style.overflowY = 'auto';
              }

              modal.style.display = 'flex';
              modal.classList.remove('hidden');
            });

            tbody.appendChild(tr);
          });
        } else {
          tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No recent alerts found.</td></tr>';
        }
      }

      // Initialize Charts
      function tryInitCharts() {
        if (typeof Chart === 'undefined') {
          setTimeout(tryInitCharts, 200);
          return;
        }
        try {
          Chart.defaults.color = '#94a3b8';
          Chart.defaults.font.family = "'Inter', sans-serif";

          if (!window.timelineChartInst && document.getElementById('timelineChart')) {
            const ctxTimeline = document.getElementById('timelineChart').getContext('2d');
            window.timelineChartInst = new Chart(ctxTimeline, {
              type: 'bar',
              data: {
                labels: data.charts?.timeline?.labels || ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                datasets: [{
                  label: 'Events Logged',
                  data: data.charts?.timeline?.data || [0, 0, 0, 0, 0, 0, 0],
                  backgroundColor: 'rgba(59, 130, 246, 0.6)',
                  borderColor: 'rgba(59, 130, 246, 1)',
                  borderWidth: 1,
                  borderRadius: 4
                }]
              },
              options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                  y: { beginAtZero: true, grid: { color: 'rgba(255, 255, 255, 0.05)' } },
                  x: { grid: { display: false } }
                },
                plugins: { legend: { display: false } },
                onClick: (e, elements) => {
                  if (elements.length > 0) {
                    const idx = elements[0].index;
                    const label = window.timelineChartInst.data.labels[idx];
                    document.querySelector('.nav-item[data-view="timeline"]')?.click();
                    const filterInput = document.getElementById('search-timeline');
                    if (filterInput) {
                      filterInput.value = label;
                      filterInput.dispatchEvent(new Event('input', { bubbles: true }));
                    }
                  }
                },
                onHover: (e, elements) => {
                  e.native.target.style.cursor = elements.length ? 'pointer' : 'default';
                }
              }
            });
          } else if (window.timelineChartInst) {
            window.timelineChartInst.data.labels = data.charts?.timeline?.labels || ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
            window.timelineChartInst.data.datasets[0].data = data.charts?.timeline?.data || [0, 0, 0, 0, 0, 0, 0];
            window.timelineChartInst.update();
          }

          if (!window.evidenceChartInst && document.getElementById('evidenceChart')) {
            const ctxEvidence = document.getElementById('evidenceChart').getContext('2d');
            
            // Generate enough colors for the dynamic labels
            const baseColors = [
              'rgba(59, 130, 246, 0.8)', // blue
              'rgba(139, 92, 246, 0.8)', // violet
              'rgba(16, 185, 129, 0.8)', // emerald
              'rgba(245, 158, 11, 0.8)', // amber
              'rgba(239, 68, 68, 0.8)',  // red
              'rgba(14, 165, 233, 0.8)'  // sky
            ];
            const labels = data.charts?.evidence?.labels || ['No Data'];
            const chartData = data.charts?.evidence?.data || [1];
            const bgColors = labels.map((_, i) => baseColors[i % baseColors.length]);

            window.evidenceChartInst = new Chart(ctxEvidence, {
              type: 'doughnut',
              data: {
                labels: labels,
                datasets: [{
                  data: chartData,
                  backgroundColor: bgColors,
                  borderColor: '#0f172a',
                  borderWidth: 2,
                  hoverOffset: 4
                }]
              },
              options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                  legend: { position: 'right', labels: { color: '#e2e8f0', padding: 20 } }
                },
                cutout: '70%',
                onClick: (e, elements) => {
                  if (elements.length > 0) {
                    const idx = elements[0].index;
                    const label = window.evidenceChartInst.data.labels[idx];
                    document.querySelector('.nav-item[data-view="evidence"]')?.click();
                    const filterInput = document.getElementById('search-evidence');
                    if (filterInput) {
                      filterInput.value = label;
                      filterInput.dispatchEvent(new Event('input', { bubbles: true }));
                    }
                  }
                },
                onHover: (e, elements) => {
                  e.native.target.style.cursor = elements.length ? 'pointer' : 'default';
                }
              }
            });
          } else if (window.evidenceChartInst) {
            const baseColors = [
              'rgba(59, 130, 246, 0.8)', 'rgba(139, 92, 246, 0.8)', 'rgba(16, 185, 129, 0.8)',
              'rgba(245, 158, 11, 0.8)', 'rgba(239, 68, 68, 0.8)', 'rgba(14, 165, 233, 0.8)'
            ];
            const labels = data.charts?.evidence?.labels || ['No Data'];
            const chartData = data.charts?.evidence?.data || [1];
            const bgColors = labels.map((_, i) => baseColors[i % baseColors.length]);
            
            window.evidenceChartInst.data.labels = labels;
            window.evidenceChartInst.data.datasets[0].data = chartData;
            window.evidenceChartInst.data.datasets[0].backgroundColor = bgColors;
            window.evidenceChartInst.update();
          }
        } catch (err) {
          const tC = document.getElementById('timelineChart');
          if (tC && tC.parentNode) tC.parentNode.innerHTML = '<div style="color:red;padding:1rem;">Error rendering chart: ' + err.message + '</div>';
        }
      }
      tryInitCharts();

    } catch (error) {
      console.error('Error loading dashboard:', error);
      const tbody = document.getElementById('alerts-table-body');
      if (tbody) tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--danger);">Failed to load data.</td></tr>';
    }
  }

  loadDashboardData();

  const btnGenerateSummary = document.getElementById('btn-generate-summary');
  const summaryContainer = document.getElementById('dashboard-summary-container');
  const summaryText = document.getElementById('dashboard-summary-text');

  if (btnGenerateSummary && summaryContainer && summaryText) {
    btnGenerateSummary.addEventListener('click', async () => {
      summaryContainer.classList.remove('hidden');
      summaryContainer.classList.add('animate-fade-in');
      summaryText.textContent = 'Analyzing global threats and generating executive summary...';
      summaryText.style.color = 'var(--text-color)';
      summaryText.style.fontStyle = 'normal';
      try {
        let summaryUrl = '/api/dashboard/summary';
        if (currentCaseId) {
            summaryUrl += `?case_id=${currentCaseId}`;
        }
        const data = await api('GET', summaryUrl);
        summaryText.textContent = data.summary;
      } catch (err) {
        summaryText.textContent = 'Failed to generate summary: ' + err.message;
        summaryText.style.color = 'var(--danger)';
      }
    });
  }
}
