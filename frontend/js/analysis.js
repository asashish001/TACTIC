import { api, jwtToken } from './api.js?v=2';
import { showToast, renderEmptyState } from './ui.js';
import { currentCaseId } from './state.js';

export function setupAnalysis() {
    const btnRunAnalysis = document.getElementById('btn-run-analysis');
  const jobsList = document.getElementById('analysis-jobs-list');
  const findingsList = document.getElementById('analysis-findings-list');

  let analysisPollInterval = null;

  let analysisStreamAbort = null;

  window.loadAnalysisJobs = async function () {
    if (!jobsList || !currentCaseId) return;

    if (analysisStreamAbort) {
        analysisStreamAbort.abort();
    }
    analysisStreamAbort = new AbortController();

    try {
      const response = await fetch(`/api/jobs/case/${currentCaseId}/stream`, {
        headers: { 'Authorization': `Bearer ${jwtToken}` },
        signal: analysisStreamAbort.signal
      });

      if (!response.ok) {
          throw new Error('SSE connection failed');
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      
      while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          const chunk = decoder.decode(value, { stream: true });
          const lines = chunk.split('\n');
          
          for (const line of lines) {
              if (line.startsWith('data: ')) {
                  const dataStr = line.replace('data: ', '').trim();
                  if (!dataStr) continue;

                  try {
                      const jobs = JSON.parse(dataStr);
                      if (!jobs || jobs.length === 0) {
                        jobsList.innerHTML = renderEmptyState('activity', 'No Analysis Jobs', 'Run an analysis module from the right panel to begin extracting intelligence.', true, 4);
                        continue;
                      }

                      jobsList.innerHTML = '';
                      let isRunning = false;
                      jobs.forEach(job => {
                        if (job.status === 'RUNNING' || job.status === 'QUEUED' || job.status === 'PROCESSING') isRunning = true;
                        let statusClass = 'info';
                        if (job.status === 'COMPLETED') statusClass = 'success';
                        if (job.status === 'FAILED') statusClass = 'danger';

                        const tr = document.createElement('tr');
                        tr.innerHTML = `
                          <td>${job.evidence_id || 'Case-wide'}</td>
                          <td><span class="badge ${statusClass}">${job.status}</span></td>
                          <td>${job.progress_percent}%</td>
                          <td>${job.stage_message || job.current_stage || ''}</td>
                        `;
                        jobsList.appendChild(tr);
                      });

                      // If no jobs are running, we can load findings and optionally close stream
                      if (!isRunning) {
                          window.loadAnalysisFindings();
                          // Could break here to stop streaming, but we'll leave it open 
                          // in case a new job is spawned by another user/tab.
                      }
                  } catch (e) {
                      console.error('Error parsing jobs stream', e);
                  }
              }
          }
      }
    } catch (e) {
      if (e.name !== 'AbortError') {
          console.error('Failed to load jobs stream', e);
      }
    }
  };

  window.loadAnalysisFindings = async function () {
    if (!findingsList || !currentCaseId) return;
    try {
      const findings = await api('GET', `/api/analyze/findings/${currentCaseId}`);
      if (!findings || findings.length === 0) {
        findingsList.innerHTML = renderEmptyState('search', 'No Findings Discovered', 'Wait for analysis jobs to complete to view extracted intelligence.', true, 4);
        return;
      }

      findingsList.innerHTML = '';
      findings.forEach(f => {
        let sevClass = 'info';
        const sev = (f.severity || '').toLowerCase();
        if (sev === 'critical' || sev === 'high') sevClass = 'danger';
        if (sev === 'medium') sevClass = 'warning';
        if (sev === 'low') sevClass = 'success';

        const tr = document.createElement('tr');
        tr.style.cursor = 'pointer';
        tr.innerHTML = `
          <td><span class="badge ${sevClass}">${f.severity}</span></td>
          <td>${f.title}</td>
          <td>${f.threat_category || 'General Analysis'}</td>
          <td>${Math.round((f.confidence || 0) * 100)}%</td>
        `;
        tr.addEventListener('click', () => {
          const modal = document.getElementById('finding-details-modal');
          const content = document.getElementById('finding-details-content');

          let detailsHtml = '';
          try {
            const parsedDetails = typeof f.details === 'string' ? JSON.parse(f.details) : f.details;
            detailsHtml = `<pre style="background: rgba(0,0,0,0.3); padding: 1rem; border-radius: 0.5rem; overflow-x: auto; overflow-y: auto; max-height: 300px; font-size: 0.85rem;">${JSON.stringify(parsedDetails, null, 2)}</pre>`;
          } catch (e) {
            detailsHtml = `<div>${f.details}</div>`;
          }

          content.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
              <div>
                <div style="font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em;">Title</div>
                <div style="font-size: 1.1rem; font-weight: 600; color: white;">${f.title}</div>
              </div>
              ${f.confidence ? `<div style="text-align: right; padding-left: 1rem;">
                <div style="font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em;">AI Confidence</div>
                <div style="font-size: 1.5rem; font-weight: 700; color: ${f.confidence >= 0.8 ? '#ef4444' : f.confidence >= 0.5 ? '#f59e0b' : '#3b82f6'};">${Math.round(f.confidence * 100)}%</div>
              </div>` : ''}
            </div>
            <div>
              <div style="font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em;">Description & Reasoning</div>
              <div style="background: rgba(0,0,0,0.2); padding: 1rem; border-radius: 0.5rem; line-height: 1.5; border: 1px solid rgba(255,255,255,0.05);">
                <p style="margin-bottom: 0.5rem; color: #38bdf8; font-weight: 600;">Evidence Source: ${f.evidence_filename || 'Unknown Source'}</p>
                <p style="margin-bottom: 0.5rem;">${f.description || ''}</p>
                <p style="color: #94a3b8;">${f.reason || ''}</p>
              </div>
            </div>
            <div>
              <div style="font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em;">Recommendation</div>
              <div style="color: #cbd5e1; background: rgba(16, 185, 129, 0.1); border-left: 3px solid #10b981; padding: 1rem; border-radius: 0 0.5rem 0.5rem 0; line-height: 1.5;">${f.recommendation || 'No specific recommendation provided.'}</div>
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
            modalContentContainer.style.margin = '5vh auto';
          }

          modal.style.display = 'flex';
          modal.classList.remove('hidden');
        });
        findingsList.appendChild(tr);
      });
    } catch (e) {
      console.error('Failed to load findings', e);
    }
  };

  const artifactsList = document.getElementById('extracted-artifacts-list');
  window.loadExtractedArtifacts = async function () {
    if (!artifactsList || !currentCaseId) return;
    try {
      const artifacts = await api('GET', `/api/analyze/artifacts/${currentCaseId}`);
      if (!artifacts || artifacts.length === 0) {
        artifactsList.innerHTML = renderEmptyState('box', 'No Artifacts Extracted', 'Run the NLP Extractor analysis to pull entities and insights from evidence.', true, 5);
        return;
      }

      artifactsList.innerHTML = '';
      artifacts.forEach(a => {
        const tr = document.createElement('tr');
        const extractedDate = new Date(a.extracted_at).toLocaleString();
        
        let valDisplay = a.value;
        if (valDisplay && valDisplay.length > 100) {
            valDisplay = valDisplay.substring(0, 100) + '...';
        }

        const safeVal = valDisplay ? valDisplay.replace(/</g, '&lt;').replace(/>/g, '&gt;') : '';
        const safeFullVal = a.value ? a.value.replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;') : '';

        tr.innerHTML = `
          <td>${a.evidence_filename || 'Case-wide'}</td>
          <td><span class="badge info">${a.artifact_type}</span></td>
          <td style="word-break: break-all;" title="${safeFullVal}">${safeVal}</td>
          <td>${a.extractor}</td>
          <td style="color: var(--text-muted); font-size: 0.85rem;">${extractedDate}</td>
        `;
        artifactsList.appendChild(tr);
      });
    } catch (e) {
      console.error('Failed to load extracted artifacts', e);
      artifactsList.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--danger);">Failed to load artifacts.</td></tr>';
    }
  };

  const btnRefreshArtifacts = document.getElementById('btn-refresh-artifacts');
  if (btnRefreshArtifacts) {
    btnRefreshArtifacts.addEventListener('click', () => {
      window.loadExtractedArtifacts();
    });
  }

  if (btnRunAnalysis) {
    btnRunAnalysis.addEventListener('click', async () => {
      if (!currentCaseId) {
        showToast('Please create and open a case first.', 'error');
        return;
      }

      let btnIcon = btnRunAnalysis.querySelector('i') || btnRunAnalysis.querySelector('svg');
      btnRunAnalysis.disabled = true;
      if (btnIcon) {
        const newIcon = document.createElement('i');
        newIcon.setAttribute('data-lucide', 'loader');
        newIcon.style.width = '18px';
        newIcon.style.height = '18px';
        btnIcon.replaceWith(newIcon);
        if (typeof lucide !== 'undefined') lucide.createIcons();
      }

      try {
        await api('POST', '/api/analyze', { case_id: currentCaseId });
        window.loadAnalysisJobs();
      } catch (err) {
        console.error(err);
        showToast('Failed to trigger analysis: ' + err.message, 'error');
      } finally {
        btnRunAnalysis.disabled = false;
        btnIcon = btnRunAnalysis.querySelector('i') || btnRunAnalysis.querySelector('svg');
        if (btnIcon) {
          const newIcon = document.createElement('i');
          newIcon.setAttribute('data-lucide', 'zap');
          newIcon.style.width = '18px';
          newIcon.style.height = '18px';
          btnIcon.replaceWith(newIcon);
          if (typeof lucide !== 'undefined') lucide.createIcons();
        }
      }
    });
  }

  const timelineList = document.getElementById('timeline-events-list');
}
