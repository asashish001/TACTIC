if (typeof lucide !== 'undefined') {
  lucide.createIcons();
}

document.addEventListener('DOMContentLoaded', () => {

  window.showToast = function (message, type = 'info') {
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
  };

  let jwtToken = null;
  async function api(method, url, data) {
    if (!jwtToken) {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: 'ChangeMe123!' })
      });
      if (res.ok) {
        const authData = await res.json();
        jwtToken = authData.access_token;
      }
    }
    const headers = { 'Authorization': `Bearer ${jwtToken}` };
    if (data) headers['Content-Type'] = 'application/json';
    const options = { method, headers };
    if (data) options.body = JSON.stringify(data);
    const response = await fetch(url, options);
    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`API Error: ${response.statusText} - ${errorBody}`);
    }
    return await response.json();
  }

  const navItems = document.querySelectorAll('.nav-item');
  const views = document.querySelectorAll('.view');
  const noCaseOverlay = document.getElementById('no-case-overlay');

  window.checkCaseSelection = function (viewName) {
    if (!noCaseOverlay) return;
    const requiresCase = ['dashboard', 'evidence', 'analysis', 'timeline', 'network', 'chat', 'reports'];
    if (requiresCase.includes(viewName) && !currentCaseId) {
      noCaseOverlay.style.display = 'flex';
    } else {
      noCaseOverlay.style.display = 'none';
    }
  };

  navItems.forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();

      navItems.forEach(nav => nav.classList.remove('active'));
      views.forEach(view => {
        view.classList.add('hidden');
        view.classList.remove('animate-fade-in');
        void view.offsetWidth;
      });

      item.classList.add('active');
      const viewName = item.getAttribute('data-view');
      const viewId = `view-${viewName}`;

      window.checkCaseSelection(viewName);

      const targetView = document.getElementById(viewId);
      if (targetView) {
        targetView.classList.remove('hidden');
        targetView.classList.add('animate-fade-in');

        if (item.getAttribute('data-view') === 'chat') {
          targetView.style.display = 'flex';
        }

        if (item.getAttribute('data-view') === 'network' && window.cyInstance) {
          setTimeout(() => {
            window.cyInstance.resize();
            window.cyInstance.layout({
              name: 'concentric', padding: 50, animate: true,
              spacingFactor: 1.5, minNodeSpacing: 50
            }).run();
          }, 50);
        }
      }
    });
  });

  async function loadDashboardData() {
    try {
      const response = await fetch('/api/dashboard');
      if (!response.ok) throw new Error('Failed to fetch dashboard data');
      const data = await response.json();

      if (document.getElementById('stat-active-threats')) {
        document.getElementById('stat-active-threats').textContent = data.stats.active_threats.toLocaleString();
        document.getElementById('stat-processed-artifacts').textContent = data.stats.processed_artifacts.toLocaleString();
        document.getElementById('stat-ai-detections').textContent = data.stats.ai_detections.toLocaleString();
        document.getElementById('stat-active-agents').textContent = data.stats.active_agents.toLocaleString();
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
                <div>
                  <div style="font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em;">Title</div>
                  <div style="font-size: 1.1rem; font-weight: 600; color: white;">${alert.title || alert.description}</div>
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
      try {
        const data = await api('GET', '/api/dashboard/summary');
        summaryText.textContent = data.summary;
      } catch (err) {
        summaryText.textContent = 'Failed to generate summary: ' + err.message;
        summaryText.style.color = 'var(--danger)';
      }
    });
  }

  const casesList = document.getElementById('cases-list');
  const globalCaseSelect = document.getElementById('global-case-select');
  window.allCases = [];
  let currentCaseId = localStorage.getItem('currentCaseId') || null;

  function updateGlobalCaseSelector() {
    if (!globalCaseSelect) return;
    globalCaseSelect.innerHTML = '<option value="">-- No Case Selected --</option>';
    window.allCases.forEach(c => {
      const opt = document.createElement('option');
      opt.value = c.id;
      opt.textContent = `${c.case_number} - ${c.name}`;
      if (c.id == currentCaseId) opt.selected = true;
      globalCaseSelect.appendChild(opt);
    });
  }

  if (globalCaseSelect) {
    globalCaseSelect.addEventListener('change', (e) => {
      currentCaseId = e.target.value;
      if (currentCaseId) {
        localStorage.setItem('currentCaseId', currentCaseId);
      } else {
        localStorage.removeItem('currentCaseId');
      }

      const activeNav = document.querySelector('.nav-item.active');
      if (activeNav) window.checkCaseSelection(activeNav.getAttribute('data-view'));

      if (typeof loadEvidence === 'function') loadEvidence();
      if (typeof loadAnalysisJobs === 'function') loadAnalysisJobs();
      if (typeof loadAnalysisFindings === 'function') loadAnalysisFindings();
      if (typeof loadExtractedArtifacts === 'function') window.loadExtractedArtifacts();
      if (typeof loadTimeline === 'function') window.loadTimeline();
      if (typeof loadNetworkGraph === 'function') window.loadNetworkGraph();
      if (typeof loadReports === 'function') window.loadReports();
    });
  }

  async function loadCases() {
    if (!casesList) return;
    casesList.innerHTML = '<div style="color: var(--text-muted);">Loading cases...</div>';
    try {
      const data = await api('GET', '/api/cases');
      window.allCases = data.items || [];
      casesList.innerHTML = '';
      if (data.items.length === 0) {
        casesList.innerHTML = '<div style="color: var(--text-muted); padding: 1rem;">No cases found.</div>';
        loadEvidence();
        return;
      }
      data.items.forEach(c => {
        let statusClass = 'info';
        if (c.status && c.status.toLowerCase() === 'closed') statusClass = 'success';
        if (c.status && c.status.toLowerCase() === 'active') statusClass = 'danger';

        const card = document.createElement('div');
        card.className = 'feature-card';
        card.innerHTML = `
          <div class="feature-header">
            <div style="padding: 0.75rem; background: rgba(59, 130, 246, 0.1); border-radius: 0.5rem; color: #3b82f6;">
              <i data-lucide="briefcase"></i>
            </div>
            <div>
              <h3 class="feature-title">${c.case_number}</h3>
              <span class="badge ${statusClass}" style="margin-top: 0.25rem;">${c.status || 'open'}</span>
            </div>
          </div>
          <div class="feature-body">
            <p>${c.name}</p>
            <div style="margin-top: 1rem; display: flex; justify-content: space-between; font-size: 0.875rem;">
              <span>Incident Date: ${c.incident_date}</span>
            </div>
          </div>
          <div style="margin-top: auto; padding-top: 1rem; border-top: 1px solid rgba(255,255,255,0.05); display: flex; justify-content: flex-end;">
            <button class="btn btn-secondary btn-open-case" data-id="${c.id}" style="padding: 0.5rem 1rem; font-size: 0.875rem;">Open Case</button>
          </div>
        `;
        casesList.appendChild(card);
      });
      if (typeof lucide !== 'undefined') lucide.createIcons();

      document.querySelectorAll('.btn-open-case').forEach(btn => {
        btn.addEventListener('click', (e) => {
          currentCaseId = e.target.closest('button').getAttribute('data-id');
          localStorage.setItem('currentCaseId', currentCaseId);
          updateGlobalCaseSelector();
          const evidenceNav = Array.from(document.querySelectorAll('.nav-item')).find(n => n.getAttribute('data-view') === 'evidence');
          if (evidenceNav) evidenceNav.click();
          loadEvidence();
          if (typeof loadAnalysisJobs === 'function') loadAnalysisJobs();
          if (typeof loadAnalysisFindings === 'function') loadAnalysisFindings();
          if (typeof loadExtractedArtifacts === 'function') window.loadExtractedArtifacts();
          if (typeof loadTimeline === 'function') window.loadTimeline();
          if (typeof loadNetworkGraph === 'function') window.loadNetworkGraph();
          if (typeof loadReports === 'function') window.loadReports();
        });
      });

      updateGlobalCaseSelector();

      const activeNav = document.querySelector('.nav-item.active');
      if (activeNav) window.checkCaseSelection(activeNav.getAttribute('data-view'));

      loadEvidence();
      if (typeof loadAnalysisJobs === 'function') loadAnalysisJobs();
      if (typeof loadAnalysisFindings === 'function') loadAnalysisFindings();
      if (typeof loadExtractedArtifacts === 'function') window.loadExtractedArtifacts();
      if (typeof loadTimeline === 'function') window.loadTimeline();
      if (typeof loadNetworkGraph === 'function') window.loadNetworkGraph();
      if (typeof loadReports === 'function') window.loadReports();
      if (typeof loadSettings === 'function') window.loadSettings();
    } catch (e) {
      console.error(e);
      casesList.innerHTML = '<div style="color: var(--danger); padding: 1rem;">Failed to load cases.</div>';
    }
  }

  loadCases();

  const modal = document.getElementById('new-case-modal');
  const btnNewCase = document.getElementById('btn-new-case');
  const btnCloseModal = document.getElementById('btn-close-modal');
  const newCaseForm = document.getElementById('new-case-form');

  if (btnNewCase && modal) {
    modal.style.display = 'none';

    btnNewCase.addEventListener('click', () => {
      modal.style.display = 'flex';
      modal.classList.remove('hidden');
    });
    btnCloseModal.addEventListener('click', () => {
      modal.style.display = 'none';
      modal.classList.add('hidden');
    });
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        modal.style.display = 'none';
        modal.classList.add('hidden');
      }
    });

    newCaseForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btnSubmit = document.getElementById('btn-submit-case');
      btnSubmit.textContent = 'Creating...';
      btnSubmit.disabled = true;

      const caseData = {
        case_number: document.getElementById('case-number').value,
        name: document.getElementById('case-name').value,
        description: document.getElementById('case-desc').value,
        incident_date: document.getElementById('case-date').value
      };

      try {
        await api('POST', '/api/cases', caseData);
        modal.style.display = 'none';
        modal.classList.add('hidden');
        newCaseForm.reset();
        loadCases(); // Refresh list
      } catch (err) {
        console.error(err);
        window.showToast('Failed to create case: ' + err.message, 'error');
      } finally {
        btnSubmit.textContent = 'Create Case';
        btnSubmit.disabled = false;
      }
    });
  }

  const evidenceList = document.getElementById('evidence-list');
  if (evidenceList) {
    evidenceList.addEventListener('click', async (e) => {
      const link = e.target.closest('.evidence-link');
      if (link) {
        e.preventDefault();
        const id = link.getAttribute('data-id');
        const filename = link.getAttribute('data-filename');

        const newWindow = window.open('', '_blank');
        if (newWindow) {
          newWindow.document.write('<html><head><title>' + filename + '</title></head><body style="font-family: monospace; white-space: pre-wrap; word-wrap: break-word;">Loading file...</body></html>');
        }

        try {
          const response = await fetch(`/api/evidence/download/${id}`, {
            headers: { 'Authorization': `Bearer ${jwtToken}` }
          });
          if (!response.ok) throw new Error('Failed to download');

          const ext = filename.split('.').pop().toLowerCase();
          const textExtensions = ['csv', 'txt', 'log', 'md', 'json', 'py', 'js', 'xml', 'ini', 'cfg'];

          if (textExtensions.includes(ext)) {
            const text = await response.text();
            if (newWindow) {
              newWindow.document.open();
              newWindow.document.write('<html><head><title>' + filename + '</title></head><body style="font-family: monospace; white-space: pre-wrap; word-wrap: break-word;">' + text.replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</body></html>');
              newWindow.document.close();
            }
          } else {
            // Fallback to blob for images/pdf etc.
            let blob = await response.blob();
            let mimeType = 'application/octet-stream';
            if (['png', 'jpg', 'jpeg', 'gif', 'webp'].includes(ext)) {
              mimeType = `image/${ext === 'jpg' ? 'jpeg' : ext}`;
            } else if (ext === 'pdf') {
              mimeType = 'application/pdf';
            }
            blob = new Blob([blob], { type: mimeType });
            const url = window.URL.createObjectURL(blob);
            if (newWindow) {
              newWindow.location.href = url;
            }
            setTimeout(() => window.URL.revokeObjectURL(url), 15000);
          }
        } catch (err) {
          if (newWindow) {
            newWindow.document.open();
            newWindow.document.write('Error opening file: ' + err.message);
            newWindow.document.close();
          }
          console.error('Error opening file:', err);
        }
      }
    });
  }

  function formatBytes(bytes) {
    if (bytes === 0 || !bytes) return '0 B';
    const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'], i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  async function loadEvidence() {
    if (!evidenceList) return;

    if (!currentCaseId) {
      evidenceList.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Please create a case first.</td></tr>';
      return;
    }

    evidenceList.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Loading evidence...</td></tr>';
    try {
      const data = await api('GET', `/api/evidence?case_id=${currentCaseId}`);
      evidenceList.innerHTML = '';
      if (!data.items || data.items.length === 0) {
        evidenceList.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No evidence found for this case.</td></tr>';
        return;
      }

      data.items.forEach(ev => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${ev.id}</td>
          <td><a href="#" class="evidence-link" data-id="${ev.id}" data-filename="${ev.filename}" style="color: var(--primary); text-decoration: underline; cursor: pointer;">${ev.filename}</a></td>
          <td>${ev.detected_mime || ev.extension || 'Unknown'}</td>
          <td>${formatBytes(ev.file_size)}</td>
          <td><span class="badge success">Processed</span></td>
        `;
        evidenceList.appendChild(tr);
      });
    } catch (e) {
      console.error(e);
      evidenceList.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--danger);">Failed to load evidence.</td></tr>';
    }
  }

  const uploadModal = document.getElementById('upload-evidence-modal');
  const btnUploadEvidence = document.getElementById('btn-upload-evidence');
  const btnCloseUploadModal = document.getElementById('btn-close-upload-modal');
  const uploadEvidenceForm = document.getElementById('upload-evidence-form');

  if (btnUploadEvidence && uploadModal) {
    uploadModal.style.display = 'none';

    btnUploadEvidence.addEventListener('click', () => {
      const caseSelectorContainer = document.getElementById('upload-case-selector-container');
      if (caseSelectorContainer) {
        if (window.allCases.length === 0) {
          caseSelectorContainer.innerHTML = '<div style="color: var(--danger);">Please create a case first before uploading.</div>';
        } else {
          let options = window.allCases.map(c => `<option value="${c.id}" ${c.id == currentCaseId ? 'selected' : ''}>${c.case_number} - ${c.name}</option>`).join('');
          caseSelectorContainer.innerHTML = `
            <label style="display: block; margin-bottom: 0.5rem; color: #94a3b8;">Select Case</label>
            <select id="upload-case-id" required style="width: 100%; padding: 0.75rem; background: rgba(0,0,0,0.2); border: 1px solid rgba(255,255,255,0.1); color: white; border-radius: 0.5rem; outline: none;">
              ${options}
            </select>
          `;
        }
      }

      uploadModal.style.display = 'flex';
      uploadModal.classList.remove('hidden');
    });

    btnCloseUploadModal.addEventListener('click', () => {
      uploadModal.style.display = 'none';
      uploadModal.classList.add('hidden');
    });

    uploadModal.addEventListener('click', (e) => {
      if (e.target === uploadModal) {
        uploadModal.style.display = 'none';
        uploadModal.classList.add('hidden');
      }
    });

    uploadEvidenceForm.addEventListener('submit', async (e) => {
      e.preventDefault();

      const fileInput = document.getElementById('evidence-file');
      if (!fileInput.files.length) return;

      const caseIdInput = document.getElementById('upload-case-id');
      if (!caseIdInput) {
        window.showToast('Please create a case first.', 'error');
        return;
      }

      const btnSubmit = document.getElementById('btn-submit-upload');
      btnSubmit.textContent = 'Uploading...';
      btnSubmit.disabled = true;

      const formData = new FormData();
      formData.append('case_id', caseIdInput.value);
      formData.append('file', fileInput.files[0]);

      try {
        const response = await fetch('/api/evidence/upload', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${jwtToken}` },
          body: formData
        });

        if (!response.ok) {
          const errText = await response.text();
          throw new Error(response.statusText + ' - ' + errText);
        }

        uploadModal.style.display = 'none';
        uploadModal.classList.add('hidden');
        uploadEvidenceForm.reset();

        currentCaseId = caseIdInput.value;
        localStorage.setItem('currentCaseId', currentCaseId);
        loadEvidence();
      } catch (err) {
        console.error(err);
        window.showToast('Upload failed: ' + err.message, 'error');
      } finally {
        btnSubmit.textContent = 'Upload File';
        btnSubmit.disabled = false;
      }
    });
  }

  const chatInput = document.getElementById('chat-input');
  const chatSendBtn = document.getElementById('chat-send');
  const chatMessages = document.getElementById('chat-messages');

  async function sendMessage() {
    const text = chatInput.value.trim();
    if (!text) return;

    if (!currentCaseId) {
      window.showToast("Please open a case before using the AI Chat.", 'error');
      return;
    }

    const userMsg = document.createElement('div');
    userMsg.className = 'chat-msg user-msg animate-fade-in';
    userMsg.innerHTML = `
      <div class="msg-avatar">U</div>
      <div class="msg-bubble">${text}</div>
    `;
    chatMessages.appendChild(userMsg);
    chatInput.value = '';
    chatMessages.scrollTop = chatMessages.scrollHeight;

    const loadingMsg = document.createElement('div');
    loadingMsg.className = 'chat-msg ai-msg animate-fade-in';
    loadingMsg.innerHTML = `
      <div class="msg-avatar"><i data-lucide="cpu" style="width:20px;height:20px;"></i></div>
      <div class="msg-bubble" style="opacity: 0.7; font-style: italic;">Analyzing case data...</div>
    `;
    chatMessages.appendChild(loadingMsg);
    if (typeof lucide !== 'undefined') lucide.createIcons();
    chatMessages.scrollTop = chatMessages.scrollHeight;

    try {
      const response = await api('POST', '/api/chat', { case_id: parseInt(currentCaseId, 10), question: text });
      loadingMsg.remove();

      const aiMsg = document.createElement('div');
      aiMsg.className = 'chat-msg ai-msg animate-fade-in';
      const formattedAnswer = (response.answer || '').replace(/\n/g, '<br>');
      const meta = response.safeguards || {};

      aiMsg.innerHTML = `
        <div class="msg-avatar"><i data-lucide="message-square" style="width:20px;height:20px;"></i></div>
        <div class="msg-bubble">
            <div>${formattedAnswer}</div>
            <div style="margin-top: 0.75rem; font-size: 0.75rem; color: var(--text-muted); border-top: 1px solid rgba(255,255,255,0.1); padding-top: 0.5rem;">
                Model: ${response.provider || 'unknown'} | Grounding: ${meta.grounding_score !== undefined ? meta.grounding_score : 'N/A'}
            </div>
        </div>
      `;
      chatMessages.appendChild(aiMsg);
      if (typeof lucide !== 'undefined') lucide.createIcons();
      chatMessages.scrollTop = chatMessages.scrollHeight;

    } catch (err) {
      console.error(err);
      loadingMsg.remove();
      const errMsg = document.createElement('div');
      errMsg.className = 'chat-msg ai-msg animate-fade-in';
      errMsg.innerHTML = `
        <div class="msg-avatar"><i data-lucide="alert-triangle" style="width:20px;height:20px; color: var(--danger);"></i></div>
        <div class="msg-bubble" style="color: var(--danger); background: rgba(239, 68, 68, 0.1);">Error connecting to AI: ${err.message}</div>
      `;
      chatMessages.appendChild(errMsg);
      if (typeof lucide !== 'undefined') lucide.createIcons();
      chatMessages.scrollTop = chatMessages.scrollHeight;
    }
  }

  if (chatSendBtn) {
    chatSendBtn.addEventListener('click', sendMessage);
    chatInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') sendMessage();
    });
  }

  const btnRunAnalysis = document.getElementById('btn-run-analysis');
  const jobsList = document.getElementById('analysis-jobs-list');
  const findingsList = document.getElementById('analysis-findings-list');

  let analysisPollInterval = null;

  window.loadAnalysisJobs = async function () {
    if (!jobsList || !currentCaseId) return;
    try {
      const jobs = await api('GET', `/api/jobs/case/${currentCaseId}`);
      if (!jobs || jobs.length === 0) {
        jobsList.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No analysis jobs running.</td></tr>';
        return;
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

      if (!isRunning && analysisPollInterval) {
        clearInterval(analysisPollInterval);
        analysisPollInterval = null;
        window.loadAnalysisFindings();
      }
    } catch (e) {
      console.error('Failed to load jobs', e);
    }
  };

  window.loadAnalysisFindings = async function () {
    if (!findingsList || !currentCaseId) return;
    try {
      const findings = await api('GET', `/api/analyze/findings/${currentCaseId}`);
      if (!findings || findings.length === 0) {
        findingsList.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No findings discovered yet.</td></tr>';
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
            <div>
              <div style="font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em;">Title</div>
              <div style="font-size: 1.1rem; font-weight: 600; color: white;">${f.title}</div>
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
        artifactsList.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No artifacts extracted yet.</td></tr>';
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
        window.showToast('Please create and open a case first.', 'error');
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
        if (!analysisPollInterval) {
          analysisPollInterval = setInterval(window.loadAnalysisJobs, 2000);
        }
        window.loadAnalysisJobs();
      } catch (err) {
        console.error(err);
        window.showToast('Failed to trigger analysis: ' + err.message, 'error');
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

  window.loadTimeline = async function () {
    if (!timelineList || !currentCaseId) return;
    try {
      timelineList.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Loading timeline...</td></tr>';
      const data = await api('GET', `/api/timeline/${currentCaseId}`);
      if (!data.events || data.events.length === 0) {
        timelineList.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No timeline events found.</td></tr>';
        return;
      }

      timelineList.innerHTML = '';
      data.events.forEach(evt => {
        let badgeClass = 'info';
        if (evt.priority === 'high' || evt.priority === 'critical') badgeClass = 'danger';
        if (evt.priority === 'medium') badgeClass = 'warning';
        if (evt.priority === 'low') badgeClass = 'success';

        const rowStyle = evt.is_suspicious ? 'background: rgba(239, 68, 68, 0.1);' : '';
        const tr = document.createElement('tr');
        if (rowStyle) tr.style = rowStyle;

        tr.innerHTML = `
          <td style="font-family: monospace; font-size: 0.85rem;">${evt.display_timestamp}</td>
          <td>${evt.evidence_source || 'Unknown'}</td>
          <td>${evt.provider || 'N/A'}</td>
          <td>${evt.event}</td>
          <td><span class="badge ${badgeClass}">${(evt.priority || 'info').toUpperCase()}</span></td>
        `;
        timelineList.appendChild(tr);
      });
    } catch (e) {
      console.error('Failed to load timeline', e);
      timelineList.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--danger);">Failed to load timeline events.</td></tr>';
    }
  };

  window.loadNetworkGraph = async function () {
    if (!document.getElementById('cy') || !currentCaseId) return;
    try {
      const artifacts = await api('GET', `/api/network/cases/${currentCaseId}/artifacts`);
      if (!artifacts || artifacts.length === 0) {
        document.getElementById('cy').innerHTML = '<div style="color:var(--text-muted); text-align:center; padding-top: 2rem;">No network artifacts found for this case.</div>';
        return;
      }

      const elements = [];
      const nodes = new Set();

      artifacts.forEach(art => {
        const src = art.source_ip || art.value;
        const dst = art.destination_ip || art.domain;

        if (src && !nodes.has(src)) {
          nodes.add(src);
          elements.push({ data: { id: src, label: src, type: 'Internal IP' } });
        }
        if (dst && !nodes.has(dst)) {
          nodes.add(dst);
          elements.push({ data: { id: dst, label: dst, type: 'External IP' } });
        }
        if (src && dst) {
          elements.push({ data: { source: src, target: dst, label: art.protocol || art.artifact_type } });
        }
      });

      if (typeof cytoscape !== 'undefined') {
        window.cyInstance = cytoscape({
          container: document.getElementById('cy'),
          elements: elements,
          style: [
            {
              selector: 'node',
              style: {
                'background-color': function (ele) { return ele.data('type') === 'External IP' ? '#ef4444' : '#0ea5e9'; },
                'label': 'data(label)',
                'color': '#e2e8f0',
                'text-valign': 'bottom',
                'text-halign': 'center',
                'text-margin-y': 6,
                'font-size': '12px',
                'font-weight': '600',
                'width': '35px',
                'height': '35px',
                'border-width': '2px',
                'border-color': 'rgba(255, 255, 255, 0.4)',
                'underlay-color': function (ele) { return ele.data('type') === 'External IP' ? '#ef4444' : '#0ea5e9'; },
                'underlay-padding': 10,
                'underlay-opacity': 0.4,
                'underlay-shape': 'ellipse'
              }
            },
            {
              selector: 'edge',
              style: {
                'width': 2,
                'line-color': '#475569',
                'target-arrow-color': '#475569',
                'target-arrow-shape': 'triangle',
                'curve-style': 'bezier',
                'label': 'data(label)',
                'color': '#cbd5e1',
                'font-size': '10px',
                'text-background-color': '#0f172a',
                'text-background-opacity': 0.8,
                'text-background-padding': '4px',
                'text-background-shape': 'roundrectangle',
                'text-rotation': 'autorotate'
              }
            }
          ],
          layout: {
            name: 'concentric',
            padding: 50,
            animate: true,
            spacingFactor: 1.5,
            minNodeSpacing: 50
          }
        });

        window.cyInstance.on('mouseover', 'node', function (e) {
          const sel = e.target;
          const connectedEdges = sel.connectedEdges();
          const connectedNodes = connectedEdges.connectedNodes();

          window.cyInstance.elements().difference(connectedNodes).difference(connectedEdges).style({
            'opacity': 0.15
          });
        });
        window.cyInstance.on('mouseout', 'node', function (e) {
          window.cyInstance.elements().style({
            'opacity': 1
          });
        });

      } else {
        document.getElementById('cy').innerHTML = '<div style="color:var(--danger); text-align:center; padding-top: 2rem;">Cytoscape.js failed to load.</div>';
      }

    } catch (e) {
      console.error('Failed to load network graph', e);
      document.getElementById('cy').innerHTML = '<div style="color:var(--danger); text-align:center; padding-top: 2rem;">Failed to load network artifacts.</div>';
    }
  };

  const btnRefreshLayout = document.getElementById('btn-refresh-layout');
  if (btnRefreshLayout) {
    btnRefreshLayout.addEventListener('click', () => {
      if (window.cyInstance) {
        window.cyInstance.layout({
          name: 'concentric', padding: 50, animate: true,
          spacingFactor: 1.5, minNodeSpacing: 50
        }).run();
      }
    });
  }

  const networkFilter = document.getElementById('network-filter');
  const networkFilterCustom = document.getElementById('network-filter-custom');

  function applyNetworkFilter(minConnections) {
    if (!window.cyInstance) return;
    window.cyInstance.batch(() => {
      window.cyInstance.nodes().forEach(node => {
        if (node.degree() < minConnections) {
          node.style('display', 'none');
        } else {
          node.style('display', 'element');
        }
      });
    });
  }

  if (networkFilter && networkFilterCustom) {
    networkFilter.addEventListener('change', (e) => {
      if (e.target.value === 'custom') {
        networkFilterCustom.style.display = 'block';
        networkFilterCustom.focus();
        const val = parseInt(networkFilterCustom.value, 10);
        if (!isNaN(val)) applyNetworkFilter(val);
      } else {
        networkFilterCustom.style.display = 'none';
        applyNetworkFilter(parseInt(e.target.value, 10) || 0);
      }
    });

    networkFilterCustom.addEventListener('input', (e) => {
      const val = parseInt(e.target.value, 10);
      if (!isNaN(val)) {
        applyNetworkFilter(val);
      }
    });
  }

  const reportsList = document.getElementById('reports-list');
  const btnGenerateReport = document.getElementById('btn-generate-report');

  window.loadReports = async function () {
    if (!reportsList || !currentCaseId) return;

    try {
      reportsList.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Loading reports...</td></tr>';
      const response = await api('GET', `/api/report?case_id=${currentCaseId}`);

      if (!response.items || response.items.length === 0) {
        reportsList.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No reports generated yet.</td></tr>';
        return;
      }

      reportsList.innerHTML = '';
      response.items.forEach(rpt => {
        const tr = document.createElement('tr');
        const tokenStr = jwtToken || '';

        const dateObj = new Date(rpt.generated_at + 'Z');
        const dateStr = dateObj.toLocaleDateString(undefined, { month: 'short', day: '2-digit', year: 'numeric' });
        const timeStr = dateObj.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });

        tr.innerHTML = `
          <td>${rpt.filename || `Report #${rpt.id}`}</td>
          <td>${(rpt.format || 'pdf').toUpperCase()}</td>
          <td>${dateStr} <span style="color:var(--text-muted); font-size:0.85em;">${timeStr}</span></td>
          <td><span class="badge success">Ready</span></td>
          <td>
            <a href="/api/report/download/${rpt.id}?token=${tokenStr}" target="_blank" class="btn btn-secondary" style="padding: 0.25rem 0.75rem; display:inline-flex; align-items:center; text-decoration:none;">
              <i data-lucide="download" style="width:14px;height:14px;"></i> <span style="margin-left:4px;">Download</span>
            </a>
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

  if (btnGenerateReport) {
    btnGenerateReport.addEventListener('click', async () => {
      if (!currentCaseId) {
        window.showToast("Please open a case to generate a report.", 'error');
        return;
      }
      btnGenerateReport.disabled = true;
      const prevHtml = btnGenerateReport.innerHTML;
      btnGenerateReport.innerHTML = '<i data-lucide="loader" class="lucide-spin" style="width:18px;height:18px;"></i><span>Generating...</span>';
      if (typeof lucide !== 'undefined') lucide.createIcons();

      try {
        await api('POST', '/api/report', { case_id: currentCaseId, format: 'pdf' });
        window.loadReports();
      } catch (err) {
        window.showToast("Failed to generate report: " + err.message, 'error');
      } finally {
        btnGenerateReport.disabled = false;
        btnGenerateReport.innerHTML = prevHtml;
        if (typeof lucide !== 'undefined') lucide.createIcons();
      }
    });
  }

  const btnSaveSettings = document.getElementById('btn-save-settings');
  const inputThreshold = document.getElementById('setting-anomaly-threshold');
  const inputTimezone = document.getElementById('setting-timezone');
  const inputTimeWindow = document.getElementById('setting-time-window');
  const inputCrossCase = document.getElementById('setting-cross-case');

  window.loadSettings = async function () {
    if (!inputThreshold) return;
    try {
      const data = await api('GET', '/api/settings');
      if (data) {
        inputThreshold.value = data.anomaly_threshold;
        inputTimezone.value = data.default_timezone;
        inputTimeWindow.value = data.correlation_time_window_seconds;
        if (inputCrossCase) inputCrossCase.checked = data.cross_case_correlation;
      }
    } catch (err) {
      console.error("Failed to load settings", err);
    }
  };

  if (btnSaveSettings) {
    btnSaveSettings.addEventListener('click', async () => {
      try {
        const payload = {
          anomaly_threshold: parseFloat(inputThreshold.value),
          default_timezone: inputTimezone.value || "UTC",
          correlation_time_window_seconds: parseInt(inputTimeWindow.value, 10),
          cross_case_correlation: inputCrossCase ? inputCrossCase.checked : true
        };
        await api('PUT', '/api/settings', payload);
        window.showToast("Settings saved successfully.", 'success');
      } catch (err) {
        window.showToast("Failed to save settings: " + err.message, 'error');
      }
    });
  }

  const findingModal = document.getElementById('finding-details-modal');
  const btnCloseFindingModal = document.getElementById('btn-close-finding-modal');

  if (findingModal && btnCloseFindingModal) {
    btnCloseFindingModal.addEventListener('click', () => {
      findingModal.style.display = 'none';
      findingModal.classList.add('hidden');
    });
    findingModal.addEventListener('click', (e) => {
      if (e.target === findingModal) {
        findingModal.style.display = 'none';
        findingModal.classList.add('hidden');
      }
    });
  }

});
