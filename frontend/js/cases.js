import { api } from './api.js?v=2';
import { renderEmptyState, showToast } from './ui.js';
import { currentCaseId, setCurrentCaseId, allCases, setAllCases } from './state.js';

export function setupCases() {
    const casesList = document.getElementById('cases-list');
    const globalCaseSelect = document.getElementById('global-case-select');

    window.updateGlobalCaseSelector = function() {
        if (!globalCaseSelect) return;
        globalCaseSelect.innerHTML = '<option value="">-- No Case Selected --</option>';
        allCases.forEach(c => {
            const opt = document.createElement('option');
            opt.value = c.id;
            opt.textContent = `${c.case_number} - ${c.name}`;
            if (c.id == currentCaseId) opt.selected = true;
            globalCaseSelect.appendChild(opt);
        });
    }

    if (globalCaseSelect) {
        globalCaseSelect.addEventListener('change', (e) => {
            setCurrentCaseId(e.target.value);
            if (currentCaseId) {
                localStorage.setItem('currentCaseId', currentCaseId);
            } else {
                localStorage.removeItem('currentCaseId');
            }
            if (document.getElementById('view-dashboard') && !document.getElementById('view-dashboard').classList.contains('hidden')) {
                if (typeof window.loadDashboardData === 'function') window.loadDashboardData();
            }
            const activeNav = document.querySelector('.nav-item.active');
            if (activeNav && typeof window.checkCaseSelection === 'function') window.checkCaseSelection(activeNav.getAttribute('data-view'));

            if (typeof window.loadEvidence === 'function') window.loadEvidence();
            if (typeof window.loadAnalysisJobs === 'function') window.loadAnalysisJobs();
            if (typeof window.loadAnalysisFindings === 'function') window.loadAnalysisFindings();
            if (typeof window.loadExtractedArtifacts === 'function') window.loadExtractedArtifacts();
            if (typeof window.loadTimeline === 'function') window.loadTimeline();
            if (typeof window.loadNetworkGraph === 'function') window.loadNetworkGraph();
            if (typeof window.loadReports === 'function') window.loadReports();
        });
    }

    window.loadCases = async function() {
        if (!casesList) return;
        casesList.innerHTML = `
          <div class="stat-card skeleton-row" style="display:flex; flex-direction:column; gap:0.5rem;">
            <div class="skeleton-box short"></div>
            <div class="skeleton-box medium"></div>
          </div>
          <div class="stat-card skeleton-row" style="display:flex; flex-direction:column; gap:0.5rem;">
            <div class="skeleton-box short"></div>
            <div class="skeleton-box medium"></div>
          </div>
        `;
        try {
            const data = await api('GET', '/api/cases');
            setAllCases(data.items || []);
            casesList.innerHTML = '';
            if (data.items.length === 0) {
                casesList.innerHTML = renderEmptyState('briefcase', 'No Cases Found', 'Get started by creating a new case for your investigation.', false);
                if (typeof window.loadEvidence === 'function') window.loadEvidence();
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
                    setCurrentCaseId(e.target.closest('button').getAttribute('data-id'));
                    if(currentCaseId) localStorage.setItem('currentCaseId', currentCaseId);
                    window.updateGlobalCaseSelector();
                    const evidenceNav = Array.from(document.querySelectorAll('.nav-item')).find(n => n.getAttribute('data-view') === 'evidence');
                    if (evidenceNav) evidenceNav.click();
                    if (typeof window.loadEvidence === 'function') window.loadEvidence();
                    if (typeof window.loadAnalysisJobs === 'function') window.loadAnalysisJobs();
                    if (typeof window.loadAnalysisFindings === 'function') window.loadAnalysisFindings();
                    if (typeof window.loadExtractedArtifacts === 'function') window.loadExtractedArtifacts();
                    if (typeof window.loadTimeline === 'function') window.loadTimeline();
                    if (typeof window.loadNetworkGraph === 'function') window.loadNetworkGraph();
                    if (typeof window.loadReports === 'function') window.loadReports();
                });
            });

            window.updateGlobalCaseSelector();

            const activeNav = document.querySelector('.nav-item.active');
            if (activeNav && typeof window.checkCaseSelection === 'function') window.checkCaseSelection(activeNav.getAttribute('data-view'));

            if (typeof window.loadEvidence === 'function') window.loadEvidence();
            if (typeof window.loadAnalysisJobs === 'function') window.loadAnalysisJobs();
            if (typeof window.loadAnalysisFindings === 'function') window.loadAnalysisFindings();
            if (typeof window.loadExtractedArtifacts === 'function') window.loadExtractedArtifacts();
            if (typeof window.loadTimeline === 'function') window.loadTimeline();
            if (typeof window.loadNetworkGraph === 'function') window.loadNetworkGraph();
            if (typeof window.loadReports === 'function') window.loadReports();
            if (typeof window.loadSettings === 'function') window.loadSettings();
        } catch (e) {
            console.error(e);
            casesList.innerHTML = '<div style="color: var(--danger); padding: 1rem;">Failed to load cases.</div>';
        }
    }

    window.loadCases();

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
                window.loadCases();
            } catch (err) {
                console.error(err);
                showToast('Failed to create case: ' + err.message, 'error');
            } finally {
                btnSubmit.textContent = 'Create Case';
                btnSubmit.disabled = false;
            }
        });
    }
}
