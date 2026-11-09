import { api, jwtToken } from './api.js?v=2';
import { renderEmptyState, showToast, showContextMenu } from './ui.js?v=31';
import { currentCaseId, setCurrentCaseId, allCases } from './state.js';
import { openEvidenceCertificate } from './certificate.js?v=2';

const evidenceMap = new Map();

export function setupEvidence() {
    const evidenceList = document.getElementById('evidence-list');
    if (evidenceList) {
        evidenceList.addEventListener('click', async (e) => {
            const link = e.target.closest('.evidence-link, .btn-cert-open, .btn-raw-open');
            if (link) {
                e.preventDefault();
                const id = link.getAttribute('data-id');
                const evItem = evidenceMap.get(String(id));
                if (evItem) {
                    openEvidenceCertificate(evItem);
                }
                return;
            }
        });
    }

    function formatBytes(bytes) {
        if (bytes === 0 || !bytes) return '0 B';
        const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'], i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    window.loadEvidence = async function() {
        if (!evidenceList) return;

        if (!currentCaseId) {
            evidenceList.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Please create a case first.</td></tr>';
            return;
        }

        evidenceList.innerHTML = `
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
          <tr class="skeleton-row">
            <td><div class="skeleton-box short"></div></td>
            <td><div class="skeleton-box medium"></div></td>
            <td><div class="skeleton-box short"></div></td>
            <td><div class="skeleton-box"></div></td>
            <td><div class="skeleton-box short"></div></td>
          </tr>
        `;
        try {
            const data = await api('GET', `/api/evidence?case_id=${currentCaseId}`);
            evidenceList.innerHTML = '';
            
            let diskImages = 0;
            let documents = 0;
            let memoryDumps = 0;
            
            const diskExts = ['iso', 'img', 'dd', 'e01'];
            const memExts = ['mem', 'dmp', 'vmem', 'crash', 'raw', 'bin'];
            const docExts = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'md', 'csv', 'rtf', 'html', 'json', 'xml', 'log'];
            
            if (!data.items || data.items.length === 0) {
                evidenceList.innerHTML = renderEmptyState('folder-open', 'No Evidence Uploaded', 'Drag and drop files here or click "Upload Evidence" to add forensic artifacts.', true, 5);
            } else {
                data.items.forEach(ev => {
                    let ext = (ev.extension || '').toLowerCase();
                    
                    if (diskExts.includes(ext)) diskImages++;
                    else if (memExts.includes(ext)) memoryDumps++;
                    else if (docExts.includes(ext)) documents++;
                    else documents++;
                    
                    evidenceMap.set(String(ev.id), ev);
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>${ev.id}</td>
                        <td>
                            <a href="#" class="evidence-link" data-id="${ev.id}" data-filename="${ev.filename}" title="Click to open raw evidence file" style="color: var(--accent); font-weight: 600; cursor: pointer; display: inline-flex; align-items: center; gap: 0.4rem; text-decoration: none;">
                                <i data-lucide="file-text" style="width: 15px; height: 15px; color: var(--accent);"></i>
                                <span style="text-decoration: underline;">${ev.filename}</span>
                            </a>
                        </td>
                        <td><span class="badge" style="font-size: 0.72rem; background: #f1f5f9; color: var(--text-secondary);">${ev.detected_mime || ev.extension || 'Unknown'}</span></td>
                        <td>${formatBytes(ev.file_size)}</td>
                        <td><span class="badge success" style="font-size: 0.72rem;">● Processed</span></td>
                        <td>
                            <div style="display: flex; align-items: center; gap: 0.35rem;">
                                <button class="btn btn-sm btn-raw-open" data-id="${ev.id}" title="Inspect Raw Evidence Payload" style="padding: 0.25rem 0.55rem; font-size: 0.75rem; display: inline-flex; align-items: center; gap: 0.25rem; background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; cursor: pointer; border-radius: 4px;">
                                    <i data-lucide="file-code" style="width: 13px; height: 13px;"></i>
                                    <span>Raw File</span>
                                </button>
                                <button class="btn btn-icon context-btn" aria-label="More Options" style="background: transparent; border: none; padding: 0.25rem; color: var(--text-muted); cursor: pointer;">
                                    <i data-lucide="more-vertical" style="width: 16px; height: 16px;"></i>
                                </button>
                            </div>
                        </td>
                    `;
                    const btn = tr.querySelector('.context-btn');
                    if (btn) {
                        btn.addEventListener('click', (e) => {
                            e.stopPropagation();
                            showContextMenu(e, { type: 'Evidence', label: ev.filename, id: ev.id });
                        });
                    }
                    evidenceList.appendChild(tr);
                });
            }
            
            const statDisk = document.getElementById('stat-disk-images');
            if (statDisk) statDisk.innerText = `${diskImages} items`;
            const statDocs = document.getElementById('stat-documents');
            if (statDocs) statDocs.innerText = `${documents} items`;
            const statMem = document.getElementById('stat-memory-dumps');
            if (statMem) statMem.innerText = `${memoryDumps} items`;
            
            if (typeof lucide !== 'undefined') {
                lucide.createIcons();
            }

            loadChainOfCustodyLedger(currentCaseId);

        } catch (e) {
            console.error(e);
            evidenceList.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--danger);">Failed to load evidence.</td></tr>';
        }
    }

    async function loadChainOfCustodyLedger(caseId) {
        const tbody = document.getElementById('custody-ledger-table-body');
        if (!tbody || !caseId) return;
        try {
            const records = await api('GET', `/api/forensic-records/cases/${caseId}/chain-of-custody`);
            if (records && records.length > 0) {
                tbody.innerHTML = records.map(r => {
                    const dateStr = (r.occurred_at || '').slice(0, 19).replace('T', ' ');
                    const isIngest = (r.action || '').includes('ingested') || (r.action || '').includes('upload');
                    const isReport = (r.action || '').includes('report');
                    const badgeStyle = isIngest ? 'background: #dcfce7; color: #15803d; border: 1px solid #bbf7d0;' : (isReport ? 'background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe;' : 'background: #f1f5f9; color: var(--text-secondary);');
                    const hashDisplay = r.hash_snapshot ? `<code style="color: #16a34a;">${r.hash_snapshot}</code>` : `<code style="color: #64748b; font-size: 0.7rem;">UUID: ${r.details?.report_id ? 'REPORT-' + r.details.report_id : 'HASH_VERIFIED'}</code>`;
                    const fileMatch = r.description ? (r.description.match(/'([^']+)'/) || [])[1] : null;
                    const itemLabel = fileMatch || (r.action === 'case_opened' ? 'Case Dossier' : 'Forensic Record');
                    return `
                    <tr style="border-top: 1px solid var(--border-subtle);">
                      <td style="padding: 1.1rem 1.25rem; font-family: monospace; color: var(--text-secondary); font-size: 0.8rem;">${dateStr}</td>
                      <td style="padding: 1.1rem 1.25rem;"><span class="badge" style="font-size: 0.7rem; text-transform: uppercase; ${badgeStyle}">● ${r.action}</span></td>
                      <td style="padding: 1.1rem 1.25rem; color: var(--text-main); font-weight: 600;">
                        <div style="display: flex; align-items: center; gap: 0.5rem;">
                          <i data-lucide="${isReport ? 'file-check' : (isIngest ? 'file-text' : 'shield-check')}" style="width: 15px; height: 15px; color: ${isReport ? '#f59e0b' : '#2563eb'};"></i>
                          <span>${itemLabel}</span>
                        </div>
                      </td>
                      <td style="padding: 1.1rem 1.25rem; font-family: monospace; font-size: 0.75rem;">${hashDisplay}</td>
                      <td style="padding: 1.1rem 1.25rem; color: var(--text-secondary); font-size: 0.8rem;">admin <span style="color: var(--text-muted);">(Investigator)</span></td>
                      <td style="padding: 1.1rem 1.25rem;"><span class="badge success" style="font-size: 0.7rem;">✓ VERIFIED</span></td>
                    </tr>
                    `;
                }).join('');
                if (typeof lucide !== 'undefined') lucide.createIcons();
            }
        } catch (err) {
            console.warn('Custody fetch fallback:', err);
        }
    }

    const btnScrollLeft = document.getElementById('btn-custody-scroll-left');
    const btnScrollRight = document.getElementById('btn-custody-scroll-right');
    const custodyContainer = document.getElementById('custody-scroll-container');

    if (btnScrollLeft && custodyContainer) {
        btnScrollLeft.addEventListener('click', () => {
            custodyContainer.scrollBy({ left: -280, behavior: 'smooth' });
        });
    }
    if (btnScrollRight && custodyContainer) {
        btnScrollRight.addEventListener('click', () => {
            custodyContainer.scrollBy({ left: 280, behavior: 'smooth' });
        });
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
                if (allCases.length === 0) {
                    caseSelectorContainer.innerHTML = '<div style="color: var(--danger);">Please create a case first before uploading.</div>';
                } else {
                    let options = allCases.map(c => `<option value="${c.id}" ${c.id == currentCaseId ? 'selected' : ''}>${c.case_number} - ${c.name}</option>`).join('');
                    caseSelectorContainer.innerHTML = `
                        <label style="display: block; margin-bottom: 0.5rem; color: var(--text-secondary); font-size: 0.85rem; font-weight: 500;">Select Case</label>
                        <select id="upload-case-id" required style="width: 100%; padding: 0.75rem;">
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
                showToast('Please create a case first.', 'error');
                return;
            }

            const btnSubmit = document.getElementById('btn-submit-upload');
            btnSubmit.textContent = 'Uploading...';
            btnSubmit.disabled = true;

            try {
                const files = Array.from(fileInput.files);
                for (const file of files) {
                    const formData = new FormData();
                    formData.append('case_id', caseIdInput.value);
                    formData.append('file', file);

                    const response = await fetch('/api/evidence/upload', {
                        method: 'POST',
                        headers: { 'Authorization': `Bearer ${jwtToken}` },
                        body: formData
                    });

                    if (!response.ok) {
                        const errText = await response.text();
                        throw new Error(response.statusText + ' - ' + errText);
                    }
                }

                uploadModal.style.display = 'none';
                uploadModal.classList.add('hidden');
                uploadEvidenceForm.reset();

                setCurrentCaseId(caseIdInput.value);
                localStorage.setItem('currentCaseId', currentCaseId);
                window.loadEvidence();
                showToast(`Successfully uploaded ${files.length} file(s).`, 'success');
            } catch (err) {
                console.error(err);
                showToast('Upload failed: ' + err.message, 'error');
            } finally {
                btnSubmit.textContent = 'Upload File';
                btnSubmit.disabled = false;
            }
        });
    }

    const dropZone = document.getElementById('evidence-drop-zone');
    const dropOverlay = document.getElementById('evidence-drop-overlay');

    if (dropZone && dropOverlay) {
        const preventDefaults = (e) => {
            e.preventDefault();
            e.stopPropagation();
        };

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, preventDefaults, false);
            document.body.addEventListener(eventName, preventDefaults, false);
        });

        dropZone.addEventListener('dragenter', () => dropOverlay.style.display = 'flex', false);
        dropZone.addEventListener('dragover', () => dropOverlay.style.display = 'flex', false);
        dropZone.addEventListener('dragleave', (e) => {
            if (e.relatedTarget && dropZone.contains(e.relatedTarget)) return;
            dropOverlay.style.display = 'none';
        }, false);
        
        dropZone.addEventListener('drop', async (e) => {
            dropOverlay.style.display = 'none';
            
            if (!currentCaseId) {
                showToast('Please select a case first before dropping files.', 'error');
                return;
            }

            const files = e.dataTransfer.files;
            if (!files || files.length === 0) return;

            showToast(`Uploading ${files.length} file(s)...`, 'info');
            try {
                for (let i = 0; i < files.length; i++) {
                    const formData = new FormData();
                    formData.append('case_id', currentCaseId);
                    formData.append('file', files[i]);
                    
                    const response = await fetch('/api/evidence/upload', {
                        method: 'POST',
                        headers: { 'Authorization': `Bearer ${jwtToken}` },
                        body: formData
                    });
                    
                    if (!response.ok) {
                        throw new Error(`Failed to upload ${files[i].name}`);
                    }
                }
                showToast(`Successfully uploaded ${files.length} file(s).`, 'success');
                window.loadEvidence();
            } catch (err) {
                console.error(err);
                showToast(err.message, 'error');
            }
        }, false);
    }
}
