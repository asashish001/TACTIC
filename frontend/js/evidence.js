import { api, jwtToken } from './api.js?v=2';
import { renderEmptyState, showToast, showContextMenu } from './ui.js?v=31';
import { currentCaseId, setCurrentCaseId, allCases } from './state.js';

export function setupEvidence() {
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
                    
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>${ev.id}</td>
                        <td><a href="#" class="evidence-link" data-id="${ev.id}" data-filename="${ev.filename}" style="color: var(--primary); text-decoration: underline; cursor: pointer;">${ev.filename}</a></td>
                        <td>${ev.detected_mime || ev.extension || 'Unknown'}</td>
                        <td>${formatBytes(ev.file_size)}</td>
                        <td><span class="badge success">Processed</span></td>
                        <td>
                            <button class="btn btn-icon context-btn" aria-label="More Options" style="background: transparent; border: none; padding: 0.25rem; color: var(--text-muted);">
                                <i data-lucide="more-vertical" style="width: 16px; height: 16px;"></i>
                            </button>
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
                if (allCases.length === 0) {
                    caseSelectorContainer.innerHTML = '<div style="color: var(--danger);">Please create a case first before uploading.</div>';
                } else {
                    let options = allCases.map(c => `<option value="${c.id}" ${c.id == currentCaseId ? 'selected' : ''}>${c.case_number} - ${c.name}</option>`).join('');
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
