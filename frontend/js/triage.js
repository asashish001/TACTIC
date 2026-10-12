import { api } from './api.js?v=2';
import { showToast } from './ui.js';
import { currentCaseId } from './state.js';

let pendingFindings = [];
let currentFindingIndex = 0;

export function setupTriage() {
    const btnRefresh = document.getElementById('btn-refresh-triage');
    if (btnRefresh) {
        btnRefresh.addEventListener('click', loadTriageQueue);
    }
    
    window.loadTriageQueue = loadTriageQueue;
}

async function loadTriageQueue() {
    if (!currentCaseId) {
        renderEmpty();
        return;
    }
    
    try {
        const data = await api('GET', `/api/analyze/findings/${currentCaseId}`);
        pendingFindings = data.filter(f => f.review_status === 'pending');
        currentFindingIndex = 0;
        
        updateCount();
        renderCurrentCard();
    } catch (err) {
        console.error('Failed to load triage queue:', err);
        showToast('Failed to load triage queue.', 'error');
    }
}

function updateCount() {
    const el = document.getElementById('triage-count');
    if (el) {
        el.textContent = `${pendingFindings.length} Pending`;
    }
}

function renderEmpty() {
    const container = document.getElementById('triage-container');
    if (!container) return;
    container.innerHTML = `
        <div id="triage-empty" style="text-align: center; color: var(--text-muted); animation: fadeIn 0.5s ease-out;">
            <i data-lucide="check-circle" style="width: 48px; height: 48px; color: #10b981; margin-bottom: 1rem; opacity: 0.5;"></i>
            <h2>All Caught Up!</h2>
            <p>No pending AI findings require your review.</p>
        </div>
    `;
    if (typeof lucide !== 'undefined') lucide.createIcons();
}

function renderCurrentCard() {
    const container = document.getElementById('triage-container');
    if (!container) return;
    
    if (currentFindingIndex >= pendingFindings.length) {
        renderEmpty();
        return;
    }
    
    const finding = pendingFindings[currentFindingIndex];
    
    let badgeColor = '#3b82f6';
    if (finding.severity.toLowerCase() === 'critical') badgeColor = '#ef4444';
    if (finding.severity.toLowerCase() === 'high') badgeColor = '#ef4444';
    if (finding.severity.toLowerCase() === 'medium') badgeColor = '#f59e0b';
    
    let detailsHtml = '';
    try {
        const parsedDetails = typeof finding.details === 'string' ? JSON.parse(finding.details) : finding.details;
        detailsHtml = `<pre style="background: rgba(0,0,0,0.3); padding: 1rem; border-radius: 0.5rem; overflow-x: auto; max-height: 150px; font-size: 0.85rem;">${JSON.stringify(parsedDetails, null, 2)}</pre>`;
    } catch (e) {
        detailsHtml = `<p>${finding.details || 'None'}</p>`;
    }

    container.innerHTML = `
        <div id="triage-card" style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 1rem; width: 100%; max-width: 650px; padding: 2rem; box-shadow: 0 10px 30px rgba(0,0,0,0.3); transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); position: relative;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.5rem;">
                <div>
                    <span style="background: ${badgeColor}22; color: ${badgeColor}; padding: 0.25rem 0.75rem; border-radius: 999px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; border: 1px solid ${badgeColor}55;">${finding.severity}</span>
                    <h2 style="font-size: 1.5rem; margin-top: 1rem; color: white;">${finding.title}</h2>
                </div>
                ${finding.confidence ? `
                <div style="text-align: right;">
                    <div style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;">Confidence</div>
                    <div style="font-size: 1.75rem; font-weight: 700; color: ${finding.confidence >= 0.8 ? '#ef4444' : '#f59e0b'};">${Math.round(finding.confidence * 100)}%</div>
                </div>` : ''}
            </div>
            
            <div style="margin-bottom: 1.5rem; color: #cbd5e1; line-height: 1.6;">
                <p style="margin-bottom: 1rem;"><strong>Source:</strong> <span style="color: #38bdf8;">${finding.evidence_filename || 'Unknown'}</span></p>
                <p style="background: rgba(255,255,255,0.05); padding: 1rem; border-radius: 0.5rem;">${finding.description}</p>
            </div>
            
            <div style="margin-bottom: 2rem;">
                <h4 style="color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; margin-bottom: 0.5rem;">Technical Details</h4>
                ${detailsHtml}
            </div>
            
            <div style="display: flex; gap: 1rem; justify-content: space-between; margin-top: 2rem; border-top: 1px solid var(--border-color); padding-top: 1.5rem;">
                <button id="btn-reject" style="flex: 1; padding: 1rem; border-radius: 0.75rem; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); color: #ef4444; font-weight: 600; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 0.5rem; transition: all 0.2s;">
                    <i data-lucide="x-circle" style="width: 20px; height: 20px;"></i> Reject
                </button>
                <button id="btn-approve" style="flex: 1; padding: 1rem; border-radius: 0.75rem; background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); color: #10b981; font-weight: 600; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 0.5rem; transition: all 0.2s;">
                    <i data-lucide="check-circle" style="width: 20px; height: 20px;"></i> Approve
                </button>
            </div>
        </div>
    `;
    
    if (typeof lucide !== 'undefined') lucide.createIcons();
    
    document.getElementById('btn-approve').addEventListener('click', () => submitReview(finding.id, 'approved', 1));
    document.getElementById('btn-reject').addEventListener('click', () => submitReview(finding.id, 'rejected', -1));
}

async function submitReview(findingId, status, direction) {
    const card = document.getElementById('triage-card');
    
    // Animate out (swipe left/right)
    card.style.transform = `translateX(${direction * 150}%) rotate(${direction * 15}deg)`;
    card.style.opacity = '0';
    
    try {
        await api('PUT', `/api/analyze/findings/${findingId}/review`, {
            review_status: status,
            review_notes: ''
        });
        
        showToast(`Finding ${status}!`, 'success');
        
        pendingFindings.splice(currentFindingIndex, 1);
        updateCount();
        
        // Render next after brief delay for animation
        setTimeout(() => {
            renderCurrentCard();
        }, 300);
        
    } catch (err) {
        console.error('Review failed:', err);
        showToast('Failed to submit review.', 'error');
        card.style.transform = 'none';
        card.style.opacity = '1';
    }
}
