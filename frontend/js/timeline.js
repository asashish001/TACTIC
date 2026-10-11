import { api } from './api.js?v=2';
import { showToast, renderEmptyState } from './ui.js';
import { currentCaseId } from './state.js';

export function setupTimeline() {
    const timelineList = document.getElementById('timeline-events-list');

    window.loadTimeline = async function () {
    if (!timelineList || !currentCaseId) return;
    try {
      timelineList.innerHTML = `
      <tr class="skeleton-row">
        <td><div class="skeleton-box short"></div></td>
        <td><div class="skeleton-box"></div></td>
        <td><div class="skeleton-box medium"></div></td>
        <td><div class="skeleton-box short"></div></td>
        <td><div class="skeleton-box short"></div></td>
      </tr>
      <tr class="skeleton-row">
        <td><div class="skeleton-box short"></div></td>
        <td><div class="skeleton-box"></div></td>
        <td><div class="skeleton-box medium"></div></td>
        <td><div class="skeleton-box short"></div></td>
        <td><div class="skeleton-box short"></div></td>
      </tr>
    `;
      const data = await api('GET', `/api/timeline/${currentCaseId}`);
      if (!data.events || data.events.length === 0) {
        timelineList.innerHTML = renderEmptyState('clock', 'Timeline Empty', 'Events will populate here as evidence is processed and analyzed.', true, 5);
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
}
