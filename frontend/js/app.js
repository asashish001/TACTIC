if (typeof lucide !== 'undefined') {
  lucide.createIcons();
}

import { currentCaseId } from './state.js?v=30';
import { setupCases } from './cases.js?v=30';
import { setupEvidence } from './evidence.js?v=31';
import { setupChat } from './chat.js?v=31';
import { setupDashboard } from './dashboard.js?v=30';
import { setupAnalysis } from './analysis.js?v=31';
import { setupTimeline } from './timeline.js?v=30';
import { setupNetwork } from './network.js?v=31';
import { setupTriage } from './triage.js?v=30';
import { setupReports } from './reports.js?v=30';
import { setupSettings } from './settings.js?v=30';
import { setupTables } from './tables.js?v=30';
import { setupContextMenu } from './ui.js?v=31';
import { setupSession } from './session.js?v=2';
import { setupAuth } from './auth.js?v=1';

document.addEventListener('DOMContentLoaded', () => {
  setupAuth();
  setupSession();
  setupContextMenu();
  setupDashboard();
  setupAnalysis();
  setupTimeline();
  setupNetwork();
  setupTriage();
  setupReports();
  setupSettings();
  setupTables();
  setupCases();
  setupEvidence();
  setupChat();

  const navItems = document.querySelectorAll('.nav-item');
  const views = document.querySelectorAll('.view');
  const noCaseOverlay = document.getElementById('no-case-overlay');

  const mobileMenuBtn = document.getElementById('mobile-menu-btn');
  const sidebar = document.getElementById('sidebar');
  if (mobileMenuBtn && sidebar) {
    mobileMenuBtn.addEventListener('click', () => {
      sidebar.classList.toggle('open');
    });
  }

  window.checkCaseSelection = function (viewName) {
    if (!noCaseOverlay) return;
    const requiresCase = ['dashboard', 'evidence', 'analysis', 'timeline', 'network', 'chat', 'reports', 'triage', 'artifacts'];
    if (requiresCase.includes(viewName) && !currentCaseId) {
      noCaseOverlay.style.display = 'flex';
    } else {
      noCaseOverlay.style.display = 'none';
    }
  };

  navItems.forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();

      if (sidebar && sidebar.classList.contains('open')) {
        sidebar.classList.remove('open');
      }

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
        
        if (item.getAttribute('data-view') === 'triage' && window.loadTriageQueue) {
            window.loadTriageQueue();
        }
        
        if (item.getAttribute('data-view') === 'artifacts' && window.loadExtractedArtifacts) {
            window.loadExtractedArtifacts();
        }
        
        if (item.getAttribute('data-view') === 'timeline' && window.loadTimeline) {
            window.loadTimeline();
        }
      }
    });
  });

  const roleSelector = document.getElementById('role-selector');
  if (roleSelector) {
    roleSelector.addEventListener('change', (e) => {
      if (e.target.value === 'executive') {
        document.body.classList.add('role-executive');
        const currentActive = document.querySelector('.nav-item.active')?.getAttribute('data-view');
        if (['triage', 'timeline', 'network'].includes(currentActive)) {
          document.querySelector('.nav-item[data-view="dashboard"]')?.click();
        }
      } else {
        document.body.classList.remove('role-executive');
      }
    });
  }
});
