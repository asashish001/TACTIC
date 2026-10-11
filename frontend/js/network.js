import { api } from './api.js?v=2';
import { showToast, renderEmptyState, showContextMenu } from './ui.js?v=31';
import { currentCaseId } from './state.js';

export function setupNetwork() {
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

        // Add context menu on right click
        window.cyInstance.on('cxttap', 'node', function(e) {
          const node = e.target;
          showContextMenu(e.originalEvent, {
            type: 'Network Artifact',
            label: node.data('label') || node.id(),
            id: node.id()
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
}
