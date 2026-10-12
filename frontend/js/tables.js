export function setupTables() {
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

  // --- Universal Table Sorting & Filtering ---
  function initTable(tableId, searchInputId) {
    const table = document.getElementById(tableId);
    const searchInput = document.getElementById(searchInputId);
    if (!table || !searchInput) return;

    let currentSortCol = -1;
    let currentSortAsc = true;

    const tbody = table.querySelector('tbody');
    if (!tbody) return;
    const headers = table.querySelectorAll('th.sortable');

    const thead = table.querySelector('thead');
    if (thead && !thead.querySelector('.filters-row')) {
      const filterRow = document.createElement('tr');
      filterRow.className = 'filters-row';
      const originalThs = thead.querySelectorAll('tr:first-child th');
      
      originalThs.forEach((th, index) => {
        const filterTh = document.createElement('th');
        filterTh.style.padding = '0.25rem 0.5rem';
        filterTh.style.background = 'rgba(15, 23, 42, 0.98)';
        filterTh.style.borderBottom = '1px solid var(--border-color)';
        filterTh.style.position = 'sticky';
        filterTh.style.top = '32px'; // Offset for the first sticky header row
        filterTh.style.zIndex = '10';
        
        if (th.textContent.trim() !== '') {
          const input = document.createElement('input');
          input.type = 'text';
          input.placeholder = 'Filter...';
          input.dataset.col = index;
          input.className = 'column-filter-input';
          input.style.width = '100%';
          input.style.padding = '0.25rem 0.5rem';
          input.style.fontSize = '0.75rem';
          input.style.background = 'rgba(0,0,0,0.2)';
          input.style.color = 'var(--text-main)';
          input.style.border = '1px solid rgba(255,255,255,0.1)';
          input.style.borderRadius = '0.25rem';
          input.style.outline = 'none';
          
          input.addEventListener('input', filterTable);
          filterTh.appendChild(input);
        }
        filterRow.appendChild(filterTh);
      });
      thead.appendChild(filterRow);
    }

    function filterTable() {
      const globalTerm = searchInput.value.toLowerCase();
      const colInputs = table.querySelectorAll('.column-filter-input');
      
      const rows = Array.from(tbody.querySelectorAll('tr'));
      if (rows.length === 1 && rows[0].querySelector('td[colspan]')) return; // skip empty state

      rows.forEach(row => {
        let matchGlobal = true;
        if (globalTerm) {
          matchGlobal = row.textContent.toLowerCase().includes(globalTerm);
        }
        
        let matchCols = true;
        colInputs.forEach(input => {
          const term = input.value.toLowerCase();
          if (term) {
            const colIndex = parseInt(input.dataset.col);
            const cell = row.children[colIndex];
            if (cell && !cell.textContent.toLowerCase().includes(term)) {
              matchCols = false;
            }
          }
        });
        
        row.style.display = (matchGlobal && matchCols) ? '' : 'none';
      });
    }

    function sortTable(colIndex, type) {
      const rows = Array.from(tbody.querySelectorAll('tr'));
      if (rows.length <= 1 && rows[0]?.querySelector('td[colspan]')) return; // skip empty state

      const isAsc = currentSortCol === colIndex ? !currentSortAsc : true;
      currentSortCol = colIndex;
      currentSortAsc = isAsc;

      headers.forEach(th => th.classList.remove('active', 'desc'));
      const activeTh = headers[colIndex];
      if (activeTh) {
        activeTh.classList.add('active');
        if (!isAsc) activeTh.classList.add('desc');
      }

      rows.sort((a, b) => {
        const aCell = a.children[colIndex];
        const bCell = b.children[colIndex];
        if (!aCell || !bCell) return 0;
        
        const aText = aCell.textContent.trim();
        const bText = bCell.textContent.trim();
        
        const priorityWeights = { 'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1 };
        const aWeight = priorityWeights[aText.toLowerCase()];
        const bWeight = priorityWeights[bText.toLowerCase()];
        
        let cmp = 0;
        if (aWeight !== undefined && bWeight !== undefined) {
          cmp = aWeight - bWeight;
        } else {
          const numA = parseFloat(aText);
          const numB = parseFloat(bText);
          if (!isNaN(numA) && !isNaN(numB) && numA.toString() === aText && numB.toString() === bText) {
            cmp = numA - numB;
          } else {
            cmp = aText.localeCompare(bText);
          }
        }
        
        return isAsc ? cmp : -cmp;
      });

      rows.forEach(row => tbody.appendChild(row));
    }

    searchInput.addEventListener('input', filterTable);

    headers.forEach((th, index) => {
      th.addEventListener('click', () => {
        sortTable(index, th.dataset.sort);
      });
    });
    
    // Create a global trigger so filter runs after fetching new data
    window[`triggerFilter_${tableId}`] = filterTable;
  }

  initTable('evidence-table', 'search-evidence');
  initTable('timeline-table', 'search-timeline');
  initTable('artifacts-table', 'search-artifacts');

  // --- CSV Export Logic ---
  function exportTableToCSV(tableId, filename) {
    const table = document.getElementById(tableId);
    if (!table) return;

    let csv = [];
    const rows = table.querySelectorAll('tr');

    rows.forEach(row => {
        if (row.classList.contains('filters-row')) return;
        if (row.style.display === 'none') return;
        
        const cols = row.querySelectorAll('td, th');
        let rowData = [];
        cols.forEach(col => {
            let text = col.innerText.replace(/"/g, '""').trim();
            if (text.includes(',') || text.includes('\n') || text.includes('"')) {
                text = `"${text}"`;
            }
            rowData.push(text);
        });
        csv.push(rowData.join(','));
    });

    const csvFile = new Blob([csv.join('\n')], { type: 'text/csv' });
    const downloadLink = document.createElement('a');
    downloadLink.download = filename;
    downloadLink.href = window.URL.createObjectURL(csvFile);
    downloadLink.style.display = 'none';
    document.body.appendChild(downloadLink);
    downloadLink.click();
    document.body.removeChild(downloadLink);
  }

  const btnExportEvidence = document.getElementById('btn-export-evidence');
  if (btnExportEvidence) {
      btnExportEvidence.addEventListener('click', () => exportTableToCSV('evidence-table', 'Evidence_Locker_Export.csv'));
  }

  const btnExportTimeline = document.getElementById('btn-export-timeline');
  if (btnExportTimeline) {
      btnExportTimeline.addEventListener('click', () => exportTableToCSV('timeline-table', 'Investigation_Timeline_Export.csv'));
  }
}
