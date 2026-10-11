export let currentCaseId = localStorage.getItem('currentCaseId') || null;
export let allCases = [];

export function setCurrentCaseId(id) {
    currentCaseId = id;
    if (id) {
        localStorage.setItem('currentCaseId', id);
    } else {
        localStorage.removeItem('currentCaseId');
    }
}

export function setAllCases(cases) {
    allCases = cases;
}
