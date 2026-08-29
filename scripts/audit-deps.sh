#!/usr/bin/env bash
# audit-deps.sh — Run pip-audit to check for known vulnerabilities.
#
# Usage:
#   ./scripts/audit-deps.sh            # table output
#   ./scripts/audit-deps.sh --json     # JSON output
#   ./scripts/audit-deps.sh --fix      # attempt automatic upgrades
set -euo pipefail

cd "$(dirname "$0")/.."

echo "═══════════════════════════════════════════════════"
echo "  T.A.C.T.I.C. — Dependency Vulnerability Audit"
echo "═══════════════════════════════════════════════════"
echo ""

# Ensure pip-audit is installed
if ! command -v pip-audit &>/dev/null; then
    echo "[*] pip-audit not found. Installing..."
    pip install pip-audit
fi

echo "[*] Auditing backend/requirements.txt ..."
echo ""

if [ "${1:-}" = "--fix" ]; then
    echo "[*] Attempting to upgrade vulnerable packages..."
    pip-audit -r backend/requirements.txt --progress-spinner=off \
        --fix --dry-run 2>&1 || true
    echo ""
    echo "[*] Run without --dry-run to apply upgrades."
elif [ "${1:-}" = "--json" ]; then
    pip-audit -r backend/requirements.txt --format json --progress-spinner=off
else
    pip-audit -r backend/requirements.txt --progress-spinner=off
fi

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ No known vulnerabilities found."
else
    echo "⚠️  Vulnerabilities detected. Review output above."
    echo "   Run: pip-audit --fix  to attempt automatic remediation."
fi

exit $EXIT_CODE
