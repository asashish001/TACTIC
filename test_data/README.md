# Manual Test Data Pack

These files are harmless, synthetic artifacts for testing the AIDFA workflow. They contain no executable payloads or personal data.

1. Sign in with the demo account shown on the login page.
2. Create a case, for example `DEMO-2026-001`.
3. Upload all files in this folder through **Evidence Ingestion**.
4. Use **Artifact Analysis** to select `browser_bookmarks.json` and click **Analyze browser**.
5. Use **Timeline & Risk** to run the risk scan and build the timeline. `invoice.pdf.exe` should produce high-risk filename findings.
6. Use **Search & Preview** to search for `203.0.113.42`, `credential`, or `invoice`.
7. In the FastAPI service, upload `chrome_120.0.1.log`, enable
   `THREAT_INTEL_REMOTE_LOOKUPS=true`, and call
   `POST /api/intelligence/cases/{case_id}/analyze` to test software detection
   and CVE enrichment.

`sample.evtx` is intentionally not included: a valid EVTX file must be captured or exported from Windows Event Viewer. The browser JSON sample exercises M4 without needing a Windows machine.
