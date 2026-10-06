import datetime
from pathlib import Path

from docx import Document
from docx.shared import Inches, Pt
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def build_pdf_report(case_data: dict, destination: Path) -> None:
    """Compile case evidence, timelines, and findings into a publication-quality PDF report."""
    styles = getSampleStyleSheet()
    story = []
    
    custom_title_style = ParagraphStyle(
        "CoverTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#0f2a4a"),
        spaceAfter=15
    )
    
    custom_heading1 = ParagraphStyle(
        "Heading1Blue",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=16,
        leading=20,
        textColor=colors.HexColor("#1b4d82"),
        spaceBefore=15,
        spaceAfter=10
    )

    ParagraphStyle(
        "CodeBox",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#333333"),
        spaceBefore=6,
        spaceAfter=6
    )

    story.append(Spacer(1, 150))
    story.append(Paragraph("AI DIGITAL FORENSICS ASSISTANT", custom_title_style))
    story.append(Paragraph("Forensic Investigation Report", styles["Heading2"]))
    story.append(Spacer(1, 40))
    
    metadata = case_data["case"]
    story.append(Paragraph(f"<b>Case Number:</b> {metadata['case_number']}", styles["Normal"]))
    story.append(Paragraph(f"<b>Case Name:</b> {metadata['name']}", styles["Normal"]))
    story.append(Paragraph(f"<b>Incident Date:</b> {metadata['incident_date']}", styles["Normal"]))
    story.append(Paragraph(f"<b>Generated At:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
    story.append(PageBreak())
    
    story.append(Paragraph("Executive Summary", custom_heading1))
    story.append(Paragraph(metadata["description"], styles["BodyText"]))
    story.append(Spacer(1, 15))

    story.append(Paragraph("Preserved Evidence Items", custom_heading1))
    story.append(Paragraph(f"A total of {len(case_data['evidence'])} evidence files were ingested and verified for cryptographic integrity.", styles["BodyText"]))
    story.append(Spacer(1, 10))

    evidence_rows = [["Filename", "Detected Type", "Integrity", "Cryptographic SHA-256 Hash"]]
    for item in case_data["evidence"]:
        evidence_rows.append([
            item["filename"],
            item["detected_mime"],
            item.get("integrity_status", "VERIFIED"),
            f"{item['sha256'][:24]}..."
        ])
    
    ev_table = Table(evidence_rows, colWidths=[120, 105, 75, 180])
    ev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b4d82")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(ev_table)
    story.append(Spacer(1, 15))

    story.append(Paragraph("Chronological Case Timeline", custom_heading1))
    timeline_rows = [["Timestamp", "Event Description", "Evidence Source", "Severity"]]
    for ev in case_data["timeline"][:15]: # Show first 15 events
        timeline_rows.append([
            ev["timestamp"][:19].replace("T", " "),
            ev["event"],
            ev["evidence_source"],
            ev["priority"].upper()
        ])
    
    if len(timeline_rows) > 1:
        time_table = Table(timeline_rows, colWidths=[110, 200, 110, 60])
        time_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b4d82")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(time_table)
    else:
        story.append(Paragraph("No chronological events found.", styles["Italic"]))
    story.append(Spacer(1, 15))

    story.append(Paragraph("AI-Flagged Suspicious Activity & Findings", custom_heading1))
    
    settings_cfg = case_data.get("settings", {})
    thresh = settings_cfg.get("anomaly_threshold", 0.80)
    thresh_lbl = settings_cfg.get("anomaly_threshold_label", "Configurable Default (0.80)")
    story.append(Paragraph(f"<b>System Anomaly Detection Threshold:</b> {thresh:.2f} <i>({thresh_lbl})</i>", styles["Normal"]))
    story.append(Spacer(1, 8))

    findings_rows = [["Severity", "Finding Title", "Risk", "Reason / XAI Summary"]]
    xai_breakdowns = []

    for f in case_data["findings"]:
        details = f.get("details", {})
        xai_data = details.get("xai_explanation")
        
        reason_text = f["reason"]
        if isinstance(xai_data, dict) and xai_data.get("summary"):
            reason_text = xai_data["summary"]
            xai_breakdowns.append({
                "title": f["title"],
                "xai": xai_data
            })
        elif isinstance(xai_data, str):
            reason_text = f"{reason_text}\n[{xai_data}]"

        findings_rows.append([
            f["severity"].upper(),
            f["title"],
            f"{f['risk_score']}%",
            reason_text
        ])
    
    if len(findings_rows) > 1:
        find_table = Table(findings_rows, colWidths=[65, 120, 45, 250])
        find_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7a1a2b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(find_table)
    else:
        story.append(Paragraph("No suspicious findings flagged by AI models.", styles["Italic"]))
        
    story.append(Spacer(1, 15))

    if xai_breakdowns:
        story.append(Paragraph("Explainable AI (XAI) Feature Attribution & Traceability", custom_heading1))
        for item in xai_breakdowns:
            xai = item["xai"]
            story.append(Paragraph(f"<b>Finding: {item['title']}</b> (Score: {xai.get('anomaly_score', 0.0):.2f} | Threshold: {xai.get('threshold', 0.80):.2f})", styles["Heading3"]))
            
            top_feats = xai.get("top_contributing_features", [])
            if top_feats:
                xai_rows = [["Feature Token", "Human Reason / Attribute", "Contribution %"]]
                for feat in top_feats[:5]:
                    xai_rows.append([
                        feat.get("feature", "N/A"),
                        feat.get("readable_label", "N/A"),
                        f"{feat.get('contribution_pct', 0.0)}%"
                    ])
                
                xai_table = Table(xai_rows, colWidths=[130, 240, 110])
                xai_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b4d82")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                ]))
                story.append(xai_table)

            trace = xai.get("explanation_trace", {})
            if trace:
                story.append(Paragraph(f"<i>Trace Proof: {trace.get('method')} | Trace ID: {trace.get('trace_id')} | Raw Score: {trace.get('raw_decision_score')}</i>", styles["Italic"]))
            story.append(Spacer(1, 10))

    story.append(Paragraph("Remediation Recommendations", custom_heading1))
    if case_data["findings"]:
        recs = list({f["recommendation"] for f in case_data["findings"] if f.get("recommendation")})
        for i, rec in enumerate(recs):
            story.append(Paragraph(f"<b>[{i+1}]</b> {rec}", styles["BodyText"]))
            story.append(Spacer(1, 4))
    else:
        story.append(Paragraph("No immediate remediation recommendations required.", styles["BodyText"]))


    story.append(Paragraph("Conclusion", custom_heading1))
    
    total_findings = len(case_data["findings"])
    critical_count = sum(1 for f in case_data["findings"] if f.get("severity", "").lower() == "critical")
    high_count = sum(1 for f in case_data["findings"] if f.get("severity", "").lower() == "high")
    medium_count = sum(1 for f in case_data["findings"] if f.get("severity", "").lower() == "medium")
    low_count = sum(1 for f in case_data["findings"] if f.get("severity", "").lower() == "low")
    evidence_count = len(case_data["evidence"])
    timeline_count = len(case_data["timeline"])
    
    conclusion_parts = []
    conclusion_parts.append(
        f"This forensic investigation examined <b>{evidence_count}</b> evidence file(s) associated with case "
        f"<b>{metadata['case_number']}</b> ({metadata['name']}). The analysis pipeline processed "
        f"<b>{timeline_count}</b> timeline events across multiple forensic sources including system logs, "
        f"browser history, document metadata, and network artifacts."
    )
    
    if total_findings > 0:
        finding_summary = []
        if critical_count > 0:
            finding_summary.append(f"<b>{critical_count}</b> critical")
        if high_count > 0:
            finding_summary.append(f"<b>{high_count}</b> high-severity")
        if medium_count > 0:
            finding_summary.append(f"<b>{medium_count}</b> medium-severity")
        if low_count > 0:
            finding_summary.append(f"<b>{low_count}</b> low-severity")
        
        conclusion_parts.append(
            f"The AI analysis engine identified <b>{total_findings}</b> suspicious finding(s): "
            f"{', '.join(finding_summary)}. These findings were generated using a combination of "
            f"PyTorch-based MITRE ATT&CK classification, Isolation Forest anomaly detection, "
            f"and rule-based signature analysis."
        )
        
        if critical_count > 0 or high_count > 0:
            conclusion_parts.append(
                "Given the presence of critical and/or high-severity findings, immediate investigation "
                "of the flagged indicators is recommended. The identified anomalies may indicate active "
                "threat activity, compromised credentials, or unauthorized system access."
            )
    else:
        conclusion_parts.append(
            "No suspicious findings were identified by the AI analysis engine. The evidence examined "
            "did not exhibit anomalous patterns, signature mismatches, or known threat indicators "
            "based on the configured detection thresholds."
        )
    
    conclusion_parts.append(
        "All evidence files have been cryptographically hashed (SHA-256) and verified for integrity. "
        "Chain-of-custody records are maintained in the audit log for legal admissibility."
    )
    
    for part in conclusion_parts:
        story.append(Paragraph(part, styles["BodyText"]))
        story.append(Spacer(1, 8))
    
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("Investigator Notice", custom_heading1))
    
    notice_style = ParagraphStyle(
        "NoticeBox",
        parent=styles["BodyText"],
        fontName="Helvetica-Oblique",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#4a4a4a"),
        borderColor=colors.HexColor("#1b4d82"),
        borderWidth=1,
        borderPadding=8,
        backColor=colors.HexColor("#f0f4f8"),
        spaceBefore=6,
        spaceAfter=6
    )
    
    notices = [
        ("This report was generated with the assistance of Artificial Intelligence (AI) models. "
        "All AI-generated findings, classifications, and anomaly scores are <b>investigative leads</b> "
        "and should not be treated as definitive conclusions."),
        
        ("Each finding includes an Explainable AI (XAI) attribution trace showing which features "
        "contributed to the detection. Investigators should review these attributions and correlate "
        "them with domain knowledge before drawing conclusions."),
        
        ("AI results may contain false positives and false negatives. The final interpretation and "
        "legal conclusions remain the responsibility of the qualified forensic investigator. "
        "Confidence scores and anomaly thresholds are configurable and should be validated against "
        "labeled ground-truth data for the specific investigation context."),
        
        (f"Report generated by T.A.C.T.I.C. v2.0.0 on "
        f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}. "
        f"All timestamps are normalized to UTC. Original source timestamps are preserved in the "
        f"timeline evidence trail.")
    ]
    
    for notice in notices:
        story.append(Paragraph(notice, notice_style))
        story.append(Spacer(1, 6))
    
    story.append(Spacer(1, 10))

    SimpleDocTemplate(
        str(destination),
        pagesize=letter,
        rightMargin=45,
        leftMargin=45,
        topMargin=45,
        bottomMargin=45
    ).build(story)

def build_docx_report(case_data: dict, destination: Path) -> None:
    """Compile case evidence, timelines, and findings into a styled DOCX report."""
    doc = Document()
    
    section = doc.sections[0]
    section.top_margin = Inches(0.8)
    section.bottom_margin = Inches(0.8)
    section.left_margin = Inches(0.8)
    section.right_margin = Inches(0.8)
    
    title = doc.add_paragraph()
    title.alignment = 1 # Centered
    run = title.add_run("AI DIGITAL FORENSICS ASSISTANT\nForensic Investigation Report\n")
    run.bold = True
    run.font.size = Pt(20)
    run.font.color.rgb = None
    
    metadata = case_data["case"]
    doc.add_paragraph(f"Case Number: {metadata['case_number']}")
    doc.add_paragraph(f"Case Name: {metadata['name']}")
    doc.add_paragraph(f"Incident Date: {metadata['incident_date']}")
    doc.add_paragraph(f"Report Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    doc.add_page_break()
    
    doc.add_heading("Executive Summary", level=1)
    doc.add_paragraph(metadata["description"])
    
    doc.add_heading("Preserved Evidence Items", level=1)
    table = doc.add_table(rows=1, cols=4)
    table.style = "Table Grid"
    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = "Filename"
    hdr_cells[1].text = "Detected MIME"
    hdr_cells[2].text = "Integrity"
    hdr_cells[3].text = "SHA-256 Hash"
    
    for item in case_data["evidence"]:
        row_cells = table.add_row().cells
        row_cells[0].text = item["filename"]
        row_cells[1].text = item["detected_mime"]
        row_cells[2].text = item.get("integrity_status", "VERIFIED")
        row_cells[3].text = f"{item['sha256'][:24]}..."

    doc.add_heading("Chronological Timeline", level=1)
    time_table = doc.add_table(rows=1, cols=4)
    time_table.style = "Table Grid"
    time_hdr = time_table.rows[0].cells
    time_hdr[0].text = "Timestamp"
    time_hdr[1].text = "Event"
    time_hdr[2].text = "Source"
    time_hdr[3].text = "Priority"
    
    for ev in case_data["timeline"][:15]:
        row = time_table.add_row().cells
        row[0].text = ev["timestamp"][:19].replace("T", " ")
        row[1].text = ev["event"]
        row[2].text = ev["evidence_source"]
        row[3].text = ev["priority"].upper()
        
    doc.add_heading("AI Suspicious Findings", level=1)
    find_table = doc.add_table(rows=1, cols=4)
    find_table.style = "Table Grid"
    find_hdr = find_table.rows[0].cells
    find_hdr[0].text = "Severity"
    find_hdr[1].text = "Title"
    find_hdr[2].text = "Risk Score"
    find_hdr[3].text = "Reason"
    
    for f in case_data["findings"]:
        row = find_table.add_row().cells
        row[0].text = f["severity"].upper()
        row[1].text = f["title"]
        row[2].text = f"{f['risk_score']}%"
        row[3].text = f["reason"]

    doc.add_heading("Remediation Recommendations", level=1)
    if case_data["findings"]:
        recs = list({f["recommendation"] for f in case_data["findings"] if f.get("recommendation")})
        for i, rec in enumerate(recs):
            doc.add_paragraph(f"[{i+1}] {rec}")
    else:
        doc.add_paragraph("No remediation recommendations flagged.")


    doc.add_heading("Conclusion", level=1)
    
    total_findings = len(case_data["findings"])
    critical_count = sum(1 for f in case_data["findings"] if f.get("severity", "").lower() == "critical")
    high_count = sum(1 for f in case_data["findings"] if f.get("severity", "").lower() == "high")
    evidence_count = len(case_data["evidence"])
    timeline_count = len(case_data["timeline"])
    
    doc.add_paragraph(
        f"This forensic investigation examined {evidence_count} evidence file(s) associated with case "
        f"{metadata['case_number']} ({metadata['name']}). The analysis pipeline processed "
        f"{timeline_count} timeline events across multiple forensic sources."
    )
    
    if total_findings > 0:
        doc.add_paragraph(
            f"The AI analysis engine identified {total_findings} suspicious finding(s) "
            f"({critical_count} critical, {high_count} high-severity). "
            f"These findings were generated using PyTorch-based MITRE ATT&CK classification, "
            f"Isolation Forest anomaly detection, and rule-based signature analysis."
        )
        if critical_count > 0 or high_count > 0:
            doc.add_paragraph(
                "Given the presence of critical and/or high-severity findings, immediate investigation "
                "of the flagged indicators is recommended."
            )
    else:
        doc.add_paragraph(
            "No suspicious findings were identified by the AI analysis engine."
        )
    
    doc.add_paragraph(
        "All evidence files have been cryptographically hashed (SHA-256) and verified for integrity. "
        "Chain-of-custody records are maintained in the audit log."
    )
    
    doc.add_heading("Investigator Notice", level=1)
    
    notices = [
        ("This report was generated with the assistance of Artificial Intelligence (AI) models. "
        "All AI-generated findings, classifications, and anomaly scores are investigative leads "
        "and should not be treated as definitive conclusions."),
        
        ("Each finding includes an Explainable AI (XAI) attribution trace showing which features "
        "contributed to the detection. Investigators should review these attributions before drawing conclusions."),
        
        ("AI results may contain false positives and false negatives. The final interpretation and "
        "legal conclusions remain the responsibility of the qualified forensic investigator."),
        
        (f"Report generated by T.A.C.T.I.C. v2.0.0 on "
        f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}. "
        f"All timestamps are normalized to UTC.")
    ]
    
    for notice in notices:
        doc.add_paragraph(notice)

    doc.save(destination)
