from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from app.models.scan import Scan
from app.models.asset import Asset
from app.models.finding import Finding
from app.core.risk_engine import calculate_risk, SEVERITY_SCORE


# Colors per severity / risk level, reused for both the risk banner and
# the small severity tag next to each finding.
SEVERITY_HEX = {
    "critical": "B0182C",
    "high":     "C6540F",
    "medium":   "B4790A",
    "low":      "1D7FBF",
    "info":     "5B6472",
    "none":     "0E9F87",
}

SEVERITY_COLORS = {
    key: colors.HexColor(f"#{hex_val}") for key, hex_val in SEVERITY_HEX.items()
}


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#8792A6"))
    canvas.drawString(0.75 * inch, 0.5 * inch, "VulnScan — Automated Vulnerability Report")
    canvas.drawRightString(letter[0] - 0.75 * inch, 0.5 * inch, f"Page {doc.page}")
    canvas.restoreState()


def generate_pdf_report(scan_id: int, db, filename: str):

    scan = db.query(Scan).filter(
        Scan.id == scan_id
    ).first()

    if not scan:
        raise Exception("Scan not found")

    assets = db.query(Asset).filter(
        Asset.scan_id == scan_id
    ).all()

    findings = db.query(Finding).filter(
        Finding.scan_id == scan_id
    ).all()

    # Worst-first ordering, unknown severities sink to the bottom
    findings = sorted(
        findings,
        key=lambda f: SEVERITY_SCORE.get(f.severity.lower(), 0),
        reverse=True
    )

    risk = calculate_risk(findings)
    risk_color = SEVERITY_COLORS.get(risk["level"].lower(), colors.HexColor("#5B6472"))

    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle", parent=styles["Title"], fontSize=20, spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle", parent=styles["Normal"], textColor=colors.HexColor("#5B6472")
    )
    section_style = ParagraphStyle(
        "SectionHeading", parent=styles["Heading2"], spaceBefore=18, spaceAfter=8
    )
    finding_title_style = ParagraphStyle(
        "FindingTitle", parent=styles["Heading3"], spaceBefore=14, spaceAfter=2
    )
    body_style = ParagraphStyle(
        "FindingBody", parent=styles["Normal"], leading=15
    )
    mono_style = ParagraphStyle(
        "Mono", parent=styles["Normal"], fontName="Courier", fontSize=8.5,
        leading=12, backColor=colors.HexColor("#F5F7FB"),
        borderColor=colors.HexColor("#E3E8F1"), borderWidth=0.5,
        borderPadding=6
    )

    content = []

    # ---------- Title ----------
    content.append(Paragraph("Vulnerability Scan Report", title_style))
    content.append(Paragraph(
        f"Generated {datetime.now().strftime('%B %d, %Y at %H:%M')}",
        subtitle_style
    ))
    content.append(Spacer(1, 20))

    # ---------- Risk banner ----------
    risk_table = Table(
        [[
            Paragraph(f"<b>Risk score: {risk['score']}</b>", body_style),
            Paragraph(f"<b>Risk level: {risk['level']}</b>", body_style),
        ]],
        colWidths=[3 * inch, 3 * inch]
    )
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.Color(
            risk_color.red, risk_color.green, risk_color.blue, alpha=0.12
        )),
        ("BOX", (0, 0), (-1, -1), 1, risk_color),
        ("TEXTCOLOR", (0, 0), (-1, -1), risk_color),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
    ]))
    content.append(risk_table)
    content.append(Spacer(1, 20))

    # ---------- Executive Summary ----------
    content.append(Paragraph("Executive Summary", section_style))

    summary_data = [
        ["Target", scan.target],
        ["Scan ID", str(scan.id)],
        ["Status", scan.status],
        ["Total Assets", str(len(assets))],
        ["Total Findings", str(len(findings))],
    ]

    for sev in ["critical", "high", "medium", "low", "info"]:
        count = risk["counts"].get(sev, 0)
        if count:
            summary_data.append([sev.capitalize(), str(count)])

    summary_table = Table(summary_data, colWidths=[2 * inch, 3.5 * inch])
    summary_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E3E8F1")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    content.append(summary_table)

    # ---------- Findings ----------
    content.append(Paragraph("Vulnerability Findings", section_style))

    if not findings:
        content.append(Paragraph("No vulnerabilities detected.", body_style))
    else:
        for index, finding in enumerate(findings, start=1):
            sev_key = finding.severity.lower()
            sev_hex = SEVERITY_HEX.get(sev_key, "5B6472")

            content.append(Paragraph(
                f'{index}. {finding.vulnerability_name} '
                f'<font color="#{sev_hex}"><b>[{finding.severity.upper()}]</b></font>',
                finding_title_style
            ))

            details = (
                f"<b>Module:</b> {finding.module}<br/>"
                f"<b>Endpoint:</b> {finding.endpoint}<br/>"
                f"<b>Recommendation:</b> {finding.recommendation}"
            )
            content.append(Paragraph(details, body_style))
            content.append(Spacer(1, 4))
            content.append(Paragraph(f"<b>Evidence:</b><br/>{finding.evidence}", mono_style))
            content.append(Spacer(1, 12))

    # ---------- Assets ----------
    content.append(PageBreak())
    content.append(Paragraph("Assets Discovered", section_style))

    if not assets:
        content.append(Paragraph("No assets found.", body_style))
    else:
        asset_data = [["URL", "Method", "Parameters"]]
        for asset in assets:
            asset_data.append([
                Paragraph(asset.url, mono_style),
                asset.method,
                asset.parameters or "—",
            ])

        asset_table = Table(asset_data, colWidths=[3.2 * inch, 0.9 * inch, 1.9 * inch])
        asset_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E3E8F1")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F5F7FB")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        content.append(asset_table)

    doc.build(content, onFirstPage=_footer, onLaterPages=_footer)