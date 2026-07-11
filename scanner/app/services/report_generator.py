from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet

from app.models.scan import Scan
from app.models.asset import Asset
from app.models.finding import Finding
from app.core.risk_engine import calculate_risk


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


    risk = calculate_risk(findings)


    doc = SimpleDocTemplate(
        filename,
        pagesize=letter
    )


    styles = getSampleStyleSheet()

    content = []


    # Title
    content.append(
        Paragraph(
            "Advanced Web Application Vulnerability Scanner Report",
            styles["Title"]
        )
    )

    content.append(Spacer(1, 20))


    # Executive Summary

    content.append(
        Paragraph(
            "Executive Summary",
            styles["Heading2"]
        )
    )


    summary_data = [
        ["Target", scan.target],
        ["Status", scan.status],
        ["Risk Score", str(risk["score"])],
        ["Risk Level", risk["level"]],
        ["Total Assets", str(len(assets))],
        ["Total Findings", str(len(findings))]
    ]


    table = Table(summary_data)

    table.setStyle(
        TableStyle([
            ("GRID", (0,0), (-1,-1), 0.5, None)
        ])
    )

    content.append(table)

    content.append(Spacer(1, 20))


    # Findings

    content.append(
        Paragraph(
            "Vulnerability Findings",
            styles["Heading2"]
        )
    )


    if not findings:

        content.append(
            Paragraph(
                "No vulnerabilities detected.",
                styles["Normal"]
            )
        )

    else:

        for index, finding in enumerate(findings, start=1):

            content.append(
                Paragraph(
                    f"{index}. {finding.vulnerability_name}",
                    styles["Heading3"]
                )
            )


            details = f"""
            <b>Module:</b> {finding.module}<br/>
            <b>Severity:</b> {finding.severity}<br/>
            <b>Endpoint:</b> {finding.endpoint}<br/>
            <b>Evidence:</b> {finding.evidence}<br/>
            <b>Recommendation:</b> {finding.recommendation}
            """

            content.append(
                Paragraph(
                    details,
                    styles["Normal"]
                )
            )

            content.append(
                Spacer(1, 15)
            )


    doc.build(content)