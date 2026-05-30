from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime
import uuid
import os

def generate_incident_pdf(report_data: dict) -> str:
    incident_id = report_data.get("incident_id", "UNKNOWN")
    filename = f"incident_{incident_id}.pdf"
    filepath = os.path.join("reports", filename)
    os.makedirs("reports", exist_ok=True)

    doc = SimpleDocTemplate(filepath, pagesize=A4)
    styles = getSampleStyleSheet()

    content = [
        Paragraph("<b>Security Incident Report</b>", styles["Title"]),
        Paragraph(f"<b>Incident ID:</b> {incident_id}", styles["Normal"]),
        Paragraph(f"<b>Date:</b> {datetime.utcnow().isoformat()}", styles["Normal"]),
        Paragraph(f"<b>Report Type:</b> {report_data['report_type']}", styles["Normal"]),
        Paragraph(f"<b>Summary:</b> {report_data['summary']}", styles["Normal"]),
        Paragraph(f"<b>Severity:</b> {report_data['severity']}", styles["Normal"]),
        Paragraph("<b>Description:</b>", styles["Heading2"]),
    ]

    for i in report_data.get("indicators", []):
        content.append(Paragraph(f"- {i}", styles["Normal"]))

    doc.build(content)
    return filepath, incident_id
