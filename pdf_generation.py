from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime
import uuid
import os

# Generate a PDF report for an incident.
def generate_incident_pdf(report_data: dict) -> str:
    incident_id = report_data.get("incident_id", f"INC{uuid.uuid4().hex[:8]}")
    filename = f"incident_{incident_id}.pdf"
    filepath = os.path.join("reports", filename)
    os.makedirs("reports", exist_ok=True)

    doc = SimpleDocTemplate(filepath, pagesize=A4)
    styles = getSampleStyleSheet()

     # Add incident details.
    content = [
        Paragraph("<b>Security Incident Report</b>", styles["Title"]),
        Paragraph(f"<b>Incident ID:</b> {incident_id}", styles["Normal"]),
        Paragraph(f"<b>Date:</b> {datetime.utcnow().isoformat()}", styles["Normal"]),
        Paragraph(f"<b>Summary:</b> {report_data.get('summary', '')}", styles["Normal"]),
    ]

    if report_data.get("conversation"):
        content.append(Paragraph("<b>Conversation:</b>", styles["Heading2"]))
        for line in report_data["conversation"].split("\n"):
            content.append(Paragraph(line, styles["Normal"]))

    elif report_data.get("details"):
        content.append(Paragraph("<b>Details:</b>", styles["Heading2"]))
        content.append(Paragraph(report_data["details"], styles["Normal"]))

    # Create PDF.
    doc.build(content)
    return filepath, incident_id
