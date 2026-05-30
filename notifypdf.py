import logging
import csv
import os
from datetime import datetime

os.makedirs("reports", exist_ok=True)

LOG_FILE = "virustotal_incident.log"
CSV_FILE = "virustotal_incident.csv"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.WARNING,
    format="%(asctime)s - %(message)s"
)

def notify_cybersecurity(meta: dict):
    logging.warning(
        f"INCIDENT {meta['incident_id']} | "
        f"type={meta['report_type']} | "
        f"severity={meta['severity']} | "
        f"indicators={meta.get('indicators', [])}"
    )

    file_exists = os.path.isfile(CSV_FILE)
    with open(CSV_FILE, mode='a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "incident_id", "report_type", "severity", "indicators"])
        if not file_exists:
            writer.writeheader()
        writer.writerow({
            "timestamp": datetime.utcnow().isoformat(),
            "incident_id": meta["incident_id"],
            "report_type": meta["report_type"],
            "severity": meta["severity"],
            "indicators": ", ".join(meta.get("indicators", []))
        })
