import os
import csv
import io
from datetime import datetime
from azure.storage.blob import BlobServiceClient

# Azure CSV storage location.
CONTAINER_NAME = "smeincidents"
BLOB_NAME = "Logs/virustotal_incident.csv"

# Record VirusTotal incidents in Azure.
def notify_cybersecurity(meta: dict):
    try:
        connection_string = os.getenv("AZURE_STORAGE_CONNECTION_STRING")

        if not connection_string:
            print("Azure Storage connection string missing.")
            return

# Connect to Azure Blob Storage.
        blob_service_client = BlobServiceClient.from_connection_string(
            connection_string
        )

        blob_client = blob_service_client.get_blob_client(
            container=CONTAINER_NAME,
            blob=BLOB_NAME
        )

        # Create the append blob the first time only
        if not blob_client.exists():
            blob_client.create_append_blob()

            header = (
                "timestamp,incident_id,report_type,severity,indicators\n"
            )

            blob_client.append_block(
                header.encode("utf-8")
            )

        # Create a new CSV row.
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow([
            datetime.utcnow().isoformat(),
            meta["incident_id"],
            meta["report_type"],
            meta["severity"],
            ", ".join(meta.get("indicators", []))
        ])

        csv_row = output.getvalue()

        # Add the incident
        blob_client.append_block(
            csv_row.encode("utf-8")
        )

        print(
            "VirusTotal incident appended to Azure CSV:",
            meta["incident_id"]
        )

    except Exception as e:
        print("AZURE CSV ERROR:", str(e))