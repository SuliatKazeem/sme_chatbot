# This file is for the scanning of URLs, domains, and uploaded email files.
import os
import re
import requests
import email
import time
from email import policy
from urllib.parse import urlparse
from dotenv import load_dotenv
from bs4 import BeautifulSoup

# Load the VirusTotal API key.
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
headers = {"x-apikey": VT_API_KEY}

# Scan a domain with VirusTotal.
def scan_domain(domain):
    resp = requests.get(
    f"https://www.virustotal.com/api/v3/domains/{domain}",
    headers=headers,
    timeout=15
    )

    if resp.status_code == 404:
        return {"verdict": "Not found on VirusTotal. Treat as suspicious and verify manually"}

    if resp.status_code != 200:
        return {"verdict": "Unable to verify with VirusTotal. Treat as suspicious and verify manually"}
    
    stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious > 0:
        return {"verdict": "Likely Malicious"}

    if suspicious > 0:
        return {"verdict": "Suspicious"}

    return {"verdict": "Looks Safe"}

# Scan a URL with VirusTotal.
def scan_url(url):
    data = {"url": url}

    resp = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data=data,
        timeout=15
    )

    if resp.status_code == 404:
        return {"verdict": "Not found on VirusTotal. Treat as suspicious and verify manually"}

    if resp.status_code != 200:
        return {"verdict": "Unable to verify with VirusTotal. Treat as suspicious and verify manually"}

    scan_id = resp.json()["data"]["id"]

# Wait for VirusTotal to complete the analysis.
    for _ in range(10):

        analysis = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
            headers=headers,
            timeout=15
        )

        if analysis.status_code == 404:
            return {"verdict": "Not found on VirusTotal. Treat as suspicious and verify manually"}

        if analysis.status_code != 200:
            return {"verdict": "Unable to verify with VirusTotal. Treat as suspicious and verify manually"}

        attributes = (
            analysis.json()
            .get("data", {})
            .get("attributes", {})
        )

        status = attributes.get("status")

        if status == "completed":
            stats = attributes.get("stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0:
                return {"verdict": "Likely Malicious"}

            if suspicious > 0:
                return {"verdict": "Suspicious"}

            return {"verdict": "Looks Safe"}

        time.sleep(2)

    return {"verdict": "Unable to verify with VirusTotal. Treat as suspicious and verify manually"}

# Scan .EML file uploaded with VirusTotal.
def scan_file_attachment(filename, file_bytes):
    files = {"file": (filename, file_bytes)}

    resp = requests.post(
        "https://www.virustotal.com/api/v3/files",
        headers=headers,
        files=files,
        timeout=15
    )

    if resp.status_code != 200:
        return {"verdict": "Unable to verify with VirusTotal. Treat as suspicious and verify manually"}

    analysis_id = resp.json()["data"]["id"]

# Wait for VirusTotal to complete the analysis.
    for _ in range(10):

        analysis = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=15
        )

        if analysis.status_code != 200:
            return {"verdict": "Unable to verify with VirusTotal. Treat as suspicious and verify manually"}

        attributes = (
            analysis.json()
            .get("data", {})
            .get("attributes", {})
        )

        status = attributes.get("status")

        if status == "completed":
            stats = attributes.get("stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            if malicious > 0:
                return {"verdict": "Likely Malicious File"}

            if suspicious > 0:
                return {"verdict": "Suspicious"}

            return {"verdict": "File Seems Safe"}

        time.sleep(2)

    return {"verdict": "Unable to verify with VirusTotal. Treat as suspicious and verify manually"}

# Extract URLs from email text.
def extract_urls(text):
    pattern = r'https?://[^\s"\']+'
    return set(re.findall(pattern, text))

# Extract URLs, domains and attachments from an email.
def parse_email(raw_email_bytes):
    msg = email.message_from_bytes(raw_email_bytes, policy=policy.default)

    text_parts = []
    html_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()

            if ctype == "text/plain":
                text_parts.append(part.get_content())
            elif ctype == "text/html":
                html_parts.append(part.get_content())
    else:
        if msg.get_content_type() == "text/plain":
            text_parts.append(msg.get_content())
        elif msg.get_content_type() == "text/html":
            html_parts.append(msg.get_content())

    email_text = "\n".join(text_parts)
    urls = set(extract_urls(email_text))

    # Extract links from HTML content.
    for html in html_parts:
        soup = BeautifulSoup(html, "html.parser")

        for a in soup.find_all("a", href=True):
            urls.add(a["href"])

    domains = {urlparse(u).netloc for u in urls}
    attachments = []

    # Extract email attachments.
    for part in msg.iter_attachments():
        fn = part.get_filename()
        
        if fn:
            attachments.append((fn, part.get_payload(decode=True)))

    return list(urls), list(domains), attachments