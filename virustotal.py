import requests
import os
import re
import email
from email import policy
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

headers = {
    "x-apikey": VT_API_KEY
}

def scan_domain(domain):
    response = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers)

    if response.status_code != 200:
        return {"error": response.text}

    stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "verdict": "Likely Malicious" if stats.get("malicious", 0) > 0 else "Looks Safe"
    }

def scan_url(url):
    data = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)

    if response.status_code != 200:
        return {"error": response.text}
    
    scan_id = response.json()["data"]["id"]
    analysis = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers)

    if analysis.status_code != 200:
        return {"error": analysis.text}

    stats = analysis.json().get("data", {}).get("attributes", {}).get("stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "verdict": "Likely Phishing" if stats.get("malicious", 0) > 0 else "Looks Safe"
    }

def scan_file_attachment(filename, file_bytes):
    files = {
        'file': (filename, file_bytes)
    }
    response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)
    if response.status_code != 200:
        return {"error": response.text}
    analysis_id = response.json()["data"]["id"]
    analysis_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
    if analysis_response.status_code != 200:
        return {"error": analysis_response.text}
    stats = analysis_response.json().get("data", {}).get("attributes", {}).get("stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "verdict": " Likely Malicious File" if stats.get("malicious", 0) > 0 else "File Seems Safe"
    }

def friendly_domain_report(domain, scan_result):
    verdict = scan_result.get("verdict", "")
    if "Likely Malicious" in verdict:
        message = (
            f"The domain '{domain}' has been flagged by security tools multiple times. "
            "It looks suspicious and might be harmful. "
            "I recommend that you avoid clicking any links or downloading files from this domain."
        )
    else:
        message = (
            f"Secure! The domain '{domain}' appears safe based on current security checks. "
            "However, always be cautious."
        )
    return message

def extract_urls(text):
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, text)

def extract_domains(urls):
    domains = set()
    for url in urls:
        parsed_url = urlparse(url)
        domains.add(parsed_url.netloc)
    return list(domains)

def parse_email(raw_email_bytes):
    msg = email.message_from_bytes(raw_email_bytes, policy=policy.default)
    
    email_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                email_text += part.get_content()
    else:
        email_text = msg.get_content()

    urls = extract_urls(email_text)
    domains = extract_domains(urls)

    attachments = []
    for part in msg.iter_attachments():
        filename = part.get_filename()
        if filename:
            payload = part.get_payload(decode=True)
            attachments.append((filename, payload))
    
    return urls, domains, attachments

def process_email(raw_email_bytes):
    urls, domains, attachments = parse_email(raw_email_bytes)

    url_reports = {}
    for url in urls:
        url_reports[url] = scan_url(url)

    domain_reports = {}
    for domain in domains:
        domain_reports[domain] = scan_domain(domain)

    attachment_reports = {}
    for filename, file_bytes in attachments:
        attachment_reports[filename] = scan_file_attachment(filename, file_bytes)

    return {
        "urls": url_reports,
        "domains": domain_reports,
        "attachments": attachment_reports
    }