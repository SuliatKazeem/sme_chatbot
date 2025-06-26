# virustotal.py

import os
import re
import requests
import email
from email import policy
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
headers = {"x-apikey": VT_API_KEY}

# Optional HTML parsing
try:
    from bs4 import BeautifulSoup
    HAVE_BS4 = True
except ImportError:
    HAVE_BS4 = False

def scan_domain(domain):
    resp = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers)
    if resp.status_code != 200:
        return {"verdict": f"Error: {resp.text}"}
    stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {"verdict": "Likely Malicious" if stats.get("malicious",0)>0 else "Looks Safe"}

def scan_url(url):
    data = {"url": url}
    resp = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
    if resp.status_code != 200:
        return {"verdict": f"Error: {resp.text}"}
    scan_id = resp.json()["data"]["id"]
    analysis = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers)
    if analysis.status_code != 200:
        return {"verdict": f"Error: {analysis.text}"}
    stats = analysis.json().get("data", {}).get("attributes", {}).get("stats", {})
    return {"verdict": "Likely Phishing" if stats.get("malicious",0)>0 else "Looks Safe"}

def scan_file_attachment(filename, file_bytes):
    files = {"file": (filename, file_bytes)}
    resp = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)
    if resp.status_code != 200:
        return {"verdict": f"Error: {resp.text}"}
    analysis_id = resp.json()["data"]["id"]
    analysis = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
    if analysis.status_code != 200:
        return {"verdict": f"Error: {analysis.text}"}
    stats = analysis.json().get("data", {}).get("attributes", {}).get("stats", {})
    return {"verdict": "Likely Malicious File" if stats.get("malicious",0)>0 else "File Seems Safe"}

def extract_urls(text):
    pattern = r'https?://[^\s"\']+'
    return set(re.findall(pattern, text))

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

    # 1) Gather all URLs from plain text
    email_text = "\n".join(text_parts)
    urls = set(extract_urls(email_text))

    # 2) If HTML and bs4 available, grab all anchor hrefs
    if HAVE_BS4:
        for html in html_parts:
            soup = BeautifulSoup(html, "html.parser")
            for a in soup.find_all("a", href=True):
                urls.add(a["href"])
    else:
        for html in html_parts:
            urls.update(extract_urls(html))

    # Deduplicate domains
    domains = {urlparse(u).netloc for u in urls}

    # Gather attachments
    attachments = []
    for part in msg.iter_attachments():
        fn = part.get_filename()
        if fn:
            attachments.append((fn, part.get_payload(decode=True)))

    return list(urls), list(domains), attachments