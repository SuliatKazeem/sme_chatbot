import os
from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import PlainTextResponse, HTMLResponse, FileResponse
import re

from smeopenai import ask_openai
from virustotal import parse_email, scan_url, scan_domain, scan_file_attachment

INTERNAL_DOMAINS = set(
    os.getenv("INTERNAL_DOMAINS", "")
       .split(",")
)

app = FastAPI()

# Regex to pull out domains from pasted email addresses
EMAIL_REGEX = r'[\w\.-]+@([\w\.-]+)'

@app.post("/chat", response_class=PlainTextResponse)
async def chat(req: Request):
    data       = await req.json()
    user_input = data.get("query", "")
    session_id = data.get("session_id", "default")

    if re.search(r'\bscan an email\b', user_input, re.IGNORECASE):
        lines = [
        "Sure! Please click the 📧 **Add Email File** button below and upload your `.eml` file for a full comprehensive scan.",
        "",
        "**How to export an EML file:**",
        "",
        "1. Open the email in Gmail’s web interface.",
        "2. Click the three-dot menu `⋮` in the top-right corner, then select **Show original**.",
        "3. On the “Original Message” page, click **Download Original**.",
        "4. Save the resulting `.eml` file to your computer.",
        "5. Return here and click **Add Email File**, then select your saved `.eml` file.",
    ]
    # Join into one string with blank lines preserved
        return "\n".join(lines)

    # 1) Try full MIME parse (for pasted raw .eml or inline URLs/HTML)
    raw_bytes = user_input.encode("utf-8")
    urls, domains, attachments = parse_email(raw_bytes)

    for dom in domains:
        if dom in INTERNAL_DOMAINS:
            return "For security and privacy reasons, internal-domain messages cannot be scanned. Please reach out to our IT support team at techsupport@rxtra.xyz for assistance."
        
    messages = []
    # Scan each URL
    for url in urls:
        verdict = scan_url(url)["verdict"]
        messages.append(f"URL {url} → {verdict}.")

    # Scan each domain
    for dom in domains:
        verdict = scan_domain(dom)["verdict"]
        messages.append(f"Domain {dom} → {verdict}.")

    # Scan any attachments
    for fname, fbytes in attachments:
        verdict = scan_file_attachment(fname, fbytes)["verdict"]
        messages.append(f"Attachment {fname} → {verdict}.")

    # 2) Quick‐and‐dirty: catch any user@domain pasted, scan that domain too
    for dom in set(re.findall(EMAIL_REGEX, user_input)):
        if dom in INTERNAL_DOMAINS:
            return "For security and privacy reasons, internal-domain messages cannot be scanned. Please reach out to our IT support team at techsupport@rxtra.xyz for assistance."
        
        if dom not in domains:
            verdict = scan_domain(dom)["verdict"]
            messages.append(f"Domain {dom} → {verdict}.")

    if messages:
    # Build a Markdown‐friendly nudge with paragraphs and a numbered list
        nudge_lines = [
        "For maximum security, please upload the original `.eml` file. This ensures all hidden links, email headers, and attachments are fully inspected. Click the 📧 Add Email File button below to get started."
        "",
        "",
        "**How to export an EML file:**",
        "",
        "1. Open the email in Gmail’s web interface.",
        "2. Click the three-dot menu `⋮` in the top-right corner, then select **Show original**.",
        "3. On the “Original Message” page, click **Download Original**.",
        "4. Save the resulting `.eml` file.",
        "5. Return here and click **Add Email File**, and select your saved `.eml` file.",
    ]
    # Join with single newlines (which `marked.parse` will turn into <p> and <li>)
        messages.append("\n".join(nudge_lines))

    # Finally join all your messages with two line breaks for good spacing
        return "\n\n".join(messages)

    # 4) Nothing found? Fall back to your LLM
    try:
        return ask_openai(user_input, session_id=session_id)
    except Exception as e:
        # log to console for debugging
        print("ask_openai error:", e)
        return "Sorry, something went wrong. Please try again or use the Add Email File button to scan an email."


@app.post("/scan-email-file", response_class=PlainTextResponse)
async def scan_email_file(email_file: UploadFile = File(...)):

    raw_bytes = await email_file.read()
    urls, domains, attachments = parse_email(raw_bytes)

    for dom in domains:
        if dom in INTERNAL_DOMAINS:
            return "For security and privacy reasons, internal-domain messages cannot be scanned. Please reach out to our IT support team at techsupport@rxtra.xyz for assistance."
        
    messages = []
    for url in urls:
        v = scan_url(url)["verdict"]
        messages.append(f"URL {url} → {v}.")
    for dom in domains:
        v = scan_domain(dom)["verdict"]
        messages.append(f"Domain {dom} → {v}.")
    for fn, fb in attachments:
        v = scan_file_attachment(fn, fb)["verdict"]
        messages.append(f"Attachment {fn} → {v}.")

    if not messages:
        return "No URLs, domains, or attachments found in that .eml."

    report_lines = ["For this email, the scan results are:"]
    for idx, line in enumerate(messages, start=1):
        report_lines.append(f"{idx}. {line}")

    return "\n\n".join(report_lines)

@app.get("/", response_class=HTMLResponse)
async def home():
    return FileResponse("frontend.html")