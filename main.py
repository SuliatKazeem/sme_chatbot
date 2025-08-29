from dotenv import load_dotenv
load_dotenv()

import os
from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import PlainTextResponse, HTMLResponse, FileResponse
from collections import defaultdict
import re

from smeopenai import ask_openai
from virustotal import parse_email, scan_url, scan_domain, scan_file_attachment

app = FastAPI()
INTERNAL_DOMAINS = {
    d.strip() for d in os.getenv("INTERNAL_DOMAINS", "").split(",") if d.strip()
}

EMAIL_REGEX = r'[\w\.-]+@([\w\.-]+)'
URL_REGEX   = r'(https?://[^\s]+|www\.[^\s]+)'

THRESHOLD     = 3
refusal_count = defaultdict(int)

REFUSAL_TAGS     = [
    "sorry",          
    "i'm afraid",     
    "i can only assist",         
    "i cannot",       
]

SCAN_KEYWORDS = [     
    r'\bscan.*email\b',
    r'\bscan.*domain\b',               
]

WARNING_MESSAGE = (
    "⚠️ Warning: You’ve exceeded the allowed number of out-of-scope questions. "
    "The IT team has been notified, and continued misuse may lead to further review. "
    "Please keep your questions focused on SME security topics!"
)

def block_internal(dom: str, session_id: str) -> str | None:
    if dom in INTERNAL_DOMAINS:
        return (
            "For security and privacy reasons, we can’t scan messages from internal domains. "
            "Please contact IT at **techsupport@rxtra.xyz** for help."
        )
    return None

@app.post("/chat", response_class=PlainTextResponse)
async def chat(req: Request):
    data       = await req.json()
    user_input = data.get("query", "")
    session_id = data.get("session_id", "default")

    if any(re.search(pat, user_input, re.IGNORECASE) for pat in SCAN_KEYWORDS):
        return "\n".join([
            "Sure! You can paste it here or click the 📧 **Add Email File** button below "
            "and upload your `.eml` for a full scan.",
            "",
            "**To export an EML file:**",
            "",
            "1. In Gmail’s web interface, open the email.",
            "2. Click ⋮ → **Show original**.",
            "3. On “Original Message,” click **Download Original**.",
            "4. Save the `.eml` to your computer.",
            "5. Come back here, hit **Add Email File**, and select it.",
        ])

    raw_bytes = user_input.encode("utf-8")
    urls, domains, attachments = parse_email(raw_bytes)

    for dom in domains:
        msg = block_internal(dom, session_id)
        if msg:
            return msg
        
    messages = []

    for url in set(re.findall(URL_REGEX, user_input)):
        full_url = url if url.startswith("http") else "http://" + url
        verdict = scan_url(full_url)["verdict"]
        messages.append(f"URL {full_url} → {verdict}.")

    for dom in domains:
        verdict = scan_domain(dom)["verdict"]
        messages.append(f"Domain {dom} → {verdict}.")

    for fname, fbytes in attachments:
        verdict = scan_file_attachment(fname, fbytes)["verdict"]
        messages.append(f"Attachment {fname} → {verdict}.")

    for dom in set(re.findall(EMAIL_REGEX, user_input)):
        msg = block_internal(dom, session_id)
        if msg:
            return msg
        
        if dom not in domains:
            verdict = scan_domain(dom)["verdict"]
            messages.append(f"Domain {dom} → {verdict}.")

    if messages:
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

        messages.append("\n".join(nudge_lines))
        return "\n\n".join(messages)

    llm_reply = ask_openai(user_input, session_id=session_id)
    low = llm_reply.lower()

    if any(phrase in low for phrase in REFUSAL_TAGS):
        refusal_count[session_id] += 1
        if refusal_count[session_id] >= THRESHOLD:
            return WARNING_MESSAGE
        return llm_reply
    
    return llm_reply

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
    for i, line in enumerate(messages, start=1):
        report_lines.append(f"{i}. {line}")

    return "\n\n".join(report_lines)

@app.get("/", response_class=HTMLResponse)
async def home():
    return FileResponse("frontend.html")