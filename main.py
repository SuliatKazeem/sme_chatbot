from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse, PlainTextResponse
import re

from smeopenai import ask_openai
from virustotal import scan_url, scan_domain, friendly_domain_report

app = FastAPI()

URL_REGEX    = r'(https?://[^\s]+)'
EMAIL_REGEX  = r'[\w\.-]+@([\w\.-]+)'
DOMAIN_REGEX = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'

@app.post("/chat", response_class=PlainTextResponse)
async def chat(req: Request):
    data       = await req.json()
    user_input = data.get("query", "")
    session_id = data.get("session_id", "default")

    print(f"User input: {user_input} | Session: {session_id}")

    urls    = re.findall(URL_REGEX, user_input)
    emails  = re.findall(EMAIL_REGEX, user_input)
    domains = re.findall(DOMAIN_REGEX, user_input)
    messages = []

    for url in urls:
        scan_result = scan_url(url)
        messages.append(f"Scan result for URL '{url}': {scan_result.get('verdict', 'No verdict')}.")

    for email in emails:
        domain = email.split('@')[-1]
        scan_result = scan_domain(domain)
        messages.append(friendly_domain_report(domain, scan_result))

    scanned = set( emails + [ re.sub(r'^https?://', '', u).split('/')[0] for u in urls ] )
    for domain in domains:
        if domain in scanned:
            continue
        scan_result = scan_domain(domain)
        messages.append(f"Scan result for domain '{domain}': {scan_result.get('verdict', 'No verdict')}.")

    if messages:
        final = "\n".join(messages)
        print(f"VirusTotal results:\n{final}")
        return final

    reply = ask_openai(user_input, session_id=session_id)
    print(f"OpenAI reply: {reply}")
    return reply

@app.get("/", response_class=HTMLResponse)
async def home():
    return FileResponse("frontend.html")
