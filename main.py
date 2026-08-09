# Load environment variables from the .env file.
# This is where API keys are stored locally so they are not hardcoded in the code.
from dotenv import load_dotenv
load_dotenv()  

import os
import re

from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import PlainTextResponse, HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from datetime import datetime
from collections import defaultdict


from smeopenai import ask_openai, classify_group
from virustotal import parse_email, scan_url, scan_domain, scan_file_attachment
from incident_report import generate_incident_pdf
from notifypdf import notify_cybersecurity
from azure.storage.blob import BlobServiceClient

import uuid
import json

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

INTERNAL_DOMAINS = {
    d.strip() for d in os.getenv("INTERNAL_DOMAINS", "").split(",") if d.strip()
}

# detect emails and URLs inside messages sent 
EMAIL_REGEX = r'[\w\.-]+@([\w\.-]+\.\w+)'
URL_REGEX   = r'(https?://[^\s]+|www\.[^\s]+)'
DOMAIN_PATTERN = r'^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$'

PI_PATTERNS = {
    "NI_NUMBER": r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b",
    "UK_PHONE": r"\b(?:\+44|0)\d{10,11}\b",
    "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
    "PASSPORT_LIKE_ID": r"\b[A-Z]{1,2}\d{6,9}\b"
}

THRESHOLD     = 3 # threshold for out-of-scope questions, warning after 3rd time
FOLLOWUPQUESTIONS = 2  # 2 follow-up questions before asking if the user wants an incident created.

refusal_count = defaultdict(int)

# Store chat history temporarily
chat_sessions = defaultdict(list)

triage_state = {}
response_cache = {}

# For the bot to detect out-of-scope questions, common phrases in replies
REFUSAL_TAGS = [ 
    "outside my scope",
    "cannot help with that request",
    "not able to help with that",
    "i can only assist",
    "i can only help",
    "I'm sorry",
    "i can't",
    "I'm here to focus"
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

# blocking internal domains from being scanned at all - cybersecurity solution
def block_internal(dom: str, session_id: str) -> str | None:
    if dom in INTERNAL_DOMAINS:
        return (
            "For security and privacy reasons, we can’t scan messages from internal domains. "
            "Please contact IT at **techsupport@rxtra.xyz** for help."
        )
    return None

# Save incidents to Azure Blob Storage
def save_incident(incident: dict):
    upload_incident_to_blob(incident)

#The function to stop the bot from creating incidents for normal advice questions. Used prompt engineering to help bot decide real issues
def classify_incident(text: str, session_id: str):
    prompt = f"""

                You are an IT/security incident classifier.

                Decide if this user message is asking for help with an issue that may need an incident ticket.

                Return TRUE only if:
                - User reports a problem
                - User cannot perform work
                - User reports suspicious activity
                - User reports a system failure
                - User reports an error
                - User reports something not working

                Return FALSE for:
                - Advice requests
                - How-to questions
                - General security questions
                - Policy questions
                - Requests for information
                - Training or educational questions

                Return ONLY valid JSON:

                {{
                    "create_incident": true
                }}

                or

                {{
                    "create_incident": false
                }}

                Message:
                {text}
                """
    
    return ask_openai(prompt, session_id)

#decides the groups based on user's input
def get_department_from_group(group: str):
    cybersecurity_groups = ["email_security", "security_incidents", "data_protection", "general_security"]
        
    if group in cybersecurity_groups:
        return "Cybersecurity"
    
    return "IT"

#the bot will generate a followup question based on user input. Focuses on missing informations.
def generate_next_question(group: str, answers: list, user_input: str, session_id: str):
        prompt = f"""
    You are an IT security incident triage assistant.

    Group: {group}

    User issue:
    {user_input}

    Conversation so far:
    {answers}

    Task:
    Ask EXACTLY ONE follow-up question to gather missing diagnostic information needed for incident creation.

    Rules:
    - Ask only ONE question
    - Keep it short and natural
    - Focus on missing information only
    """
        return ask_openai(prompt, session_id)

# Save the incident to Azure Blob Storage, create a PDF report, and give user a download link.
def create_incident_from_triage(session_id: str, state: dict):
    group = state["group"]
    department = get_department_from_group(group)

    incident = {
    "id": f"INC{uuid.uuid4().hex[:8]}",
    "summary": generate_incident_title(state["conversation"], session_id),
    "conversation": redact_pi("\n".join(state["conversation"])),
    "department": department,
    "status": "open",
    "created_at": datetime.utcnow().isoformat()
}

    save_incident(incident)

    pdf_path, incident_id = generate_incident_pdf({
        "incident_id": incident["id"],
        "summary": incident["summary"],
        "details": state["answers"][-1]
    })
    
    filename = os.path.basename(pdf_path)

    triage_state.pop(session_id, None)

    return (
        f"Your incident has been successfully created and sent to the "
        f"{incident['department']} department.\n\n"
        f"- **ID**: {incident['id']}\n\n"
        f"- **Status**: {incident['status']}\n\n"
        f"- **Summary**: {incident['summary']}\n\n"
        f"The team will contact you soon to provide support and assistance.\n\n"
        f"In the meantime, you can download the PDF for your incident [here](/download/{filename})."
    )

# gives short helpful advice first, then asks one follow-up question
def generate_triage_response(group, answers, user_input, session_id):
    prompt = f"""
You are an IT and cybersecurity assistant.

Issue:
{answers[0]}

Answers so far:
{answers}

Task:

1. Give a short helpful recommendation according to company policy (2-4 sentences).
2. Then ask EXACTLY ONE follow-up question.

Rules:
- Keep advice practical.
- Do not provide a complete solution.
- Do not repeat same recommendation.
- Do not mention incident creation.
- Do not suggest they contact department.
- Ask only one question.
- Do not suggest to give contact information unless asked.
- Maximum 100 words.
"""
    return ask_openai(prompt, session_id)

def generate_final_details_question(group: str, answers: list, session_id: str):
    prompt = f"""
You are an IT and cybersecurity incident triage assistant.

Incident category:
{group}

Information collected so far:
{answers}

Task:
Ask the user for more useful details about the incident before creating the incident.

Rules:
- Do not use a generic template.
- Ask for details relevant to the incident category.
- Do not ask for information already provided.
- Keep it short and natural.
- Mention examples only if they fit the incident.
- Do not ask more than one question.
- Do not mention error messages unless the issue is a system or login problem.
"""
    return ask_openai(prompt, session_id)

def generate_incident_title(answers: list, session_id: str):
    prompt = f"""
Create a short incident title from this triage conversation.

Rules:
- Maximum 8 words
- Clear and professional
- Do not include quotation marks
- Return only the title

Conversation:
{answers}
"""
    return ask_openai(prompt, session_id)

def redact_pi(text: str) -> str:
    if not text:
        return text

    redacted = text

    for label, pattern in PI_PATTERNS.items():
        redacted = re.sub(
            pattern,
            f"[REDACTED_{label}]",
            redacted,
            flags=re.IGNORECASE
        )

    return redacted

def upload_incident_to_blob(incident: dict):
    try:
        connection_string = os.getenv("AZURE_STORAGE_CONNECTION_STRING")

        if not connection_string:
            print("Azure Storage connection string missing.")
            return

        blob_service_client = BlobServiceClient.from_connection_string(connection_string)

        container_name = "smeincidents"

        blob_name = f"{incident['department']}/{incident['id']}.json"

        blob_client = blob_service_client.get_blob_client(
            container=container_name,
            blob=blob_name
        )

        blob_client.upload_blob(
            json.dumps(incident, indent=2),
            overwrite=False
        )

        print("Incident uploaded to Blob:", blob_name)

    except Exception as e:
        print("BLOB ERROR:", str(e))


# The main chatbot endpoint, handles messages, scans links/domains, sends questions to OpenAI
@app.post("/chat", response_class=PlainTextResponse)
async def chat(req: Request):
    data = await req.json()
    user_input = data.get("query", "").strip()
    safe_user_input = redact_pi(user_input)

    session_id = data.get("session_id", "default")

    cache_key = safe_user_input.lower().strip()

    if session_id in triage_state:
        state = triage_state[session_id]

        if state.get("stage") == "confirm":
            if user_input.lower() in ["yes", "y"]:
                state["conversation"].append(f"U: {user_input}")
                state["stage"] = "more_details"

                question = generate_final_details_question(
                    state["group"],
                    state["answers"],
                    session_id
                )

                state["conversation"].append(f"B: {question}")

                return question
            
            if user_input.lower() in ["no", "n"]:
                triage_state.pop(session_id, None)
                return "Okay, no incident was created."

            return "Please reply YES or NO."

        if state.get("stage") == "more_details":
            state["answers"].append(user_input)
            state["conversation"].append(f"U: {user_input}")
            return create_incident_from_triage(session_id, state)

        state["answers"].append(user_input)

        if state["question_count"] >= FOLLOWUPQUESTIONS:
            state["stage"] = "confirm"
            question = "Okay. Would you like me to create an incident for this? Reply YES or NO."

            state["conversation"].append(f"B: {question}")

            return question
        
        next_question = generate_triage_response(
            state["group"],
            state["answers"],
            user_input,
            session_id
        )
        state["conversation"].append(f"B: {next_question}")
        state["question_count"] += 1
        return next_question

    # This message is sent if the user asks about scanning an email explain how to upload an .eml file
    if any(re.search(pat, user_input, re.IGNORECASE) for pat in SCAN_KEYWORDS):
        return "\n".join([
            "For maximum security, please upload the original `.eml` file. This ensures all hidden links, email headers, and attachments are fully inspected. Click the 📧 Add Email File button below to get started.",
            "",
            "",
            "**How to export an EML file:**",
            "",
            "1. Open the email in Gmail’s web interface.",
            "2. Click the three-dot menu `⋮` in the top-right corner, then select **Show original**.",
            "3. On the “Original Message” page, click **Download Original**.",
            "4. Save the resulting `.eml` file.",
            "5. Return here and click **Add Email File**, and select your saved `.eml` file."
        ])

    raw_bytes = user_input.encode("utf-8")
    urls, domains, attachments = parse_email(raw_bytes)

    malicious_indicators = []
    messages = []

    # if domain is rxtra.xyz (internal domain), don't scan
    for dom in domains:
        msg = block_internal(dom, session_id)
        if msg:
            return msg
        
    
    # Scan URLs 
    for url in set(re.findall(URL_REGEX, user_input)):
        full_url = url if url.startswith("http") else "http://" + url
        verdict = scan_url(full_url)["verdict"]
        messages.append(f"URL {full_url} → {verdict}.")
        if verdict.startswith("Likely") or verdict == "Suspicious":
            malicious_indicators.append(f"URL: {full_url}")

     # Scan domains
    for dom in domains:
        if not re.match(DOMAIN_PATTERN, dom):
            messages.append(
                f"Domain {dom} → Invalid domain format. Please check the spelling."
            )
            continue
        verdict = scan_domain(dom)["verdict"]
        messages.append(f"Domain {dom} → {verdict}.")

        if verdict.startswith("Likely") or verdict == "Suspicious":
            malicious_indicators.append(f"Domain: {dom}")

    for fname, fbytes in attachments:
        verdict = scan_file_attachment(fname, fbytes)["verdict"]
        messages.append(f"Attachment {fname} → {verdict}.")

        if verdict.startswith("Likely") or verdict == "Suspicious":
            malicious_indicators.append(f"Attachment: {fname}")

    for dom in set(re.findall(EMAIL_REGEX, user_input)):
        msg = block_internal(dom, session_id)
        if msg:
            return msg
        
        if dom not in domains:
            verdict = scan_domain(dom)["verdict"]
            messages.append(f"Domain {dom} → {verdict}.")

            if verdict.startswith("Likely") or verdict == "Suspicious":
                malicious_indicators.append(f"Domain: {dom}")

    # If anything malicious is detected, generate a PDF incident report automatically & notify security team
    if malicious_indicators:

        incident = {
            "id": f"INC{uuid.uuid4().hex[:8]}",
            "summary": "Malicious indicators detected during scan",
            "details": ", ".join(malicious_indicators),
            "department": "Cybersecurity",
            "status": "open",
            "created_at": datetime.utcnow().isoformat()
        }

        # Save incident permanently to Azure Blob Storage
        save_incident(incident)

        report_data = {
            "incident_id": incident["id"],
            "report_type": "automatic",
            "summary": incident["summary"],
            "severity": "high",
            "indicators": malicious_indicators
        }

        pdf_path, incident_id = generate_incident_pdf(report_data)

        notify_cybersecurity({
            "incident_id": incident["id"],
            "report_type": "automatic",
            "severity": "high",
            "indicators": malicious_indicators
        })

        filename = os.path.basename(pdf_path)

        message = (
            f"⚠️ A potential security threat was detected during the VirusTotal scan.\n\n"
            f"An incident report has been automatically generated and sent to the Cybersecurity team.\n\n"
            f"- **Incident ID**: {incident['id']}\n\n"
            f"- **Severity**: High\n\n"
            f"Please avoid interacting with the suspicious URL, domain, or file until it has been reviewed.\n\n"
            f"You can download the incident report [here](/download/{filename})."
        )

        return JSONResponse({
            "message": message,
            "download_url": f"/download/{filename}",
            "incident_id": incident["id"]
        })

        # This message is sent if the user pastes an email as a text and explains how to upload an .eml file
    if messages:
        messages.append("\n".join([
            "For maximum security, please upload the original `.eml` file. This ensures all hidden links, email headers, and attachments are fully inspected. Click the 📧 Add Email File button below to get started.",
            "",
            "",
            "**How to export an EML file:**",
            "",
            "1. Open the email in Gmail’s web interface.",
            "2. Click the three-dot menu `⋮` in the top-right corner, then select **Show original**.",
            "3. On the “Original Message” page, click **Download Original**.",
            "4. Save the resulting `.eml` file.",
            "5. Return here and click **Add Email File**, and select your saved `.eml` file."]))

        return "\n\n".join(messages)

    classification_raw = classify_incident(user_input, session_id)

    try:
        classification_clean = classification_raw.strip()

        if classification_clean.startswith("```json"):
            classification_clean = classification_clean.replace("```json", "").replace("```", "").strip()
        elif classification_clean.startswith("```"):
            classification_clean = classification_clean.replace("```", "").strip()

        classification = json.loads(classification_clean)

    except Exception as e:
        print("JSON PARSE ERROR:", e)
        print("RAW CLASSIFICATION:", classification_raw)
        classification = {"create_incident": False}
            
    if classification.get("create_incident"):
        group = classify_group(user_input)

        first_question = generate_triage_response(
            group,
            [user_input],
            user_input,
            session_id
        )

        triage_state[session_id] = {
            "group": group,
            "answers": [user_input],
            "conversation": [
                f"U: {user_input}",
                f"B: {first_question}"
            ],
            "question_count": 1,
            "stage": "asking"
        }

        return first_question
    
    if cache_key in response_cache:
        print("CACHE HIT:", cache_key)
        return response_cache[cache_key]


    llm_reply = ask_openai(safe_user_input, session_id=session_id)

    response_cache[cache_key] = llm_reply

    reply_lower = llm_reply.lower()

    if any(tag.lower() in reply_lower for tag in REFUSAL_TAGS):
            refusal_count[session_id] += 1
    else:
            # optional reset if user goes back to normal flow
            refusal_count[session_id] = max(0, refusal_count[session_id] - 1)

    if refusal_count[session_id] >= THRESHOLD:
            refusal_count[session_id] = 0  # prevent spam looping
            return WARNING_MESSAGE
        
    chat_sessions[session_id].append({
        "sender": "bot",
        "message": llm_reply
        })
        
    return llm_reply
    
# Returns previous chat history for a session
@app.get("/history/{session_id}")
async def get_history(session_id: str):
    return chat_sessions[session_id]

# To scan uploaded .eml files
@app.post("/scan-email-file", response_class=PlainTextResponse)
async def scan_email_file(email_file: UploadFile = File(...)):

    raw_bytes = await email_file.read()
    urls, domains, attachments = parse_email(raw_bytes)

    malicious_indicators = []
    messages = []

    for dom in domains:
        if dom in INTERNAL_DOMAINS:
            return "For security and privacy reasons, internal-domain messages cannot be scanned. Please reach out to our IT support team at ithelp@rxtra.xyz for assistance."

    for url in urls:
        verdict = scan_url(url)["verdict"]
        messages.append(f"URL {url} → {verdict}.")
        if verdict.startswith("Likely") or verdict == "Suspicious":
            malicious_indicators.append(f"URL: {url}")

    for dom in domains:
        verdict = scan_domain(dom)["verdict"]
        messages.append(f"Domain {dom} → {verdict}.")
        if verdict.startswith("Likely") or verdict == "Suspicious":
            malicious_indicators.append(f"Domain: {dom}")

    for fn, fb in attachments:
        verdict = scan_file_attachment(fn, fb)["verdict"]
        messages.append(f"Attachment {fn} → {verdict}.")
        if verdict.startswith("Likely") or verdict == "Suspicious":
            malicious_indicators.append(f"Attachment: {fn}")

    if malicious_indicators:

        incident = {
            "id": f"INC{uuid.uuid4().hex[:8]}",
            "summary": "Malicious indicators detected in uploaded email",
            "details": ", ".join(malicious_indicators),
            "department": "Cybersecurity",
            "status": "open",
            "created_at": datetime.utcnow().isoformat()
        }

        save_incident(incident)

        report_data = {
            "incident_id": incident["id"],
            "report_type": "automatic",
            "summary": incident["summary"],
            "severity": "high",
            "indicators": malicious_indicators
        }

        pdf_path, incident_id = generate_incident_pdf(report_data)

        notify_cybersecurity({
            "incident_id": incident["id"],
            "report_type": "automatic",
            "severity": "high",
            "indicators": malicious_indicators
        })

        filename = os.path.basename(pdf_path)

        message = (
            f"⚠️ A potential security threat was detected in the uploaded email.\n\n"
            f"An incident report has been automatically generated for the Cybersecurity team.\n\n"
            f"- **Incident ID**: {incident['id']}\n\n"
            f"- **Severity**: High\n\n"
            f"Please avoid interacting with any suspicious links or attachments until they have been reviewed.\n\n"
            f"You can download the incident report [here](/download/{filename})."
        )

        return JSONResponse({
            "message": message,
            "download_url": f"/download/{filename}",
            "incident_id": incident["id"]
        })
    if not messages:
            return "No URLs, domains, or attachments found in that .eml."

    report_lines = ["For this email, the scan results are:"]
    for i, line in enumerate(messages, start=1):
            report_lines.append(f"{i}. {line}")

    return "\n\n".join(report_lines)

# Open incident form page
@app.get("/incident_form.html")
async def incident_page():
    return FileResponse("incident_form.html")

# manually create incidents submitted with the button
@app.post("/incidents")
async def create_incident(request: Request):

    try: 

        data = await request.json()

        title = data.get("title", "")
        description = data.get("description", "")
        
        group = classify_group(title + " " + description)
        department = get_department_from_group(group)

        # creating incident 
        incident = {
            "id": f"INC{uuid.uuid4().hex[:8]}",
            "summary": title,
            "details": description,
            "department": department,
            "status": "open",
            "created_at": datetime.utcnow().isoformat()
        }

        save_incident(incident)

        # Generate downloadable PDF report
        pdf_path, incident_id = generate_incident_pdf({
            "incident_id": incident["id"],
            "summary": incident["summary"],
            "details": incident["details"]
        })

        filename = os.path.basename(pdf_path)
        session_id = data.get("session_id", "default")
        incident_message = (
            f"Your incident has been successfully created and sent to the "
            f"{incident['department']} department!\n\n"
            f"For reference, the details of your incident are:\n\n"
            f"- **ID**: {incident['id']}\n\n"
            f"- **Status**: {incident['status']}\n\n"
            f"- **Summary**: {incident['summary']}\n\n"
            f"The team will contact you soon to provide support and assistance. Please be ready to share any details regarding the issue to help them assist you effectively.\n\n" 
            f"In the meantime, you can download the PDF for your incident [here](/download/{filename})"
        )

        chat_sessions[session_id].append({
            "sender": "bot",
            "message": incident_message
        })

        print("Saved incident:", incident)

        return {
            "success": True,
            "incident": incident,
            "message": incident_message,
            "download_url": f"/download/{filename}"
        }
    
    except Exception as e:
        print("ERROR:", e)
        return JSONResponse(
    status_code=500,
    content={"success": False, "error": str(e)}
)
    
# Users can download incident reports from reports folder
@app.get("/download/{filename}")
async def download_pdf(filename: str):

    path = os.path.join("reports", filename)

    return FileResponse(
        path,
        media_type="application/pdf",
        filename=filename
    )

# Serves the main frontend page
@app.get("/", response_class=HTMLResponse)
async def home():
    return FileResponse("frontend.html")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)