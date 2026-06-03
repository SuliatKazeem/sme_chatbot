# Load environment variables from the .env file.
# This is where API keys are stored locally so they are not hardcoded in the code.
from dotenv import load_dotenv
load_dotenv()  

import os
import re

from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import PlainTextResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from datetime import datetime
from collections import defaultdict


from smeopenai import ask_openai, classify_group
from virustotal import parse_email, scan_url, scan_domain, scan_file_attachment
from incident_report import generate_incident_pdf
from notifypdf import notify_cybersecurity

import csv
import uuid
import json

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

INTERNAL_DOMAINS = {
    d.strip() for d in os.getenv("INTERNAL_DOMAINS", "").split(",") if d.strip()
}

# detect emails and URLs inside messages sent 
EMAIL_REGEX = r'[\w\.-]+@[\w\.-]+\.\w+'
URL_REGEX   = r'(https?://[^\s]+|www\.[^\s]+)'

# CSVs created for departments. IT issues go into it_incidents.csv and security issues go into security_incidents.csv.
IT_CSV = "it_incidents.csv"
SECURITY_CSV= "security_incidents.csv"

THRESHOLD     = 3 # threshold for out-of-scope questions, warning after 3rd time
FOLLOWUPQUESTIONS = 2  # 2 follow-up questions before asking if the user wants an incident created.

refusal_count = defaultdict(int)

# Store chat history temporarily
chat_sessions = defaultdict(list)

triage_state = {}


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

# save incidents created into the inicdents csv file
def save_incident(incident: dict):
    file_path = SECURITY_CSV if incident["department"] == "Cybersecurity" else IT_CSV

    file_exists = os.path.isfile(file_path)

    with open(file_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow(["id","title","description","department","status","created_at"])

        writer.writerow([
            incident["id"],
            incident["title"],
            incident["description"],
            incident["department"],
            incident["status"],
            incident["created_at"]
        ])
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

#save the incident to CSV, create a PDF report, and give user a download link.
def create_incident_from_triage(session_id: str, state: dict):
    group = state["group"]
    department = get_department_from_group(group)

    incident = {
        "id": f"INC{uuid.uuid4().hex[:8]}",
        "title": state["answers"][0],
        "description": state["answers"][-1],
        "department": department,
        "status": "open",
        "created_at": datetime.utcnow().isoformat()
    }

    save_incident(incident)

    pdf_path, incident_id = generate_incident_pdf({
        "incident_id": incident["id"],
        "report_type": "manual",
        "summary": incident["title"],
        "severity": "medium",
        "indicators": state["answers"]
    })

    filename = os.path.basename(pdf_path)

    triage_state.pop(session_id, None)

    return (
        f"Your incident has been successfully created and sent to the "
        f"{incident['department']} department.\n\n"
        f"- **ID**: {incident['id']}\n\n"
        f"- **Status**: {incident['status']}\n\n"
        f"- **Short Description**: {incident['title']}\n\n"
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
- Ask only one question.
- Maximum 100 words.
"""
    return ask_openai(prompt, session_id)

# The main chatbot endpoint, handles messages, scans links/domains, sends questions to OpenAI
@app.post("/chat", response_class=PlainTextResponse)
async def chat(req: Request):
    data = await req.json()
    user_input = data.get("query", "").strip()
    session_id = data.get("session_id", "default")

    if session_id in triage_state:
        state = triage_state[session_id]

        if state.get("stage") == "confirm":
            if user_input.lower() in ["yes", "y"]:
                state["stage"] = "more_details"
                return (
                    "Great! Before I create the incident, please provide any extra details that may help such as the exact error message, screenshots, affected device, affected system, time it started, "
                    "or anything you have already tried."
                )
            if user_input.lower() in ["no", "n"]:
                triage_state.pop(session_id, None)
                return "Okay, no incident was created."

            return "Please reply YES or NO."

        if state.get("stage") == "more_details":
            state["answers"].append(user_input)
            return create_incident_from_triage(session_id, state)

        state["answers"].append(user_input)

        if state["question_count"] >= FOLLOWUPQUESTIONS:
            state["stage"] = "confirm"
            return "Okay. Would you like me to create an incident for this? Reply YES or NO."

        next_question = generate_triage_response(
            state["group"],
            state["answers"],
            user_input,
            session_id
        )

        state["question_count"] += 1
        return next_question

    # This message is sent if the user asks about scanning an email explain how to upload an .eml file
    if any(re.search(pat, user_input, re.IGNORECASE) for pat in SCAN_KEYWORDS):
        return "\n".join([
            "You can paste it here or click the 📧 **Add Email File** button below "
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
        if verdict.startswith("Likely"):
            malicious_indicators.append(f"URL: {full_url}")

     # Scan domains
    for dom in domains:
        verdict = scan_domain(dom)["verdict"]
        messages.append(f"Domain {dom} → {verdict}.")
        if verdict.startswith("Likely"):
            malicious_indicators.append(f"Domain: {dom}")

    for fname, fbytes in attachments:
        verdict = scan_file_attachment(fname, fbytes)["verdict"]
        messages.append(f"Attachment {fname} → {verdict}.")
        if verdict.startswith("Likely"):
            malicious_indicators.append(f"Attachment: {fname}")

    for dom in set(re.findall(EMAIL_REGEX, user_input)):
        msg = block_internal(dom, session_id)
        if msg:
            return msg
        
        if dom not in domains:
            verdict = scan_domain(dom)["verdict"]
            messages.append(f"Domain {dom} → {verdict}.")

    # If anything malicious is detected, generate a PDF incident report automatically & notify security team
    if malicious_indicators:
        report_data = {
        "report_type": "automatic",
        "summary": "Malicious indicators detected during scan",
        "severity": "high",
        "indicators": malicious_indicators
        }

        pdf_path, incident_id = generate_incident_pdf(report_data)

        notify_cybersecurity({
            "incident_id": incident_id,
            "report_type": "automatic",
            "severity": "high",
            "indicators": malicious_indicators
        })

        return FileResponse(
            pdf_path,
            media_type="application/pdf",
            filename="incident_report.pdf"
        )

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

        triage_state[session_id] = {
                    "group": group,
                    "answers": [user_input],
                    "question_count": 1,
                    "stage": "asking"
                }

        first_question = generate_triage_response(
                    group,
                    [user_input],
                    user_input,
                    session_id
                )

        return first_question
    
    llm_reply = ask_openai(user_input, session_id=session_id)

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
        if verdict.startswith("Likely"):
            malicious_indicators.append(f"URL: {url}")

    for dom in domains:
        verdict = scan_domain(dom)["verdict"]
        messages.append(f"Domain {dom} → {verdict}.")
        if verdict.startswith("Likely"):
            malicious_indicators.append(f"Domain: {dom}")

    for fn, fb in attachments:
        verdict = scan_file_attachment(fn, fb)["verdict"]
        messages.append(f"Attachment {fn} → {verdict}.")
        if verdict.startswith("Likely"):
            malicious_indicators.append(f"Attachment: {fn}")

    if malicious_indicators:
        report_data = {
            "report_type": "automatic",
            "summary": "Malicious indicators detected in uploaded EML file",
            "severity": "high",
            "indicators": malicious_indicators
        }

        pdf_path, incident_id = generate_incident_pdf(report_data)

        notify_cybersecurity({
            "incident_id": incident_id,
            "report_type": "automatic",
            "severity": "high",
            "indicators": malicious_indicators
        })

        return FileResponse(
            pdf_path,
            media_type="application/pdf",
            filename="incident_report.pdf"
        )

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
            "title": title,
            "description": description,
            "department": department,
            "status": "open",
            "created_at": datetime.utcnow().isoformat()
        }

        save_incident(incident)

        session_id = data.get("session_id", "default")

        incident_message = (
            f"Your incident has been successfully created and sent to the "
            f"{incident['department']} department!\n\n"
            f"For reference, the details of your incident are:\n\n"
            f"- **ID**: {incident['id']}\n\n"
            f"- **Status**: {incident['status']}\n\n"
            f"- **Short Description**: {incident['title']}\n\n"
            f"The team will contact you soon to provide support and assistance. Please be ready to share any details regarding the issue to help them assist you effectively.\n\n" 
            f"In the meantime, you can download the PDF for your incident [here](${data.download_url})"
        )

        chat_sessions[session_id].append({
            "sender": "bot",
            "message": incident_message
        })

        # Generate downloadable PDF report
        pdf_path, incident_id = generate_incident_pdf({
        "incident_id": incident["id"],
        "report_type": "manual",
        "summary": title,
        "severity": "medium",
        "indicators": [description]
        })

        print("Saved incident:", incident)

        filename = os.path.basename(pdf_path)

        return {
            "success": True,
            "incident": incident,
            "download_url": f"/download/{filename}"
        }
    
    except Exception as e:
        print("ERROR:", e)
        return {"error": str(e)}

# PDF download endpoint
@app.get("/download-pdf")
async def download_pdf(path: str):
    return FileResponse(
        path,
        media_type="application/pdf",
        filename=os.path.basename(path)
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