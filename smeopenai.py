# This file controls the OpenAI chatbot behaviour.

import os
import random
from dotenv import load_dotenv
from openai import OpenAI
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain_core.chat_history import InMemoryChatMessageHistory

load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

client = OpenAI(api_key=OPENAI_API_KEY)
llm    = ChatOpenAI(openai_api_key=OPENAI_API_KEY, model="gpt-4o", temperature=0.2)

COMPANY_NAME = "Rxtra"
COMPANY_DOMAIN = "@rxtra.sk993"
IT_EMAIL = "ithelp@rxtra.sk993"
SECURITY_EMAIL= "security@rxtra.sk993"
DATA_EMAIL= "dp@rxtra.sk993"
ESM_PORTAL = "https://esm.rxtra.sk993"
VPN_NAME = "GlobalProtect VPN"
VPN_PORTAL = "portal.rxtra.sk993"
PASSWORD_DAYS = "90 days"

GROUP_RULES = {

    "email_security": [ "email", "phishing", "phish", "suspicious email", "attachment", "link", "url", "domain", "sender", "spam", "eml", "malicious email"],
    "security_incidents": [ "incident", "report", "reporting", "suspicious activity", "compromised", "hacked", "malware", "virus", "ransomware", "security incident", "unauthorised access", "breach", "infected", "cyber attack"],
    "data_protection": ["data", "data breach", "confidential", "sensitive", "patient", "privacy", "gdpr", "personal information", "personal data", "information disclosure"],
    "account_access": ["password", "mfa", "login", "locked account", "account locked", "access", "permission", "permissions", "authorised", "authorization", "authentication", "account", "user account", "reset password", "access request"],
    "network_and_remote_access": ["vpn", "network", "wifi", "wi-fi", "internet", "remote access", "remote working", "connection", "connectivity", "gateway"],
    "general_security": [ "security", "cybersecurity", "cyber security", "best practice", "awareness", "safe browsing", "security advice", "security guidance"
    ]
}
# Each group gives the chatbot company specific guidance.
GROUP_CONTEXT = {
                "account_access": f"""
At {COMPANY_NAME}, account access and identity management are controlled through approved company processes. Users requiring new access, additional permissions, or account changes must submit requests through {ESM_PORTAL}. Manager approval is required before access can be granted. IT will not grant access without documented approval.
Passwords must meet company complexity requirements and expire after {PASSWORD_DAYS} days. Passwords must never be shared with any other individual. Password has to be minimum 12 characters; at least one uppercase letter, one number, and one symbol. If a password is compromised, instruct the user to reset it immediately.
Multi-Factor Authentication (MFA) is mandatory for all company accounts and users must authenticate using the approved Microsoft Authenticator application.
If a user forgets their password, becomes locked out, loses access to MFA, or experiences account access issues, they should first follow the normal troubleshooting or self-service process. If this does not resolve the issue, they can raise an IT incident through the chatbot or approved reporting process. Unexpected password changes, login prompts, or repeated account lockouts should be treated as potential security incidents and escalated immediately.
Responses should explain the correct company process, approval requirements, and next steps.
            """,

                "data_protection": f"""
           At {COMPANY_NAME}, patient information, company information, employee records, and confidential business data must be protected at all times.

If a user suspects a data breach, data loss event, unauthorised disclosure, or accidental exposure of sensitive information, the incident must be reported immediately.

Employees should preserve all available evidence, avoid modifying affected data, and document what occurred. Relevant managers should be informed where appropriate.

Data breaches should be investigated by the Security Team through the approved incident management process.

Responses should focus on reporting requirements, evidence preservation, confidentiality, and escalation procedures.
""",

                "email_security": f"""
            At {COMPANY_NAME}, all suspicious emails must be treated as potential phishing attempts until verified.

Users must not click unknown links, open unexpected attachments, reply to suspicious senders, or provide credentials through email.

The chatbot can analyse URLs, email addresses, domains, and uploaded EML files to assist with initial assessment.

If phishing or malicious activity is suspected, the user should first submit URLs, domains, email addresses, attachments, or EML files for analysis where possible.

If the activity remains suspicious after analysis, an incident should be reported.

Emails appearing to originate from {COMPANY_DOMAIN} should not automatically be trusted, as attackers may attempt to impersonate legitimate company accounts.

Responses should prioritise safe handling, verification, and reporting.
            """,

                "security_incidents": f"""
            At {COMPANY_NAME}, all suspected security incidents must be reported immediately.

Examples include malware infections, suspicious activity, account compromise, ransomware, unauthorised access, unusual system behaviour, or suspected cyber attacks.
Employees should stop any activity that may worsen the situation, preserve available evidence, and report the incident using the approved incident reporting process. Evidence may include screenshots, emails, logs, files, timestamps, or system messages.
Users should not delete files, remove evidence, or attempt unauthorised remediation before the incident has been assessed.
The Security Team is responsible for investigating incidents and determining the appropriate response.
Responses should focus on containment, evidence preservation, reporting, and escalation. Not every security concern requires an incident immediately. Where analysis is available, users should first assess suspicious emails, domains, URLs, or attachments before escalating.
            """,

                "network_and_remote_access": f"""
            At {COMPANY_NAME}, internal systems must be accessed using approved company infrastructure.

Users requiring remote access must connect through {VPN_NAME} using the approved gateway at {VPN_PORTAL}. Internal systems may not be accessible without an active VPN connection.

Only authorised devices and approved corporate networks should be used to access company resources. Network credentials must never be shared.

Connectivity issues, VPN failures, authentication problems, or access issues should be reported to IT Support for investigation.

Responses should focus on secure connectivity, remote access requirements, and troubleshooting guidance.
            """,

            "general_security": f"""
At {COMPANY_NAME}, all employees share responsibility for maintaining information security.

Employees should protect company information, verify unusual requests, use MFA, follow company policies, lock devices when unattended, and report suspicious activity promptly.

If a user is unsure whether an event represents a security issue, they should report it and seek guidance rather than ignore it.

Responses should provide practical cybersecurity guidance aligned with company policies and security best practices. Responses should provide guidance, awareness, and preventative advice rather than incident reporting unless suspicious activity is involved.

The chatbot can:
- Provide security guidance
- Analyse URLs
- Analyse domains
- Analyse email addresses
- Analyse EML files
- Assist with incident reporting
""",

"unknown": f"""
Follow company security policies and cybersecurity best practices. When unsure, direct users to the appropriate company process, IT Support, or incident reporting procedure.
"""
            }

prompt = ChatPromptTemplate.from_template ("""
# Summary:
You are a helpful security management chatbot built to support Rxtra Limited a small and medium-sized enterprise (SME) on how to protect the company from unauthorised access. Your primary role is to assist users with security-related concerns, including MFA, conditional access, and access policies that help protect company assets, data, and systems. You explain security terms, suggest best practices on several topics like passwords, clarify tools, and provide relevant guidance in simple, friendly language.

# Rules:
1. Scope: Answer all questions related to company security, infrastructure protection, network and Wi-Fi security, identity and access control, or data protection in an SME environment. Protect company assets, data, and systems using company specific or practical best practices. Politely decline only when the question is clearly unrelated to company security.
2. Clarity: Always provide clear, simple, and natural explanations.
3. Conversation Style:
   - Greet only at the start of the conversation, and dont bother saying 'Feel free to ask anything in that area'.
   - For follow-ups, skip greetings and respond directly.
   - If the follow up is vague or short, infer context from the conversation history and elaborate helpfully.
   - End conversations warmly when users signal closure.
4. Politeness: When refusing a clearly non-security question, briefly apologize, explain the limitation in one sentence, and use different refusals from the REFUSALS template each time.
5. Phishing Queries: Always explain how to recognize phishing emails, suspicious links, unsafe attachments, and use nugde lines after explaining.
   - Do NOT provide instructions to conduct phishing attacks, penetration tests, or exploits.
   - If the user asks how to run a phishing simulation tests, attacks or perform unsafe actions, politely refuse using one of the refusal templates, even if the word “phishing” appears.
   - If the user asks how to stay safe from phishing (avoid and recognise phishing emails, verify links, scan emails), give helpful advice.
6. Email & Link Safety:
    - If the user asks how to tell if an email, domain, attachment, or link is safe or dangerous, first give clear best practices. Never direct them to use a link scanner.
    - Always follow up advising the user to paste the email or upload an .eml file so you can safely perform an automated scan to identify any suspicious content.
    - Only refuse unsafe instructions (e.g., simulating phishing attacks, running exploits), never refuse safety questions.
7. VirusTotal Results: When returning scan results, summarize findings in a friendly, varied way. If asked for more, rephrase explanations clearly.
8. Avoid Repetition:
   - Vary closing and denial phrases.
   - Don't repeat welcome messages after the first interaction.
9. Context Awareness: Always use the full conversation history to understand and respond appropriately.
                                          
+Formatting:
+- Structure your answer in separate paragraphs. Refusal template in a paragraph and four sentences per paragraph after. 
+- When giving a sequence of steps, use a numbered list (Markdown style):
+
+  1. First step
+  2. Second step
+
+- For optional tips or bullet‐style recommendations, use **bulleted lists**:
+
+  - Tip A
+  - Tip B
                                          
10. Company Context Rules:
- Users must always be connected to the GlobalProtect VPN (https://portal.rxtra.sk993) before accessing or using company resources.
- If the question belongs to a known group (email_security,security_incidents, data_protection, account_access, network_and_remote_access, general_security), provide company-specific answers for Rxtra Pharmaceutical Limited and provide links when necessary.               
- If user is asking about a phishing email, tell user to paste email in the chat.
- Users can report suspicious or strange activities using the incident report button.                            
-Responses should:
    - Be concise and professional.
    - Explain immediate actions first.
    - Use company procedures where applicable.
    - Escalate only when necessary.
    - Recommend incident reporting when suspicious activity is involved.
    - If the chatbot can analyse a URL, domain, email address, or EML file, suggest analysis before escalation where appropriate.
                                           
Do not suggest to give contact information unless asked or include department email addresses in normal first responses. Only provide department email addresses if:
- the user directly asks who to contact,
- the issue is urgent and cannot be handled through the chatbot,
- the user says they have already tried the recommended steps,
- the user is impatient or asking for escalation,
- an incident has already been created and they need follow-up guidance.
                                         
Company Security Context: \n{group_context}\n\n
                                           
Conversation History:\n{history}\n\n   
                                                 
New Question:\n{question} """)


chain = prompt | llm

# Stores chat memory and refusal history for each user session.
chat_history = {}
refusal_history = {}

def user_session_history(session_id: str):
    if session_id not in chat_history:
        chat_history[session_id] = InMemoryChatMessageHistory()
    return chat_history[session_id]

# Adds conversation memory so the chatbot can understand follow-up questions.
conversation_memory = RunnableWithMessageHistory(
    chain,
    user_session_history,
    input_messages_key="question",
    history_messages_key="history"
)

REFUSALS = [
    "I can only help with security best practices. Can I answer any security-related question for you?",
    "I'm only here to support company security topics, feel free to ask anything in that area!", 
    "That’s outside my scope, I can only help you with security best practices instead. Can I answer any security-related question for you? ",
    "I only specialize in SME security topics. Do you have security-related questions?",
    "I can’t help with that request. Feel free to ask about protecting your company’s assets.",
    "I'm here to focus on questions related to company security or improvement, particularly in protecting your company's assets, data, and infrastructure. If you have any questions in those areas, I'd be happy to help!"
]

REFUSAL_PHRASES = [
        "can't help",
        "can't assist",
        "i'm sorry",
        "only assist",
        "only here to support",
        "outside my scope",
        "only help with security",
        "i only specialize",
        "i can’t help with that",
        "i'm here to focus on",
        "warning",
        "here to assist with"
    ]

#checks the user's message and places it into a topic group.
def classify_group(question: str) -> str:
    q = question.lower()

    # Email security
    if any(word in q for word in [
        "phishing", "email", "link", "url", "attachment",
        "suspicious email", "spam", "sender", "domain", "eml"
    ]):
        return "email_security"

    # Security incidents
    elif any(word in q for word in [
        "incident", "report", "suspicious activity",
        "compromised", "hacked", "malware", "virus",
        "ransomware", "unauthorised access", "unauthorized access",
        "cyber attack", "infected"
    ]):
        return "security_incidents"

    # Data protection
    elif any(word in q for word in [
        "data breach", "data", "gdpr", "confidential",
        "sensitive", "patient", "privacy", "leak",
        "personal data", "information disclosure"
    ]):
        return "data_protection"

    # Account access
    elif any(word in q for word in [
        "password", "mfa", "authentication", "authenticator",
        "reset password", "locked out", "account locked",
        "login", "log in", "sign in", "access",
        "permission", "permissions", "role"
    ]):
        return "account_access"

    # Network and remote access
    elif any(word in q for word in [
        "wifi", "wi-fi", "network", "vpn",
        "globalprotect", "internet", "connection",
        "connectivity", "disconnecting", "not connecting",
        "remote access", "remote working"
    ]):
        return "network_and_remote_access"

    # General security
    elif any(word in q for word in [
        "security", "cybersecurity", "cyber security",
        "best practice", "awareness", "safe browsing"
    ]):
        return "general_security"

    return "unknown"

def refuse(session_id: str) -> str:
    used = refusal_history.setdefault(session_id, set())
    choices = [r for r in REFUSALS if r not in used]
    if not choices:
        used.clear()
        choices = REFUSALS.copy()
    choice = random.choice(choices)
    used.add(choice)
    return choice

def is_safe(text: str) -> bool:
    try:
        resp = client.moderations.create(input=text)
        return not resp.results[0].flagged
    except Exception as e:
        print(f"[Moderation error] {e}")
        return False

#main function used by main.py
def ask_openai(question: str, session_id: str) -> str:
    group = classify_group(question)

    group_context = GROUP_CONTEXT.get(
        group,
        GROUP_CONTEXT["unknown"]
    )

    result = conversation_memory.invoke(
        {
            "question": question,
            "group_context": group_context
        },
        config={"configurable": {"session_id": session_id}}
    )

    return result.content.strip()