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
COMPANY_DOMAIN = "@rxtra.xyz"
IT_EMAIL = "ithelp@rxtra.xyz"
SECURITY_EMAIL= "security@rxtra.xyz"
DATA_EMAIL= "dp@rxtra.xyz"
ESM_PORTAL = "https://esm.rxtra.com"
VPN_NAME = "GlobalProtect VPN"
VPN_PORTAL = "portal.rxtra.com"
PASSWORD_DAYS = "90 days"

GROUP_RULES = {
    "access_control": ["access", "permission", "authorised", "role"],
    "password_security": ["password", "mfa", "login"],
    "data_protection": ["data", "confidential", "patient"],
    "email_phishing": ["email", "phishing", "link", "url"],
    "incident_reporting": ["incident", "reporting", "suspicious"]
}

# Each group gives the chatbot company specific guidance.
GROUP_CONTEXT = {
                "access_control": f"""
            At {COMPANY_NAME}, access is strictly role-based.

            - All access requests must be submitted via the {ESM_PORTAL}
            - Requests MUST include manager approval from an authorised {COMPANY_DOMAIN} email
            - IT will not grant access without documented approval
            - Shared accounts are strictly prohibited
            - Users MUST be connected to {VPN_NAME} to access internal systems
            - Access is only available via the secure gateway: {VPN_PORTAL}

            Users should be directed to submit an ESM ticket and attach approval evidence.
            """,

                "password_security": f"""
            At {COMPANY_NAME}, password policy requires:

            - Minimum 12 characters
            - At least one uppercase letter, one number, and one symbol.
            - MFA (Multi-Factor Authentication) is mandatory for all accounts linked to {COMPANY_DOMAIN}. Users need to authenticate from the Microsoft Authentication App.

            Users must never share passwords or reuse passwords across systems. Passwords expire after {PASSWORD_DAYS}.
            If a password is compromised, instruct the user to reset it immediately.
            """,

                "data_protection": f"""
            At {COMPANY_NAME}, all patient and company data is strictly confidential.

            - Data must NOT be shared externally without encryption and proper authorisation
            - Access to sensitive data requires an approved ESM ticket
            - Only users with valid {COMPANY_DOMAIN} accounts and permissions may access internal data
            - Company resources can only be accessed when connected to the GlobalProtect VPN via https://portal.rxtra.com
            """,

                "email_phishing": f"""
            At {COMPANY_NAME}, phishing and suspicious emails must be handled as follows:

            - DO NOT click unknown links or download attachments.
            - Emails, URLs must be pasted to chatbot for verdict before using the incident report button.
            - Users must use the internal incident report button immediately for suspicious activity.
            - Users can submit URLs, email addresses, or upload .eml files for analysis
            - Suspicious emails often impersonate {COMPANY_DOMAIN} accounts
            """,

                "incident_reporting": f"""
            At {COMPANY_NAME}, any suspicious activities need to be reported using the incident report button.

            - Users must use incident report button.
            - If in doubt, report it immediately using the incident report button.
            """,

                "network_security": f"""
            At {COMPANY_NAME}, all users must connect through {VPN_NAME} before accessing internal resources.

            - Use only approved corporate Wi-Fi networks.
            - Never share Wi-Fi credentials.
            - Connect through {VPN_PORTAL}.
            """,

                "unknown": f"""
            Follow general cybersecurity best practices at {COMPANY_NAME}.
            When unsure, escalate via the {ESM_PORTAL} or report it immediately using the incident report button.
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
- Users must always be connected to the GlobalProtect VPN (https://portal.rxtra.com) before accessing company resources.
- If the question belongs to a known group (password_security, access_control, data_protection, network_security, email_phishing), provide company-specific answers for Rxtra Pharmaceutical Limited.                
- If user is asking about a phishing email, tell user to paste email in the chat.
- Users can report suspicious or strange activities using the incident report button.
- For other issues, always include internal guidance such as contacting:
  - IT Support: ithelp@rxtra.xyz
  - Security Team: security@rxtra.xyz
  - Data Protection: dp@rxtra.xyz
- If group is unknown, give general best practices.
                                         
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

    if any(word in q for word in [
        "password", "mfa", "authentication", "authenticator", "reset password",
        "locked out", "account locked", "sign in", "signin", "login", "log in"
    ]):
        return "password_security"

    elif any(word in q for word in [
        "access", "permission", "authorised", "authorized", "role",
        "conditional access", "denied", "not allowed", "can't access",
        "cannot access"
    ]):
        return "access_control"

    elif any(word in q for word in [
        "data", "protect", "sensitive", "gdpr", "breach", "confidential",
        "patient", "leak", "shared externally"
    ]):
        return "data_protection"

    elif any(word in q for word in [
        "wifi", "wi-fi", "network", "vpn", "globalprotect", "internet",
        "connection", "connectivity", "disconnecting", "not connecting",
        "slow", "offline"
    ]):
        return "network_security"

    elif any(word in q for word in [
        "phishing", "email", "link", "attachment", "suspicious email",
        "spam", "malware", "virus", "clicked", "downloaded"
    ]):
        return "email_phishing"

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