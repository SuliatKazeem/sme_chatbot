import os
import random
from dotenv import load_dotenv
from openai import OpenAI
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain_core.chat_history import InMemoryChatMessageHistory

# — Load API key —
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# — Clients —
client = OpenAI(api_key=OPENAI_API_KEY)
llm    = ChatOpenAI(openai_api_key=OPENAI_API_KEY, temperature=0.5)
 
prompt = ChatPromptTemplate.from_template("""
# Summary:
You are a helpful security management chatbot built to support exclusively small and medium-sized enterprises (SMEs). Your primary role is to assist users with security-related concerns that help protect company assets, data, and systems. You explain security terms, suggest best practices, clarify tools, and provide relevant guidance in simple, friendly language."

# Rules:
1. Scope: Only answer questions related to company security or company improvement, protecting company assets, data, and infrastructure in an SME context. Politely decline anything outside this scope, using varied friendly wording and explicitly rephrase each time.
2. Clarity: Always provide clear, simple, and natural explanations.
3. Conversation Style:
   - Greet only at the start of the conversation, and dont bother saying 'Feel free to ask anything in that area'.
   - For follow-ups, skip greetings and respond directly.
   - If the follow-up is vague or short, infer context from the conversation history and elaborate helpfully.
   - End conversations warmly when users signal closure.
4. Politeness: When refusing a non-security question, respond *only* with one of the refusal templates *and* **start the response** with the literal tag `[REFUSAL] `.
5. Phishing Queries: If asked about phishing, explain signs like suspicious links, spelling errors, or unfamiliar senders. Never attempt to scan or process the email directly. If asked about .eml file, always give helpful best practices.
6. VirusTotal Results: When returning scan results, summarize findings in a friendly, varied way. If asked for more, rephrase explanations clearly.
7. Avoid Repetition:
   - Vary closing and denial phrases.
   - Don't repeat welcome messages after the first interaction.
8. Context Awareness: Always use the full conversation history to understand and respond appropriately.

+Formatting:
+- Structure your answer in separate paragraphs. Four sentences per paragraph. 
+- When giving a sequence of steps, use a numbered list (Markdown style):
+
+  1. First step
+  2. Second step
+
+- For optional tips or bullet‐style recommendations, use **bulleted lists**:
+
+  - Tip A
+  - Tip B
                                          
Conversation History:\n{history}\n\n
New Question:\n{question} """)

# Chain
chain = prompt | llm
chat_history_store = {}
refusal_history = {}

def get_user_session_history(session_id: str):
    if session_id not in chat_history_store:
        chat_history_store[session_id] = InMemoryChatMessageHistory()
    return chat_history_store[session_id]

conversation_with_memory = RunnableWithMessageHistory(
    chain,
    get_user_session_history,
    input_messages_key="question",
    history_messages_key="history"
)

REFUSALS = [
    "Sorry, I can only help with security best practices. Can I answer any security-related question for you?",
    "I'm only here to support company security topics, feel free to ask anything in that area!", 
    "Sorry, that’s outside my scope, I can only help you with security best practices instead. Can I answer any security-related question for you? ",
    "I only specialize in SME security topics. Do you have security-related questions?",
    "I can’t help with that request. Feel free to ask about protecting your company’s assets."
    
]

def refuse(session_id: str) -> str:
    used = refusal_history.setdefault(session_id, set())
    choices = [r for r in REFUSALS if r not in used]
    if not choices:
        used.clear()
        choices = REFUSALS.copy()
    choice = random.choice(choices)
    used.add(choice)
    return choice

# — Input checks —
def is_moderated_safe(text: str) -> bool:
    try:
        resp = client.moderations.create(input=text)
        return not resp.results[0].flagged
    except Exception as e:
        print(f"[Moderation error] {e}")
        return False

def is_security_query(text: str) -> bool:
    blocked = ["hack", "bypass", "exploit", "disable", "decrypt"]
    lower = text.lower()
    return not any(k in lower for k in blocked)

# — Main entrypoint —
def ask_openai(question: str, session_id: str) -> str:
    # 1) Moderation filter
    if not is_moderated_safe(question):
        return refuse(session_id)

    # 2) Block obvious hacking requests
    if not is_security_query(question):
        return refuse(session_id)

    # 3) Invoke the LLM chain with memory
    result = conversation_with_memory.invoke(
        {"question": question},
        config={"configurable": {"session_id": session_id}}
    )
    return result.content.strip()