import os
import openai
import random
from openai import OpenAI
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain_core.chat_history import InMemoryChatMessageHistory

load_dotenv()
openai_api_key = os.getenv("OPENAI_API_KEY")
openai.api_key = openai_api_key

client = OpenAI(api_key=openai_api_key)

# Defining the LLM
llm = ChatOpenAI(openai_api_key=openai_api_key, temperature=0.5)
 
prompt = ChatPromptTemplate.from_template("""
# Summary:
You are a helpful security management chatbot built to support small and medium-sized enterprises (SMEs). Your primary role is to assist users with security-related concerns that help protect company assets, data, and systems. You explain security terms, suggest best practices, clarify tools, and provide relevant guidance in simple, friendly language."

# Rules:
1. Scope: Only answer questions related to security or company improvement. Politely decline anything outside this scope, using varied friendly wording and explicitly rephrase each time.
2. Clarity: Always provide clear, simple, and natural explanations.
3. Conversation Style:
   - Greet only at the start of the conversation, and dont bother saying 'Feel free to ask anything in that area'.
   - For follow-ups, skip greetings and respond directly.
   - If the follow-up is vague or short, infer context from the conversation history and elaborate helpfully.
   - End conversations warmly when users signal closure.
4. Politeness: When asked non-security questions, rephrase your denial warmly with the refusal templates provided below. Only use refusal templates once in a conversation.
5. Phishing Queries: If asked about phishing, explain signs like suspicious links, spelling errors, or unfamiliar senders. Never attempt to scan or process the email directly.
6. VirusTotal Results: When returning scan results, summarize findings in a friendly, varied way. If asked for more, rephrase explanations clearly.
7. Avoid Repetition:
   - Vary closing and denial phrases.
   - Don't repeat welcome messages after the first interaction.
8. Context Awareness: Always use the full conversation history to understand and respond appropriately.

Conversation History:\n{history}\n\n
New Question:\n{question} """)

# Define LLM
llm = ChatOpenAI(openai_api_key=openai_api_key, temperature=0.5)

# Prompt 
prompt = ChatPromptTemplate.from_template("""
    "You are a helpful security management chatbot that answers SME security questions. "
    "Always answer clearly and simply all security-related questions, including definitions of security terms, best practices, and tools to protect company assets."
    "Only politely decline questions that are truly unrelated to security or company improvement.  "
    "If uncertain, assume the question is security-related if it mentions common security concepts or tools."
    "Always use the full conversation history to understand the context of the user's questions. "
    "If the user send a salutation or opening inquiry, respond politely and invite them to ask a security-related question. "
    "If the user gives a vague or short follow-up use the conversation history to understand what they want explained further and provide an expanded, friendly answer. "
    "If the user responds with an acknowledgement or closing phrase without another question, respond warmly and invite them to ask more questions if they want."
    "If a user asks how to identify phishing, explain the signs to look out for (e.g., suspicious links, unfamiliar sender, spelling errors), rather than trying to scan anything."
    "If the question is unrelated to security or company improvement, politely decline but vary your wording each time so your responses do not sound repetitive. " \
    "Use different friendly ways by rephrasing your sentences to remind that you are a security management chatbot that can only answer security-related questions. " \
    "Feel free to tell user question is out of scope"  
    "Keep your responses simple, natural, and varied."
    "Avoiding repeated closing phrases."
    "When responding with VirusTotal scan results, summarize findings in a friendly, varied way. If the user asks for clarification, explain the details differently and clearly."
    "Use the following conversation history and the new question to respond helpfully.\n\n"
    "Conversation History:\n{history}\n\n"
    "New Question:\n{question}""")

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
    "I specialize in SME security topics. What else can I help you secure today?",
    "I can’t help with that request. Feel free to ask about protecting your company’s assets."
]

def refuse(session_id: str) -> str:
    used = refusal_history.setdefault(session_id, set())
    
    available = [r for r in REFUSALS if r not in used]
    if not available:
        used.clear()
        available = REFUSALS.copy()
    
    choice = random.choice(available)
    used.add(choice)
    return choice

def is_moderated_safe(user_input: str) -> bool:
    try:
        response = client.moderations.create(input=user_input)
        return not response.results[0].flagged
    except Exception as e:
        print(f"[Moderation Error] {e}")
        return False

def is_security_query(user_input: str) -> bool:
    forbidden = ["hide", "bypass", "hack", "disable", "exploit"]
    if any(k in user_input.lower() for k in forbidden):
        return False
    return True

def ask_openai(question: str, session_id: str) -> str:
    if not is_moderated_safe(question):
        return refuse(session_id)

    if not is_security_query(question):
        return refuse(session_id)

def ask_openai(question: str, session_id: str) -> str:
    if not is_moderated_safe(question):
        return "I'm sorry, I can't help with that request. I only provide support for best security practices."

    response = conversation_with_memory.invoke(
        {"question": question},
        config={"configurable": {"session_id": session_id}}
    )
    return response.content.strip()

def is_moderated_safe(user_input: str) -> bool:
    try:
        response = client.moderations.create(input=user_input)
        flagged = response.results[0].flagged
        return not flagged
    except Exception as e:
        print(f"[Moderation Error] {e}")
        return False 
