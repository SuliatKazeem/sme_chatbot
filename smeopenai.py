import os
import openai
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
