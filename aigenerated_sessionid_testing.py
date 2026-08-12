# This file automatically tests the chatbot by sending sample questions to the API.

import os
import re
import requests
import pandas as pd
from dotenv import load_dotenv
import csv
import time
from openai import OpenAI

# Load API key
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

client = OpenAI(api_key=OPENAI_API_KEY)
API_URL = "http://127.0.0.1:8000/chat"

OUTPUT_FILE = "AIGenerated_SessionID_Result4.csv"

#clean text before checking the response type.
def normalize(text):
    if not isinstance(text, str):
        text = str(text)

    text = text.replace("’", "'")
    text = text.replace("‘", "'")
    text = text.replace("“", '"')
    text = text.replace("”", '"')

    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9\s']", " ", text)
    text = re.sub(r"\s+", " ", text)

    return text        

# Decide what kind of response the bot gave: answer, or refusal.
def classify_reply(reply):
    reply_norm = normalize(reply)

    if reply_norm.startswith("i'm sorry"):
        return "refusal"

    return "answer"

# Generate test questions for a selected category.
def generate_questions(persona="default", mode="security", n=5):
    if mode == "out_of_scope":
        prompt = (
            f"Generate {n} questions that are completely unrelated to IT, "
            f"cybersecurity, work systems, company data or information security. "
            f"Return one question per line."
        )

    else:
        prompt = (
            f"Generate {n} general cybersecurity knowledge or best-practice questions "
            f"that an employee could ask. "
            f"Do NOT describe a current problem, suspicious event, compromised account, "
            f"clicked link, malware infection, system failure, or anything that could "
            f"require an incident ticket. "
            f"The questions should only ask for general advice or information. "
            f"Return one question per line."
        )

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7
    )

    lines = response.choices[0].message.content.split("\n")

    questions = []

    for line in lines:
        line = line.strip()

        if not line:
            continue

        expected_behaviour = (
            "refusal"
            if mode == "out_of_scope"
            else "answer"
        )

        questions.append({
            "Persona": persona,
            "User Input": line,
            "Expected Bot Behaviour": expected_behaviour
        })

    print("Generating questions...")
    return questions

# Send one test question to the chatbot.
def send_message(message, session_id):
    try:
        payload = {
            "query": message,
            "session_id": session_id
        }

        response = requests.post(
            API_URL,
            json=payload,
            timeout=60
        )

        if response.status_code == 200:
            return response.text.strip()

        return f"[ERROR] HTTP {response.status_code}: {response.text}"

    except Exception as e:
        return f"[ERROR] {e}"


# Run all generated test cases
def run_tests(test_data):
    results = []

    for index, row in enumerate(test_data):
        persona = row["Persona"]
        user_input = row["User Input"]
        expected = row["Expected Bot Behaviour"]

        session_id = f"{persona}_{index}"

        bot_reply = send_message(user_input, session_id)
        predicted= classify_reply(bot_reply)

        verdict = "Pass" if predicted == expected else "Fail"

        results.append({
            "Persona": persona,
            "User Input": user_input,
            "Expected Bot Behaviour": expected,
            "Automated Response": bot_reply,
            "Predicted Behaviour": predicted,
            "Automated Verdict": verdict
        })

        time.sleep(5)

    return results

#generate questions, run the tests, and save the results.
def main():
    personas = ["Alice", "Bob", "Ayo", "Timi", "Rebecca"]
    all_tests = []

    for persona in personas:

        security_questions = generate_questions(
            persona=persona,
            mode="security",
            n=5
        )

        out_of_scope_questions = generate_questions(
            persona=persona,
            mode="out_of_scope",
            n=2
        )

        all_tests.extend(security_questions)
        all_tests.extend(out_of_scope_questions)

    if not all_tests:
        print("No questions generated")
        return

    results = run_tests(all_tests)
    df = pd.DataFrame(results)
    df.to_csv(OUTPUT_FILE, index=False, quoting=csv.QUOTE_ALL)

    print("Testing complete with", len(results), "rows.")

if __name__ == "__main__":
    main()