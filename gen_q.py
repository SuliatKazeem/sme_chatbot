# This file automatically tests the chatbot by sending sample questions to the API.

import os
import re
import requests
import pandas as pd
from dotenv import load_dotenv
import csv
from openai import OpenAI
from smeopenai import REFUSAL_PHRASES

load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

client = OpenAI(api_key=OPENAI_API_KEY)

load_dotenv()

API_KEY = os.getenv("OPENAI_API_KEY")
API_URL = "http://127.0.0.1:8000/chat"

def normalize(text):
    if not isinstance(text, str):
        text = str(text)
    text = text.replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"')
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9\s']", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text          

# Decide what kind of response the bot gave: answer, refusal, or triage.
def classify_reply(reply):
    reply_norm = normalize(reply)

    triage_phrases = [
        "would you like me to create an incident",
        "before i create the incident",
        "please provide any extra details",
        "have you",
        "could you please",
        "can you confirm",
        "did you",
        "what error",
        "what message",
        "has this happened",
        "when did this start"
    ]

    for phrase in triage_phrases:
        if phrase in reply_norm:
            return "triage"

    for pattern in REFUSAL_PHRASES:
        if re.search(pattern, reply_norm):
            return "refusal"

    return "answer"

def expected_bot_behaviour_from_response(bot_reply):

    return classify_reply(bot_reply)

# Use OpenAI to generate test questions for each test category.
def generate_questions(persona="default", mode="security", n=8):
    if mode == "out_of_scope":
        prompt = f"Generate {n} OUT-OF-SCOPE questions not related to IT, cybersecurity, work systems, or company data. One per line."

    elif mode == "triage":
        prompt = f"Generate {n} realistic employee IT or cybersecurity problem reports that may need an incident ticket. One per line."

    else:
        prompt = f"Generate {n} general cybersecurity advice questions from employees. These should NOT be incident reports. One per line."

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7
    )

    lines = response.choices[0].message.content.split("\n")

    data = []
    for line in lines:
        line = line.strip()
        if not line:
            continue

        data.append({
            "Persona": persona,
            "User Input": line,
            "Expected Bot Behaviour": (
                "refusal" if mode == "out_of_scope"
                else "triage" if mode == "triage"
                else "answer"
            )
        })

    print("Generating Questions...")
    return data

# Send one test question to the local chatbot API.
def send_message(message, persona="default"):
    try:
        payload = {"query": message, "session_id": persona}
        headers = {"Content-Type": "application/json"}

        response = requests.post(API_URL, headers=headers, json=payload)

        if response.status_code == 200:
            return response.text.strip()

        return f"[ERROR] HTTP {response.status_code}: {response.text}"

    except Exception as e:
        return f"[ERROR] {e}"


def run_tests(test_data):
    results = []

    for row in test_data:
        persona = row["Persona"]
        user_input = row["User Input"]
        expected = row["Expected Bot Behaviour"]

        bot_reply = send_message(user_input, persona)
        predicted_type = classify_reply(bot_reply)

        verdict = "Pass" if predicted_type == expected else "Fail"

        results.append({
            "Persona": persona,
            "User Input": user_input,
            "Expected Bot Behaviour": expected,
            "Automated Response": bot_reply,
            "Predicted Behaviour": predicted_type,
            "Automated Verdict": verdict
        })

    return results


def main():
    personas = ["Alice", "Bob", "Ayo"]
    all_tests = []

    for persona in personas:
        advice_questions = generate_questions(
            persona=persona,
            mode="security",
            n=5
        )

        triage_questions = generate_questions(
            persona=persona,
            mode="triage",
            n=5
        )

        out_of_scope_questions = generate_questions(
            persona=persona,
            mode="out_of_scope",
            n=4
        )

        all_tests.extend(advice_questions)
        all_tests.extend(triage_questions)
        all_tests.extend(out_of_scope_questions)

    if not all_tests:
        print("No questions generated. Check API response.")
        return

    results = run_tests(all_tests)
    df = pd.DataFrame(results)
    df.to_csv("Test_results.csv", index=False, quoting=csv.QUOTE_ALL)

    print("Completed! CSV saved with", len(results), "rows.")

if __name__ == "__main__":
    main()