import os
import re
import requests
import pandas as pd
from dotenv import load_dotenv
import csv
from openai import OpenAI
from smeopenai import GROUP_CONTEXT, GROUP_RULES, REFUSAL_PHRASES

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

def detect_group(text):
    text = normalize(text)

    for group, keywords in GROUP_RULES.items():
        for k in keywords:
            if re.search(rf"\b{k}\b", text):
                return group

    return "unknown"


def classify_reply(reply):
    reply_norm = normalize(reply)

    for pattern in REFUSAL_PHRASES:
        if re.search(pattern, reply_norm):
            return "refusal"
    return "answer"

def expected_bot_behaviour_from_response(bot_reply):

    return classify_reply(bot_reply)

def generate_questions(persona="default", mode="security", n=8):
    if mode == "out_of_scope":
        prompt = f"Generate {n} OUT-OF-SCOPE questions (not cybersecurity). One per line."
    else:
        prompt = f"Generate {n} personalised cybersecurity questions that MUST sound like natural human questions from employees in a company. One per line."

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
            "Expected Bot Behaviour": "refusal" if mode == "out_of_scope" else "answer"
        })
    print("Generating Questions...")
    return data


def send_message(message, persona="default"):
    try:
        group = detect_group(message)
        context = GROUP_CONTEXT.get(group, "")
        payload = {"query": message, "session_id": persona}
        headers = {"Content-Type": "application/json"}

        if API_KEY:
            headers["Authorization"] = f"Bearer {API_KEY}"

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

        group = row.get("Group", "unknown")

        if expected == "refusal":
            predicted_type = classify_reply(bot_reply)
            verdict = "Pass" if predicted_type == "refusal" else "Fail"

        else:
            if group == "email_phishing":
                if any(word in bot_reply.lower() for word in ["safe", "malicious", "phishing"]):
                    verdict = "Pass"
                else:
                    verdict = "Fail"
            else:
                # normal answer check
                predicted_type = classify_reply(bot_reply)
                verdict = "Pass" if predicted_type == "answer" else "Fail"

        results.append({
        "Persona": persona,
        "User Input": user_input,
        "Expected Bot Behaviour": expected,
        "Automated Response": bot_reply,
        "Automated Verdict": verdict
    })

    return results


def main():
    personas = ["Alice", "Bob", "Ayo"]
    all_tests = []

    for persona in personas:
        sgenerated = generate_questions(
            persona = persona,
            mode="security", 
            n=8
        )

        ogenerated = generate_questions(
            persona=persona,
            mode="out_of_scope",
            n=4
        )

        all_tests.extend(sgenerated)
        all_tests.extend(ogenerated)

    if not all_tests:
        print("No questions generated. Check API response.")
        return

    results = run_tests(all_tests)
    df = pd.DataFrame(results)
    df.to_csv("Test9"
    ".csv", index=False, quoting=csv.QUOTE_ALL)
    print("Completed! CSV saved with", len(results), "rows.")

if __name__ == "__main__":
    main()