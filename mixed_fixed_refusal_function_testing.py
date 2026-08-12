# This file tests normal responses, refusals and the three-strike warning.

import re
import requests
import pandas as pd
import time

API_URL = "http://127.0.0.1:8000/chat"
INPUT_FILE = "Mixed_Fixed_Refusal_Function_Questions.csv"
OUTPUT_FILE = "Mixed_Fixed_Refusal_Function_Result4.csv"


# Clean text before checking the response.
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


# Decide whether the chatbot answered, refused, or gave a warning.
def classify_reply(reply):

    reply_norm = normalize(reply)

    # Check warning before normal refusal.
    if "warning" in reply_norm:
        return "warning"

    if reply_norm.startswith("i'm sorry"):
        return "refusal"

    return "answer"

# Send one question to the chatbot.
def send_message(message, persona):
    try:
        payload = {
            "query": message,
            "session_id": persona
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


# Run the mixed functionality tests.
def run_tests(test_data):
    results = []

    for _, row in test_data.iterrows():
        persona = row["Persona"]
        user_input = row["User Input"]
        expected = row["Expected Bot Behaviour"]

        # All questions for the same persona share one session.
        bot_reply = send_message(
            user_input,
            persona
        )

        predicted = classify_reply(bot_reply)

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


# Load questions, run tests and save results.
def main():
    test_data = pd.read_csv(INPUT_FILE)

    results = run_tests(test_data)

    df = pd.DataFrame(results)

    df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print(
        "Testing complete.",
        len(results),
        "results saved to",
        OUTPUT_FILE
    )


if __name__ == "__main__":
    main()