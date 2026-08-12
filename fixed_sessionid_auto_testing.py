# This file automatically tests the chatbot using predefined questions from a CSV file.

import re
import requests
import pandas as pd
import time

API_URL = "http://127.0.0.1:8000/chat"
INPUT_FILE = "Fixed_SessionID_Auto_Questions.csv"
OUTPUT_FILE = "Fixed_SessionID_Auto_Result4.csv"

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


# Decide whether the chatbot answered or refused.
def classify_reply(reply):
    reply_norm = normalize(reply)

    if reply_norm.startswith("i'm sorry"):
        return "refusal"

    return "answer"


# Send one question to the chatbot.
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


# Run all predefined test questions.
def run_tests(test_data):
    results = []

    for index, row in test_data.iterrows():
        persona = row["Persona"]
        user_input = row["User Input"]
        expected = row["Expected Bot Behaviour"]

        session_id = f"{persona}_{index}"

        bot_reply = send_message(
            user_input,
            session_id
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


# Load the fixed questions, run the tests, and save the results.
def main():
    try:
        test_data = pd.read_csv(INPUT_FILE)

    except FileNotFoundError:
        print(f"Could not find {INPUT_FILE}.")
        return

    required_columns = [
        "Persona",
        "User Input",
        "Expected Bot Behaviour"
    ]

    for column in required_columns:
        if column not in test_data.columns:
            print(f"Missing column: {column}")
            return

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