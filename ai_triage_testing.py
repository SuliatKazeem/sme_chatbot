# This file uses AI-generated scenarios to test complete chatbot triage workflows.

import os
import json
import time
import requests
import pandas as pd

from dotenv import load_dotenv
from openai import OpenAI


# Load the OpenAI API key.
load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

client = OpenAI(api_key=OPENAI_API_KEY)

API_URL = "http://127.0.0.1:8000/chat"
OUTPUT_FILE = "AI_Triage_Testing2.csv"

# Maximum number of chatbot turns before stopping a workflow.
MAX_TURNS = 6


# Eight workflows: two for each persona.
TEST_WORKFLOWS = [
    {"Persona": "Alice", "Expected Outcome": "IT"},
    {"Persona": "Alice", "Expected Outcome": "Cybersecurity"},
    {"Persona": "Alice", "Expected Outcome": "No Incident"},

    {"Persona": "Bob", "Expected Outcome": "IT"},
    {"Persona": "Bob", "Expected Outcome": "Cybersecurity"},
    {"Persona": "Bob", "Expected Outcome": "No Incident"},

    {"Persona": "Ayo", "Expected Outcome": "IT"},
    {"Persona": "Ayo", "Expected Outcome": "Cybersecurity"}
]


# Generate one realistic employee incident.
def generate_scenario(persona, expected_outcome):

    if expected_outcome == "IT":
        scenario_rules = """
Generate an active IT problem.

Possible topics include:
- VPN problem
- Wi-Fi or Internet problem
- password/login problem
- hardware problem
- software problem

The employee should clearly be experiencing a problem that may require
an IT incident.
"""

    elif expected_outcome == "Cybersecurity":
        scenario_rules = """
Generate an active cybersecurity incident.

Possible topics include:
- employee clicked a phishing link
- employee opened a suspicious attachment
- compromised account
- malware
- data breach

Something must have already happened.

Do NOT generate someone who is simply asking whether an email is suspicious.
Do NOT ask the chatbot to scan an email, URL or attachment.
"""

    else:
        scenario_rules = """
Generate a general cybersecurity or IT advice question that does NOT
describe an active problem or incident.

Examples of suitable topics include:
- why MFA is important
- password security
- phishing awareness
- safe remote working
- protecting company information

The employee must only be asking for information or advice.
Nothing bad has happened and an incident should NOT need to be created.
"""

    prompt = f"""
You are creating a test scenario for an SME security chatbot.

Persona: {persona}
Expected outcome: {expected_outcome}

{scenario_rules}

Rules:
- Write like a normal employee talking to a chatbot.
- Keep the message short and natural.
- Do not mention the expected outcome.
- Do not mention that this is a test.
- Avoid overly formal or technical wording.

Return only valid JSON:

{{
    "topic": "short topic",
    "message": "employee's message"
}}
"""

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "user", "content": prompt}
        ],
        temperature=0.7,
        response_format={"type": "json_object"}
    )

    data = json.loads(
        response.choices[0].message.content
    )

    return data

# Send a message to the chatbot being tested.
def send_message(message, session_id):
    try:
        response = requests.post(
            API_URL,
            json={
                "query": message,
                "session_id": session_id
            },
            timeout=60
        )

        if response.status_code == 200:
            return response.text.strip()

        return f"[ERROR] HTTP {response.status_code}: {response.text}"

    except Exception as e:
        return f"[ERROR] {e}"


# Generate a short employee response to the chatbot's follow-up question.
def generate_employee_reply(
    persona,
    original_scenario,
    bot_message
):

    prompt = f"""
            You are {persona}, an employee who reported this problem:

            {original_scenario}

            The support chatbot has now said:

            {bot_message}

            Reply naturally as the employee.

            Rules:
            - Keep the response short.
            - Stay consistent with the original problem.
            - Do not create a new problem.
            - Give useful information if the chatbot asks a question.
            - Do not mention that this is a test.
            """

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "user", "content": prompt}
        ],
        temperature=0.3
    )

    return response.choices[0].message.content.strip()


# Identify the department from the final incident message.
def get_actual_route(response):
    response_lower = response.lower()

    if "cybersecurity department" in response_lower:
        return "Cybersecurity"

    if "it department" in response_lower:
        return "IT"

    return "Unknown"


# Run one complete triage workflow.
def run_workflow(workflow, workflow_number):

    persona = workflow["Persona"]
    expected_outcome = workflow["Expected Outcome"]

    # Each incident gets its own session.
    session_id = f"ai_triage_{workflow_number}"

    scenario = generate_scenario(
        persona,
        expected_outcome
    )

    topic = scenario["topic"]
    initial_message = scenario["message"]

    conversation = []

    current_user_message = initial_message

    incident_created = False
    actual_route = "Unknown"
    final_response = ""

    for turn in range(MAX_TURNS):

        bot_response = send_message(
            current_user_message,
            session_id
        )

        conversation.append(
            f"User: {current_user_message}\n"
            f"Bot: {bot_response}"
        )

        # Stop if an API/server error occurs.
        if bot_response.startswith("[ERROR]"):
            final_response = bot_response
            break

        bot_lower = bot_response.lower()
                
        # For a No Incident scenario, a normal answer without
        # incident creation is the expected behaviour.
        if expected_outcome == "No Incident":
            final_response = bot_response
            break

        # Incident has been successfully created.
        if (
            "incident has been successfully created"
            in bot_lower
        ):
            incident_created = True
            actual_route = get_actual_route(
                bot_response
            )
            final_response = bot_response
            break

        # The chatbot is asking for confirmation.
        if (
            "would you like me to create an incident"
            in bot_lower
            or "reply yes or no" in bot_lower
        ):
            current_user_message = "YES"

        else:
            # AI acts as the employee and answers
            # the chatbot's follow-up question.
            current_user_message = (
                generate_employee_reply(
                    persona,
                    initial_message,
                    bot_response
                )
            )

        time.sleep(5)

    # Work out whether the workflow passed.
    if expected_outcome == "No Incident":

        if not incident_created:
            actual_outcome = "No Incident"
            result = "Pass"
        else:
            actual_outcome = actual_route
            result = "Fail"

    else:

        actual_outcome = actual_route

        if (
            incident_created
            and actual_route == expected_outcome
        ):
            result = "Pass"
        else:
            result = "Fail"

    return {
        "Persona": persona,
        "Topic": topic,
        "Initial Message": initial_message,
        "Expected Outcome": expected_outcome,
        "Full Conversation": "\n\n".join(conversation),
        "Incident Created": (
            "Yes" if incident_created else "No"
        ),
        "Actual Outcome": actual_outcome,
        "Result": result
    }


# Run all eight workflows.
def main():
    results = []

    for index, workflow in enumerate(
        TEST_WORKFLOWS,
        start=1
    ):

        print(
            f"Running workflow {index}/{len(TEST_WORKFLOWS)}: "
            f"{workflow['Persona']} - "
            f"{workflow['Expected Outcome']}"
        )

        result = run_workflow(
            workflow,
            index
        )

        results.append(result)

        print(
            f"Completed: {result['Result']}"
        )

        # Give the APIs a short break.
        time.sleep(10)

    df = pd.DataFrame(results)

    df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print(
        "AI triage testing complete.",
        len(results),
        "workflows saved to",
        OUTPUT_FILE
    )


if __name__ == "__main__":
    main()