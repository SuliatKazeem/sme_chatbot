# SME Security Chatbot

Hey! Welcome to the readme for my little project which is a chatbot that helps SMEs with security queries, incident reporting, and VirusTotal scans. This document will walk you through what is used, how the pieces fit together, and how to get it running. 


## Introduction

Small and medium businesses often don’t have a big security team, so this chatbot is meant to be the first line of defense, answering questions about best practices, scanning email files for suspicious activities, checking URLs/domains with VirusTotal.
---

## Files in the repository

1. **`Frontend.html`**

   - A single page UI that loads in your browser at `http://localhost:8000/`. The plan is to integrate the bot into Microsoft Teams app.
   - The front-end of the chatbot system was built and designed in HTML, JavaScript, and CSS.
   - Renders messages as Markdown (thanks to [marked.js](https://github.com/markedjs/marked)).
   - Buttons for “Add Email File” (.eml upload) and “Generate Incident Report” fallback.

2. **`Main.py`** (FastAPI server)

   * Serves the (`frontend.html`).
   * Handles `/chat` POST requests:

     * Tries to parse pasted raw email text or inline URLs/HTML via our `virustotal.parse_email`, but advises to upload an `.eml` file for deep scanning.
     * Scans any found URLs, domains, and attachments with VirusTotal APIs.
     * If nothing email-related is found, hands the query off to the LLM.
     * Implements a “three strikes” rule: certain kinds of refusals (like internal-domain scans or out-of-scope questions) get counted, and after 3 you get a warning message.

   * Handles `/scan-email-file` POST:

     * Accepts a `.eml` upload, parses it fully, and returns a nice numbered report of URLs, domains, and attachments with verdicts.

3. **`Smeopenai.py`**

   * Wraps OpenAI + LangChain for our “fallback” chat logic.
   * Loads your `OPENAI_API_KEY` and sets up:

     * A moderation check (to catch nasty inputs).
     * A prompt template to keep the bot focused on SME security topics.
     * A rotating set of refusal templates, each prefixed with `[REFUSAL] ` so the main server can detect and count them.

4. **`Virustotal.py`**

   * Contains helper functions to talk to VirusTotal’s REST API:

     * `scan_url(url)` → verdict
     * `scan_domain(domain)` → verdict
     * `scan_file_attachment(filename, bytes)` → verdict
   * Also a little email parser (`parse_email`) that extracts:

     * Plain-text and HTML links
     * Domains
     * Attachments

---

## How to set it up

1. **Clone & install**

    ```bash
   git clone https://github.com/SuliatKazeem/sme_chatbot.git
   cd sme_chatbot
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Create a `.env` file**

   ```env
   OPENAI_API_KEY= **enter your API Key**
   VT_API_KEY= **enter your API Key**
   INTERNAL_DOMAINS= rxtra.xyz (you can enter your personalized domain)
   ```

  #INTERNAL_DOMAINS: these are domains that the bot will refuse to scan.

3. **Run the server**

   ```bash
   uvicorn main:app --reload
   ```

   Then open your browser at [http://127.0.0.1:8000](http://127.0.0.1:8000).

---

## Working Principle

1. **User sends a query**

   * If the text literally contains “scan an email”, we shortcut into instructions for uploading a `.eml`.
   * Otherwise we try to detect any raw email content or links.

2. **VirusTotal checks**

   * Extracted URLs & domains get sent off to VT and verdicts come back.
   * If attachments are embedded in the .eml, we upload them too.

3. **LLM fallback**

   * If no URLs/domains/attachments found, we call out to `smeopenai.ask_openai()`.
   * That function first runs the text through a moderation endpoint.
   * If it’s okay, it invokes a LangChain conversation with memory.

4. **Refusals & Three-strike**

   * Any refusal from `ask_openai` begins with a rephrased refusal template.
   * The server strips that tag, counts it, and once you hit 3 total refusals it sends you a friendly warning.

---

## Tools Used

* **FastAPI + Uvicorn**: easy async Python web server.
* **marked.js**: client-side Markdown rendering, so we can send bullet lists, numbered steps, etc.
* **OpenAI + LangChain**: gives us memory, nice templating, and a robust way to manage prompts & refusals.
* **VirusTotal API**: known reputation checks for links, domains, and files—perfect for a lightweight security bot.
* **python-dotenv**: keep secrets out of your code and in `.env`.

---

## To be updated

* Build a **Teams** connector so you can plug this into your actual SME chat platform.
* Store logs of refused queries in a database and send real tickets to IT.
* Enhance the LLM prompt to handle more nuanced follow-up questions, maybe even triage severity levels.

---

Thank you for reading. Enjoy coding and tweaking!