# SME Security Chatbot
This project was developed as part of my MSc Computer Science (Cybersecurity) project. It is an AI-powered cybersecurity chatbot designed to support SMEs with security-related queries, suspicious email and URL scanning, and incident reporting.

This README provides an overview of the project, the main files included in the repository, how the different components work together, and how to run the chatbot.

## Introduction
Small and medium-sized businesses may not always have large dedicated cybersecurity teams. The aim of this chatbot is to provide users with a first point of support for common security queries while also helping them identify and report potential security incidents.

The chatbot can answer security-related questions, provide organisation-specific guidance, scan suspicious URLs, domains and email files using VirusTotal, and generate incident reports when required.

The system uses an LLM for its conversational functionality, with additional security controls implemented around it to reduce some of the risks associated with using LLMs in an enterprise environment.


## Files in the Repository

### 1. `frontend.html`

This contains the main user interface for the chatbot.

The frontend was developed using HTML, CSS and JavaScript and includes:

- The main chat interface
- FAQ questions
- New Chat functionality
- Email file upload
- Manual incident reporting
- Markdown rendering of chatbot responses
- Communication with the FastAPI backend

The interface was also adapted for deployment through Microsoft Teams.


### 2. `main.py`

This is the main FastAPI server and connects the different parts of the application together.

It:

- Serves the chatbot frontend
- Handles `/chat` requests
- Detects URLs and domains included in user queries
- Coordinates VirusTotal scanning
- Handles uploaded `.eml` files
- Applies internal-domain restrictions
- Handles incident triage
- Generates automatic incidents for malicious, suspicious or unverified indicators
- Handles manual incident reporting
- Applies personal information redaction
- Uses response caching for repeated queries
- Communicates with the LLM through `smeopenai.py`


### 3. `smeopenai.py`

This file handles the LLM side of the chatbot.

It contains:

- OpenAI and LangChain configuration
- The main system prompt
- Organisation-specific security guidance
- Conversation memory
- Topic classification
- Refusal handling
- OpenAI moderation

The system prompt is used to keep the chatbot focused on cybersecurity and organisation-specific policies rather than allowing unrestricted responses.


### 4. `virustotal.py`

This file handles communication with the VirusTotal API.

It contains functions for:

- Scanning URLs
- Scanning domains
- Scanning email attachments
- Parsing `.eml` files
- Extracting links and domains from email content
- Extracting email attachments

The application waits for VirusTotal analysis to complete before returning a verdict. Results can be returned as safe, suspicious, malicious or unable to be verified.


### 5. `pdf_generation.py`

This file generates PDF incident reports.

Each generated report contains an incident ID and relevant information about the incident. Depending on how the incident was created, this can include the incident details or relevant conversation information.


### 6. `notifypdf.py`

This file records VirusTotal-related incidents in Azure Blob Storage.

A CSV file is maintained in Azure and new incidents are appended to it. This provides a record of automatically generated incidents without storing the CSV locally.


### 7. `incident_form.html`

This contains the manual incident reporting form.

The user provides a title and description of the problem. The information is sent to the backend, where the incident is classified and routed to either IT or Cybersecurity.


### 8. `requirements.txt`

This contains the Python packages required to run the project.


## How to Set It Up

### 1. Install the requirements

From the project directory, run:

    pip install -r requirements.txt


### 2. Create a `.env` file

The application requires environment variables for the external services used by the chatbot.

For example:

    OPENAI_API_KEY=your_openai_api_key
    VT_API_KEY=your_virustotal_api_key
    AZURE_STORAGE_CONNECTION_STRING=your_azure_storage_connection_string
    INTERNAL_DOMAINS=your_internal_domain

`INTERNAL_DOMAINS` contains organisational domains that should not be submitted to VirusTotal.

Actual API keys and connection strings are not included in this repository or corpus for security reasons.


### 3. Run the server

Run:

    uvicorn main:app --reload

The local version of the chatbot can then be opened at:

    http://127.0.0.1:8000


## How the Chatbot Works

### 1. User sends a query

The user enters a security-related question through the chatbot interface.

If the message contains a URL or domain that requires checking, the application can send the indicator to VirusTotal. For suspicious emails, the user can also upload the original `.eml` file for a more complete scan.


### 2. VirusTotal scanning

URLs, domains and email attachments are checked using the VirusTotal API.

If an indicator is identified as malicious or suspicious, the chatbot warns the user and an incident can be generated automatically.

Indicators that cannot be verified are also treated cautiously rather than automatically being considered safe.


### 3. LLM response

If the request does not require VirusTotal scanning or incident handling, it is passed to the LLM through `smeopenai.py`.

The input is checked using moderation and the chatbot uses its system prompt and organisation-specific guidance when generating the response.

Conversation memory allows the chatbot to understand follow-up questions within the same session.


### 4. Incident Reporting

The chatbot supports both automatic and manual incident reporting.

Automatic incidents can be generated following malicious, suspicious or unverified VirusTotal results.

Users can also manually report an issue using the incident form.

Incidents are classified as either IT or Cybersecurity depending on the nature of the issue.


### 5. Incident Storage

Incident information is stored using Azure Blob Storage.

Individual incident records can be stored separately, while VirusTotal-related incidents are also appended to a CSV file.

PDF reports are generated where required so that the incident information can also be provided in a readable report format.


## Security Controls

Because the chatbot uses an LLM and external services, several security controls were added rather than relying only on the language model.

These include:

- Prompt engineering and organisation-specific system prompts
- OpenAI moderation
- VirusTotal threat intelligence
- Internal-domain restrictions
- Input validation
- Personal information redaction
- Incident confirmation workflows
- Restricted chatbot scope
- Response caching
- Conversation and refusal handling

These controls provide different layers of protection around the chatbot and its external integrations.


## Tools Used

- **FastAPI and Uvicorn** – backend API and web server
- **OpenAI and LangChain** – conversational AI, prompts and conversation memory
- **VirusTotal API** – URL, domain and file reputation checks
- **Azure Blob Storage** – storage of incident information
- **ReportLab** – generation of PDF incident reports
- **BeautifulSoup** – extraction of links from HTML email content
- **python-dotenv** – loading environment variables
- **HTML, CSS and JavaScript** – chatbot frontend
- **marked.js** – rendering Markdown responses
- **Microsoft Teams** – deployment platform


## Testing

The chatbot was tested throughout development using both manual and automated testing.

Manual testing was used to test individual functions and realistic user scenarios, including security questions, phishing emails, URL scanning, incident reporting, moderation and refusal behaviour.

Automated tests were also used to run predefined questions against the chatbot and record the results consistently.

The manual and automated testing files are included separately in the project corpus.


## Known Limitations

This chatbot is a research prototype and is not intended to replace professional IT or Cybersecurity staff.

VirusTotal results depend on the information available to VirusTotal, so a safe result cannot guarantee that an indicator is harmless. Similarly, an indicator that cannot be verified is treated cautiously and may require manual investigation.

LLM-generated responses can also be inaccurate or inconsistent. The additional controls implemented in this project are intended to reduce these risks but cannot eliminate them completely.

The organisation-specific policies used by the chatbot were created for this research project and would need to be replaced with the policies of the organisation using the system in a real deployment.


## Corpus

The project corpus contains the final source code, manual and automated testing evidence, and supporting documentation.

API keys, passwords, Azure connection strings and other credentials have been excluded for security reasons.