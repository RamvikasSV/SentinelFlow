# 🛡️ SentinelFlow: Complete Step-by-Step Developer Guide

Welcome! This guide is designed to help you thoroughly understand **SentinelFlow**—even if you don't work with cybersecurity or agentic AI systems daily. 

Use this handbook to learn how the system works, understand the security terms, navigate the files, and confidently explain the project step-by-step during demos or interviews.

---

## 🧭 Part 1: The Cybersecurity Basics (In Plain English)
Before looking at the code, here are the security threats we are defending against:

### 1. SSH Brute Force Attack
* **What it is**: An attacker tries to log into your server by repeatedly guessing common usernames (like `admin`, `root`) and passwords (like `password123`). 
* **Analogy**: Imagine a thief trying 1,000 different keys on your front door lock in under a minute.
* **How we detect it**: We read the server's authentication logs (`/var/log/auth.log`). Every time someone fails to log in, it leaves a record. If we see 3 or more failures from the same IP address in a short time, we flag it.

### 2. Web Shell Upload & Reverse Shell Attack
* **What it is**: 
  * A **Web Shell** is a malicious script (like a `.php` file) an attacker uploads to your website folder. It allows them to run terminal commands on your server through a browser window.
  * A **Reverse Shell** is a command run by that web shell that forces your server to connect back to the attacker's computer, giving them complete remote terminal control.
* **Analogy**: Imagine an intruder sneaking into your house and installing a secret backdoor that stays unlocked so they can enter whenever they want.
* **How we detect it**: We scan Nginx/Apache logs for exploits (like reading `/etc/passwd`), monitor filesystem changes for uploaded scripts (like `backdoor.php`), and audit the process tree to see if the web server user (`www-data`) is running terminal sessions (like `sh` or `bash`).

### 3. Host Firewall (`iptables` / `ufw`)
* **What it is**: The system software that decides which network traffic is allowed to enter or leave your server.
* **Analogy**: A bouncer standing at the door of a club, checking IDs and turning away banned guests.
* **How we use it**: When our agents confirm an attacker IP, they add a `DROP` rule to the firewall, completely blocking that IP from connecting to the server.

---

## 🤖 Part 2: The Agent Crew & Their Roles
SentinelFlow uses a team of **7 specialized agents**. Instead of one giant script, each agent acts like a person with a specific job in a Security Operations Center:

```
[Log Scanner] ──(Alert)──> [Threat Classifier] ──(High Severity)──> [Forensics Agent]
                                                                          │
                                                                   (Evidence Report)
                                                                          ▼
[Forensic Notifier] <──(Email PDF)── [Response Agent] <───────────────────┘
```

1. **Log Scanner Agent (The Sentinel)**
   * *Job*: Asynchronously reads the end of server log files in real-time.
   * *Logic*: Scans for words like "Failed password" or `/etc/passwd`.

2. **Threat Classifier Agent (The Analyst)**
   * *Job*: Looks at the alerts flagged by the Scanner and determines how dangerous they are.
   * *Logic*: Uses a Gemini LLM (or a local rules engine fallback) to classify the threat into a category (e.g., *Reconnaissance*, *Web Exploit*, *False Positive*) and assigns a severity grade (*Low*, *Medium*, *High*, *Critical*).

3. **Forensic Investigator Agent (The Detective)**
   * *Job*: Runs deep diagnostics on the server once a high-severity threat is classified.
   * *Logic*: Looks up the attacker's physical location (GeoIP) and crawls the server's OS to see:
     * Are there active network connections coming from the attacker? (`ss` commands)
     * Are there suspicious processes running? (`ps` commands)
     * Were any critical files recently modified? (`find` commands)

4. **Response Agent (The Guard)**
   * *Job*: Executes defensive actions to neutralize the threat based on the Forensic Agent's report.
   * *Logic*: Blocks the attacker's IP in the firewall, terminates malicious process IDs (PIDs), and deletes/quarantines uploaded backdoors.

5. **Watchdog Filesystem Agent (The Patrol Guard)**
   * *Job*: Monitors critical system directories (like temp folders or startup registries) for malware files.
   * *Logic*: If it detects a file with a suspicious extension or containing malware indicators, it immediately flags it to the Classifier.

6. **Forensic Notifier Agent (The Reporter)**
   * *Job*: Emails detailed PDF reports to system administrators.
   * *Logic*: If the Response Agent successfully resolves a **High** or **Critical** incident, the Notifier generates a clean PDF report containing the GeoIP map, details of the block, and processes terminated, then emails it.

7. **Crew Coordinator Agent (The Operator)**
   * *Job*: Serves as the conversational interface between the system and the human administrator.
   * *Logic*: Manages the chat terminal on the dashboard, taking natural language queries (like *"Show status"* or *"List blocked IPs"*) and translating them into backend commands.

---

## ⚙️ Part 3: Architecture Keys (Great for Interviews!)
If you are presenting this project, make sure to highlight these **three design patterns**:

### 1. Asynchronous Pub/Sub Event Broker
* **The Concept**: Agents do not talk directly to one another. Instead, they write messages (events) to a central bulletin board (`broker.py`), and other agents read them from there.
* **Why it's crucial**: Scale. If the **Log Scanner** had to wait for the **Classifier's** LLM API call to finish before scanning the next log line, a fast-moving attack would overwhelm the server. By using a Broker queue, the Scanner can tail logs at lightning speed without being blocked by AI processing.

### 2. The Adapter Pattern
* **The Concept**: The agents don't run commands directly on the host OS. Instead, they talk to a middleman class (`ServerAdapter`).
* **Why it's crucial**: It allows SentinelFlow to run in **Simulation Mode** (generating fake logs and mock states so you can run it on Windows/Mac for quick demos) OR **Live Mode** (where it uses SSH to connect and run real commands on an Ubuntu server).

### 3. Notification Registry & Debouncing
* **Registry**: Admin emails are stored in a persistent JSON database (`registered_users.json`) so your server configuration remains decoupled from the notifications database.
* **Debouncing**: In a real attack, multiple alerts hit within seconds. To prevent spamming your inbox, the Notifier caches sent alerts and blocks duplicate emails for the same IP within a 30-second window.

---

## 📂 Part 4: File Directory Map
Here is where all the critical logic lives in your project:

```text
cyber agent/
│
├── backend/
│   ├── agents/
│   │   ├── scanner.py          # Tails auth.log and access.log
│   │   ├── classifier.py       # Interacts with Gemini API / heuristics
│   │   ├── forensics.py        # Gathers active processes/sockets/GeoIP
│   │   ├── response.py         # Blocks IPs, kills processes, deletes shells
│   │   ├── watchdog_agent.py   # Watches folders for malware filenames
│   │   └── coordinator.py      # Translates chat commands to system actions
│   │
│   ├── main.py                 # FastAPI server, WebSockets & REST routes
│   ├── config.py               # Loads settings from .env file
│   ├── broker.py               # Pub/sub event broker queue
│   ├── notifier.py             # Generates PDF reports & sends SMTP emails
│   ├── user_registry.py        # Manages registered admin emails database
│   └── registered_users.json   # Saved database file of recipient emails
│
├── frontend/
│   ├── index.html              # Dashboard tab layouts & embedded chat
│   ├── styles.css              # Custom neon glassmorphism CSS
│   └── app.js                  # WebSocket handler & UI state controller
│
└── .env                        # Configuration (Gemini keys, SMTP password)
```

---

## 🗣️ Part 5: Step-by-Step Project Explanation Script
When explaining the project to an interviewer or colleague, you can follow this exact sequence:

1. **The Problem Statement**:
   > *"When a server gets attacked, human response times average hours. SentinelFlow solves this by combining specialized AI agents with an event-driven loop to reduce detection, forensic investigation, and firewall containment times from hours to under 3 seconds."*

2. **The Demo Walkthrough**:
   > *"Here is the dashboard. On the left column, we tail live log files. The middle column has our control tab panel and our Command Console. The right column has our Agent Cognitive Pipeline visualizer and thinking log.*
   >
   > *When I click 'SSH Brute Force', a stream of failed logins enters the log terminal. Instantly, our Log Scanner flags the anomaly. The Threat Classifier notes the frequency and rates the severity as High.*
   >
   > *This dispatches our Forensic Investigator, which performs a GeoIP trace—locating the attacker in Germany—and scans active processes and network sockets. It forwards these details to the Response Agent, which dynamically adds a firewall block rule.*
   >
   > *Once mitigated, the Forensic Notifier automatically drafts a styled PDF report and emails it to all registered administrators in our database registry."*

3. **The Engineering highlights**:
   > *"Architecturally, this is built on top of FastAPI and Python Asyncio using a Pub/Sub event broker. This decouples our scanning agents from our AI classification agents, making the pipeline highly scalable. It also implements the Adapter Pattern so it can seamlessly toggle between a safe offline simulation environment and a live SSH production server."*
