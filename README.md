# SentinelX IDS

> An AI-powered, full-stack Intrusion Detection System with real-time alerting, threat intelligence, audit logging, and a beautiful React dashboard.
SentinelX is a full-stack intrusion detection system for collecting and parsing security events, matching them against detection rules, enriching indicators, and presenting alerts in a web dashboard. The project includes a FastAPI backend, a React frontend, a local SQLite database, and optional integrations for notifications and AI-assisted analysis.

![Python](https://img.shields.io/badge/Python-3.12+-blue?style=flat-square&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi)
![React](https://img.shields.io/badge/React-18-61dafb?style=flat-square&logo=react)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
> **Development/demo software:** the default configuration enables simulated events and creates a demo administrator. Do not expose a default-configured instance to an untrusted network or use it as a production security control without reviewing and hardening it first.

---
## Features

## ✨ Features
- **Event collection and parsing:** demo event generator and configurable file watcher; parsers for Syslog, Windows, firewall, web, and Suricata logs.
- **Rule-based detection:** YAML detection rules, event correlation, and anomaly scoring.
- **Alert investigation:** searchable alerts, severity and risk information, status updates, and MITRE ATT&CK context.
- **Threat intelligence:** indicator storage and enrichment, feed synchronization, and GeoIP-related context.
- **Live dashboard:** React interface with WebSocket updates for events and alerts.
- **SOC utilities:** audit trail, system health, and investigation workflows.
- **Optional integrations:** Slack, Discord, and SMTP notifications; AI assistant providers can be configured in `.env`.

| Module | Description |
|--------|-------------|
| 🔍 **Detection Engine** | 8 built-in YAML rules (brute force, port scan, lateral movement, reverse shell, data exfiltration, persistence, privilege escalation, PowerShell) |
| 📊 **Live Dashboard** | Real-time WebSocket feed, severity charts, top source IPs, MITRE heatmap |
| 🚨 **Alert Management** | Paginated alerts with MITRE ATT&CK mapping, status workflow, risk scoring |
| 📜 **Log Viewer** | Live log stream from 5 parsers: Syslog, Windows, Firewall, Web, Suricata |
| 🌐 **Threat Intelligence** | IOC database with 5 auto-synced open-source feeds (Feodo, ET, CINS, URLhaus, ThreatFox), IP/domain/hash enrichment, GeoIP |
| 🤖 **AI Copilot** | SOC analyst assistant — alert analysis, remediation steps, attack explanation (supports OpenAI, Anthropic, Gemini, local LLM) |
| 🔔 **Alert Notifications** | Slack (Block Kit), Discord (embeds), Email (HTML) with severity filtering and rate limiting |
| 📋 **Audit Log** | Immutable trail of every user action — login, alert updates, IP blocks, IOC changes, and more |
| 🔐 **JWT Auth** | Role-based access control: Admin / Analyst / Viewer |
| 🏥 **System Health** | Real-time CPU, memory, disk, and service status |
## Requirements

---
- Python **3.12 or newer**
- Node.js **18 or newer** and npm
- Git

## 🚀 Quick Start
## Quick start

### Prerequisites

- **Python 3.12+**
- **Node.js 18+**

### 1. Clone & setup
### 1. Get the source and configure the backend

```bash
git clone https://github.com/Pranav-Anshu-Pathak/sentinelx-ids.git
git clone https://github.com/Sayan-Ghosh-5/sentinelx-ids.git
cd sentinelx-ids
python -m venv .venv
```

### 2. Backend
Activate the virtual environment, then install dependencies and create your local configuration:

**Linux / macOS**

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
```

# Activate (Windows)
.venv\Scripts\activate
**Windows PowerShell**

# Install dependencies
pip install -r requirements.txt
```powershell
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

# Copy environment config
cp .env.example .env
### 2. Start the backend

From the repository root, with the virtual environment active:

# Start backend
```bash
python -m backend.main
```

### 3. Frontend
On startup, the backend initializes the database and seeds the demo administrator, bundled rules, and sample threat-intelligence indicators. The default database is `sentinelx.db` in the working directory.

### 3. Start the frontend

Open another terminal, change into `frontend`, and run:

```bash
cd frontend
npm install
npm run dev
```

### 4. Open the app
The Vite development server proxies `/api` and `/ws` requests to the backend at `http://localhost:8000`.

| Service | URL |
|---------|-----|
| **Dashboard UI** | http://localhost:5173 |
| **API** | http://localhost:8000 |
| **API Docs** | http://localhost:8000/docs |
### 4. Open SentinelX

### Demo Login
| Service | Address |
| --- | --- |
| Web dashboard | <http://localhost:5173> |
| API | <http://localhost:8000> |
| Interactive API docs | <http://localhost:8000/docs> |
| API schema | <http://localhost:8000/openapi.json> |

| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `sentinelx` |
In demo mode, sign in with **admin** / **sentinelx**. Change the default credentials and secret key before using the application beyond a local demo.

---
### Windows helper scripts

## ⚙️ Configuration
The repository also includes `start.ps1`, which opens backend and frontend terminals. Run it from PowerShell in the repository root. The backend helper creates `.env` from `.env.example` if needed; the frontend helper installs npm packages if `node_modules` is absent.

Copy `.env.example` to `.env` and configure:
## Configuration

```env
# Demo mode — generates synthetic security events automatically
DEMO_MODE=true
Copy `.env.example` to `.env` and edit the settings you need. The default setup uses SQLite and local/demo functionality; external credentials are optional.

# Alert Notifications (optional)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
SMTP_HOST=smtp.gmail.com
SMTP_USER=you@gmail.com
SMTP_PASSWORD=your-app-password
ALERT_EMAIL_TO=team@yourcompany.com
Common settings include:

# Threat Intelligence API Keys (optional — enhances scoring)
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
| Setting | Purpose |
| --- | --- |
| `DATABASE_URL` | Database connection; defaults to local SQLite (`sqlite+aiosqlite:///./sentinelx.db`). |
| `SECRET_KEY` | JWT signing key. Replace the example value with a strong, unique secret. |
| `DEMO_MODE` | Enables demo-mode behavior and synthetic events. |
| `CORS_ORIGINS` | Comma-separated allowed frontend origins. |
| `LLM_PROVIDER` | AI provider selection (`local`, `openai`, `anthropic`, or `gemini`). |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY` | Optional provider credentials. |
| `SLACK_WEBHOOK_URL`, `DISCORD_WEBHOOK_URL` | Optional notification webhooks. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD` | Optional email delivery configuration. |
| `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY` | Optional threat-intelligence service credentials. |

# AI / LLM (optional)
LLM_PROVIDER=local        # or openai / anthropic / gemini
OPENAI_API_KEY=
```
Keep `.env` private and never commit real credentials. The values in `.env.example` are examples, not production secrets.

---
## Run tests

## 🏗️ Architecture
Install dependencies from `requirements.txt`, then run the Python test suite from the repository root:

```bash
python -m pytest
```
sentinelx-ids/
├── backend/              # FastAPI app — 61 REST endpoints
│   ├── routes/           # alert, auth, rule, intel, audit, notification...
│   ├── models.py         # SQLAlchemy ORM (7 tables)
│   ├── pipeline.py       # Event → alert → notify pipeline
│   └── audit.py          # Immutable audit logger
├── frontend/             # React 18 + Vite + Framer Motion
│   └── src/pages/        # 10 pages: Dashboard, Alerts, Logs, Rules,
│                         #   Threat Intel, Investigations, Audit Log,
│                         #   Settings, Health, Login
├── detection_engine/     # YAML rule matching (Sigma-like)
├── threat_intel/         # IOC feeds, GeoIP, enrichment, scoring
├── alerts/               # Slack / Discord / Email notifier
├── ai_engine/            # LLM copilot integration
├── parsers/              # Syslog, Windows, Firewall, Web, Suricata
├── collectors/           # Demo log generator + file watcher
└── websocket/            # Real-time event broadcasting
```

---

## 🔌 API Reference

Full interactive docs available at **http://localhost:8000/docs**

Key endpoint groups:
On Windows, if the environment is not activated:

| Prefix | Description |
|--------|-------------|
| `/api/auth` | Login, register, user profile |
| `/api/alerts` | CRUD + stats + filters |
| `/api/logs` | Log search + stream |
| `/api/rules` | Detection rule management |
| `/api/intel` | Threat intel lookup, IOC database, feeds, GeoIP |
| `/api/audit` | Audit log query + statistics |
| `/api/notifications` | Channel config, test, history |
| `/api/copilot` | AI chat + alert analysis |
| `/api/dashboard` | Aggregated dashboard stats |
| `/api/health` | System health metrics |

---

## 🧰 Tech Stack

**Backend:** Python 3.12 · FastAPI · SQLAlchemy (async) · SQLite · aiosqlite · JWT · bcrypt · httpx

**Frontend:** React 18 · Vite · Framer Motion · Recharts · Lucide Icons · React Router
```powershell
.venv\Scripts\python -m pytest
```

**Detection:** YAML rules · Regex + keyword matching · Anomaly scoring
## Project structure

```text
.
├── ai_engine/          # AI assistant, query parsing, and anomaly scoring
├── alerts/             # Notification formatting, dispatch, and rate limiting
├── backend/            # FastAPI app, database, auth, services, and API routes
├── collectors/         # Demo event generator and file watcher
├── detection_engine/   # Rule loading, matching, and event correlation
├── frontend/           # React + Vite dashboard
├── parsers/            # Syslog, Windows, firewall, web, and Suricata parsers
├── rules/              # Bundled YAML detection rules
├── tests/              # Backend and component-level Python tests
├── threat_intel/       # IOC feeds, enrichment, GeoIP, and scoring
└── websocket/          # WebSocket connection manager
```

**Integrations:** Slack · Discord · SMTP · AbuseIPDB · VirusTotal · ip-api.com (GeoIP) · OpenAI / Anthropic / Gemini
## API overview

---
The API is mounted under `/api`. It includes route groups for authentication, alerts, audit events, dashboard data, health, threat intelligence, investigations, logs, notifications, rules, search, and AI features. Browse the interactive docs at <http://localhost:8000/docs> while the backend is running.

## 📄 License
## License

MIT — free to use, modify, and distribute.
This project is distributed under the MIT License. See [LICENSE](LICENSE).