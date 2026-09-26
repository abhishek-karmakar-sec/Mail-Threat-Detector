# 🛡️ CYBERCOP // Threat Intelligence & Forensic Platform

> Automated email threat monitoring, deep heuristic analysis, and digital forensics workstation designed for high-end Security Operations Centers (SOC).

---

## 🚀 Core Features
* **Forensic Ingestion Hub:** Deep parsing of raw RFC822 `.eml` payloads, headers, and routing paths.
* **Heuristic & AI Scoring:** Real-time threat matrix assessment, signature matching, and Deep Neural Net (DNN) phishing confidence scoring.
* **Sandbox Detonation:** Automated isolation and execution telemetry for suspicious attachments.
* **Immutable Chain of Custody:** Cryptographic SHA-256 evidence logging appended to a local ledger.
* **Courtroom-Ready Reports:** Generates dark-themed, highly detailed PDF forensic reports mirroring the application UI.
* **Cinematic Interface:** Built with a deep-slate cyberpunk aesthetic, ultra-transparent glassmorphism, and a looping 3D fluid video background.

---

## 💻 Tech Stack
* **Backend:** Python, Flask
* **Frontend:** Tailwind CSS, Alpine.js, HTML5/CSS3
* **Reporting Engine:** ReportLab
* **Deployment:** Docker, Google Cloud Run

---

## 🛠️ Project Structure
```text
PROJECT/
├── app.py                  # Main Flask application and routing logic
├── report_generator.py     # Forensic PDF report compiler
├── templates/
│   └── index.html          # Glassmorphic SOC frontend dashboard
├── static/
│   └── videos/
│       └── background-fluid.mp4 # 3D background animation asset
└── uploads/                # Isolated payload ingestion directory
