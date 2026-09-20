# 🛡️ ScamShield AI - Full-Stack Scam Website & SMS Fraud Radar

**ScamShield AI** is an advanced cyber-threat intelligence web application backed by a dedicated **Python Flask Backend**, connecting directly to real threat intelligence APIs (**URLhaus by abuse.ch** and **Google Gemini AI**) alongside a 25+ point heuristic inspection engine.

---

## 🌟 Architecture & Detection Layers

```
[ Frontend: HTML5 / CSS3 / JavaScript ]
                   │
           HTTP REST API Calls
   (POST /api/scan/url  |  POST /api/scan/sms)
                   ▼
[ Python Flask Backend Server (backend/app.py) ]
       │                               │
       ├──► 1. Python Heuristics       ├──► 2. URLhaus API (abuse.ch)
       │    - Typosquatting / Leet     │    - Real-time active malware
       │    - Suspicious TLDs          │      and phishing feed query
       │    - Raw IP Hostnames         │
       │    - SMS Urgency & OTPs       ├──► 3. Google Gemini AI API
       │                               │    - Deep social engineering
       │                               │      and pretexting evaluation
       ▼                               ▼
[ SQLite Database (scans.db) ] ◄───────┘
```

---

## 📁 Project Structure

```
scam-shield/
├── backend/
│   ├── app.py              # Main Flask REST API & static server
│   ├── api_service.py      # Real API caller (URLhaus Threat DB & Gemini AI)
│   ├── detector.py         # Server-side heuristic & smishing engine
│   ├── storage.py          # SQLite persistent database manager
│   ├── config.py           # Server configuration & threat dictionaries
│   └── scans.db            # Persistent SQLite database file
├── css/
│   └── styles.css          # Cyber dark/light theme, gauge animations
├── js/
│   ├── app.js              # Frontend controller (calls Python backend API)
│   ├── api.js              # Client fallback API handler
│   ├── heuristic.js        # Client fallback heuristic engine
│   ├── samples.js          # Curated real-world test cases
│   └── config.js           # Client-side configuration
├── run.py                  # One-command backend launcher
├── requirements.txt        # Python dependencies (flask, flask-cors, requests, python-dotenv)
├── test_backend.py         # Automated verification test suite
├── index.html              # Frontend single-page application
└── README.md               # Documentation
```

---

## 🚀 How to Run the Full-Stack Application

### 1. Install Dependencies
```powershell
cd C:\Users\nihar\.gemini\antigravity\scratch\scam-shield
python -m pip install -r requirements.txt
```

### 2. Start the Python Backend Server
```powershell
python run.py
```
This launches the Flask server at:
👉 **`http://127.0.0.1:5000`**

Open `http://127.0.0.1:5000` in your web browser. The frontend and backend will be seamlessly connected!

---

## 🔑 Attaching Google Gemini AI API (Optional)

1. Obtain a free Gemini API key from [Google AI Studio](https://aistudio.google.com/app/apikey).
2. You can configure it either:
   - **On the Server**: Add `GEMINI_API_KEY=your_key_here` to a `.env` file in the project directory.
   - **In the UI**: Click **⚙️ API Settings** in the top right corner of the website and paste your key.
3. Once attached, all scans utilize Gemini AI for deep semantic reasoning!

---

## 🧪 Testing

To run the automated backend test suite:
```powershell
python test_backend.py
```
All tests should pass with 100% success.
