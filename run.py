"""
ScamShield AI - Application Server Launcher
Run with: python run.py
"""

import sys
from backend.app import app
from backend.config import Config

if __name__ == "__main__":
    print("=" * 60)
    print("[INFO] Starting ScamShield AI Backend Server")
    print(f"Local Server: http://{Config.HOST}:{Config.PORT}")
    print(f"REST API endpoint: http://{Config.HOST}:{Config.PORT}/api/scan/url")
    print(f"SQLite DB path: {Config.DATABASE_PATH}")
    print("=" * 60)
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
