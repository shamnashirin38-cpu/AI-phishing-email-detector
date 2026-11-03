"""
Entry point to run the AI-Powered Phishing Email Detection System Flask server.
"""

import os
import sys

# Ensure UTF-8 output on Windows terminals
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from app import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "True").lower() in ["true", "1", "yes"]
    print("=" * 65)
    print(" [*] AI-POWERED PHISHING EMAIL DETECTION SYSTEM")
    print(f" [*] Local Web Server: http://127.0.0.1:{port}")
    print(f" [*] Ollama Configured Model: {app.config.get('OLLAMA_MODEL', 'llama3.2:3b')}")
    print("=" * 65)
    app.run(host="127.0.0.1", port=port, debug=debug)
