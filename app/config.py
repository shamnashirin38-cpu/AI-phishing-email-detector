import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env if present
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

class Config:
    """Base application configuration."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "phishing-detector-default-dev-key-2026")
    
    # Database
    db_relative = os.environ.get("DATABASE_PATH", "instance/phishing_detector.db")
    DATABASE_PATH = str(BASE_DIR / db_relative)
    
    # Ollama Local AI
    OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")
    OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", 30))
    
    # Input Constraints
    MAX_CONTENT_LENGTH = 512 * 1024  # 512 KB limit to prevent oversized input attacks
    MAX_SUBJECT_LENGTH = 500
    MAX_BODY_LENGTH = 100000
    MAX_SENDER_LENGTH = 320


class TestConfig(Config):
    """Configuration used during automated pytest runs."""
    TESTING = True
    DATABASE_PATH = str(BASE_DIR / "instance" / "test_phishing.db")
    OLLAMA_TIMEOUT = 2
