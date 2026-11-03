"""
Pytest configuration and test fixtures.
Provides an isolated test database, test Flask client,
and mocked responses for Ollama AI testing without requiring a running AI model.
"""

import os
from pathlib import Path
import pytest
from app import create_app
from app.config import TestConfig
from app.database import init_db


@pytest.fixture(autouse=True)
def clean_test_db():
    """Ensures test database is cleanly initialized before each test."""
    db_path = Path(TestConfig.DATABASE_PATH)
    if db_path.exists():
        try:
            db_path.unlink()
        except Exception:
            pass
    init_db(str(db_path))
    yield
    if db_path.exists():
        try:
            db_path.unlink()
        except Exception:
            pass


@pytest.fixture
def app():
    """Creates a Flask application instance configured for testing."""
    test_app = create_app(TestConfig)
    with test_app.app_context():
        yield test_app


@pytest.fixture
def client(app):
    """Provides a test client for simulating HTTP requests."""
    return app.test_client()


@pytest.fixture
def mock_ollama_phishing_response():
    """Mocked Ollama response predicting a high-confidence phishing attack."""
    return {
        "response": """{
            "verdict": "Phishing",
            "ai_risk_score": 38,
            "confidence": 0.96,
            "reasoning": "The email exhibits classic brand impersonation, urgent coercion, and direct credential solicitation via an unofficial IP-hosted login portal.",
            "evidence": ["Unrecognized IP address in URL", "Account suspension ultimatum", "Direct request for current password"],
            "recommended_actions": ["Do not click the link", "Report to security team", "Reset corporate passwords if entered"]
        }"""
    }


@pytest.fixture
def mock_ollama_safe_response():
    """Mocked Ollama response predicting a safe legitimate message."""
    return {
        "response": """{
            "verdict": "Safe",
            "ai_risk_score": 2,
            "confidence": 0.98,
            "reasoning": "Normal project coordination message with expected academic context and no deceptive links or coercive demands.",
            "evidence": ["Legitimate academic domain", "No coercive threats", "No external unverified URLs"],
            "recommended_actions": ["No action required", "Maintain standard email vigilance"]
        }"""
    }


@pytest.fixture
def mock_ollama_markdown_response():
    """Mocked Ollama response with markdown code fences."""
    return {
        "response": """```json
{
    "verdict": "Suspicious",
    "ai_risk_score": 22,
    "confidence": 0.85,
    "reasoning": "Ambiguous delivery tracking notice with unverified domain.",
    "evidence": ["Generic greeting", "Unverified tracking link"],
    "recommended_actions": ["Verify shipment directly on courier portal"]
}
```"""
    }
