"""
Unit tests for the Ollama Local AI integration using unittest.mock.
Verifies JSON parsing, markdown stripping, score clamping, connection errors, and timeout handling.
No live AI daemon required.
"""

from unittest.mock import patch, MagicMock
import requests
from app.ai import OllamaClient


def test_ollama_check_status_online():
    """Tests status check when Ollama is running and model is present."""
    client = OllamaClient(model="llama3.2:3b")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "models": [{"name": "llama3.2:3b:latest"}, {"name": "mistral:latest"}]
    }

    with patch("requests.get", return_value=mock_resp):
        status = client.check_status()
        assert status["available"] is True
        assert status["model_installed"] is True
        assert status["status"] == "online"


def test_ollama_check_status_model_missing():
    """Tests status check when Ollama is running but target model is not installed."""
    client = OllamaClient(model="llama3.2:3b")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "models": [{"name": "mistral:latest"}]
    }

    with patch("requests.get", return_value=mock_resp):
        status = client.check_status()
        assert status["available"] is True
        assert status["model_installed"] is False
        assert status["status"] == "model_missing"


def test_ollama_check_status_offline():
    """Tests status check when Ollama daemon is completely offline."""
    client = OllamaClient()

    with patch("requests.get", side_effect=requests.exceptions.ConnectionError("Connection refused")):
        status = client.check_status()
        assert status["available"] is False
        assert status["status"] == "offline"


def test_ollama_analyze_email_success(mock_ollama_phishing_response):
    """Tests successful email inference returning valid structured JSON."""
    client = OllamaClient()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_ollama_phishing_response

    with patch("requests.post", return_value=mock_resp):
        res = client.analyze_email(
            sender="support@attacker.com",
            subject="Urgent",
            body="Click here"
        )
        assert res["available"] is True
        assert res["verdict"] == "Phishing"
        assert res["ai_risk_score"] == 38
        assert res["confidence"] == 0.96
        assert len(res["evidence"]) > 0


def test_ollama_analyze_email_with_markdown_fences(mock_ollama_markdown_response):
    """Verifies that markdown code blocks (```json ... ```) are cleanly stripped and parsed."""
    client = OllamaClient()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_ollama_markdown_response

    with patch("requests.post", return_value=mock_resp):
        res = client.analyze_email(
            sender="shipping@courier.com",
            subject="Tracking",
            body="Parcel ready"
        )
        assert res["available"] is True
        assert res["verdict"] == "Suspicious"
        assert res["ai_risk_score"] == 22


def test_ollama_analyze_score_clamping():
    """Verifies that out-of-range scores and confidences are clamped safely."""
    client = OllamaClient()

    # Raw response with score 99 (exceeding 40 max) and confidence 5.0 (exceeding 1.0)
    raw_response = {
        "response": '{"verdict": "Phishing", "ai_risk_score": 99, "confidence": 5.0, "reasoning": "Severe"}'
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = raw_response

    with patch("requests.post", return_value=mock_resp):
        res = client.analyze_email("a@b.com", "sub", "body")
        assert res["ai_risk_score"] == 40  # Clamped to max 40
        assert res["confidence"] == 1.0    # Clamped to max 1.0


def test_ollama_connection_error_graceful_handling():
    """Verifies that ConnectionError does not crash the app and returns graceful fallback."""
    client = OllamaClient()

    with patch("requests.post", side_effect=requests.exceptions.ConnectionError("Offline")):
        res = client.analyze_email("a@b.com", "sub", "body")
        assert res["available"] is False
        assert res["status"] == "offline"
        assert res["ai_risk_score"] is None
        assert "offline" in res["reasoning"].lower()


def test_ollama_timeout_graceful_handling():
    """Verifies that request Timeout does not crash the app and returns graceful fallback."""
    client = OllamaClient()

    with patch("requests.post", side_effect=requests.exceptions.Timeout("Timeout")):
        res = client.analyze_email("a@b.com", "sub", "body")
        assert res["available"] is False
        assert res["status"] == "timeout"
        assert "timed out" in res["reasoning"].lower()
