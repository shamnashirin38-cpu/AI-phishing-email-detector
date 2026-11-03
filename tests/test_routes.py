"""
Integration and End-to-End Route tests for Flask web pages and REST API.
Verifies all endpoints, input validation, mocked AI execution, offline fallbacks, and exports.
"""

from unittest.mock import patch, MagicMock
import requests


def test_web_pages_load(client):
    """Verifies that all primary HTML dashboard views return 200 OK."""
    # 1. Dashboard Home
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Threat Intelligence Dashboard" in resp.data

    # 2. Email Analysis View
    resp = client.get("/analyze")
    assert resp.status_code == 200
    assert b"Submit Email for Threat Inspection" in resp.data

    # 3. History View
    resp = client.get("/history")
    assert resp.status_code == 200
    assert b"Security Incident &amp; Scan History" in resp.data or b"Scan History" in resp.data

    # 4. About View
    resp = client.get("/about")
    assert resp.status_code == 200
    assert b"Viva Defense Guide" in resp.data


def test_api_status(client):
    """Tests the /api/status live health check endpoint."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"models": [{"name": "llama3.2:3b"}]}

    with patch("requests.get", return_value=mock_resp):
        res = client.get("/api/status")
        assert res.status_code == 200
        json_data = res.get_json()
        assert json_data["available"] is True
        assert json_data["model_installed"] is True


def test_api_sample_emails(client):
    """Verifies sample emails endpoint returns valid preloaded emails."""
    res = client.get("/api/sample-emails")
    assert res.status_code == 200
    data = res.get_json()
    assert "samples" in data
    assert len(data["samples"]) >= 4


def test_api_analyze_suspicious_email(client, mock_ollama_phishing_response):
    """Tests /api/analyze with a malicious phishing email and mocked AI response."""
    payload = {
        "sender": "PayPal Support <security@mailer-secure92.xyz>",
        "subject": "URGENT: Your Account Has Been Suspended",
        "body": "Your account has been locked. Enter your password at http://192.168.1.1/login within 24 hours."
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_ollama_phishing_response

    with patch("requests.post", return_value=mock_resp):
        res = client.post("/api/analyze", json=payload)
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        result = data["data"]
        assert result["verdict"] == "Phishing"
        assert result["final_risk_score"] >= 75
        assert result["risk_category"] == "Critical"
        assert result["rule_score"] > 0
        assert result["ai_score"] == 38
        assert "scan_id" in result


def test_api_analyze_safe_email(client, mock_ollama_safe_response):
    """Tests /api/analyze with a benign academic email and mocked AI response."""
    payload = {
        "sender": "Prof. Alan Turing <a.turing@university.edu>",
        "subject": "Meeting agenda for Tuesday lab review",
        "body": "Dear team, please find attached the review notes for our lab meeting this Tuesday at 10 AM. Alan."
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_ollama_safe_response

    with patch("requests.post", return_value=mock_resp):
        res = client.post("/api/analyze", json=payload)
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        result = data["data"]
        assert result["verdict"] == "Safe"
        assert result["final_risk_score"] < 25
        assert result["risk_category"] == "Low"


def test_api_analyze_ollama_offline_graceful_fallback(client):
    """Verifies that /api/analyze handles Ollama being offline without crashing."""
    payload = {
        "sender": "alert@bank.com",
        "subject": "Account Alert",
        "body": "Please confirm your password immediately."
    }

    # Simulate connection error to Ollama daemon
    with patch("requests.post", side_effect=requests.exceptions.ConnectionError("Connection refused")):
        res = client.post("/api/analyze", json=payload)
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        result = data["data"]
        assert result["ai_available"] is False
        assert result["scoring_mode"] == "rule_only"
        assert result["ai_score"] is None
        assert result["rule_score"] > 0


def test_api_analyze_validation_empty_body(client):
    """Verifies that submitting an empty body returns HTTP 400 Bad Request."""
    payload = {
        "sender": "test@example.com",
        "subject": "Subject",
        "body": ""
    }
    res = client.post("/api/analyze", json=payload)
    assert res.status_code == 400
    data = res.get_json()
    assert data["success"] is False
    assert "empty" in data["error"].lower()


def test_api_analyze_validation_oversized_body(client):
    """Verifies that submitting an oversized body (> 100,000 chars) returns HTTP 400."""
    payload = {
        "sender": "test@example.com",
        "subject": "Large",
        "body": "A" * 105000
    }
    res = client.post("/api/analyze", json=payload)
    assert res.status_code == 400
    data = res.get_json()
    assert data["success"] is False
    assert "exceeds" in data["error"].lower()


def test_history_api_and_exports(client, mock_ollama_phishing_response):
    """Tests scan creation, history retrieval, deletion, and TXT/JSON file downloads."""
    # 1. Create a scan
    payload = {
        "sender": "support@paypa1.xyz",
        "subject": "Suspension Alert",
        "body": "Account suspended. Click http://192.168.1.1/login to verify your password."
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_ollama_phishing_response

    with patch("requests.post", return_value=mock_resp):
        res = client.post("/api/analyze", json=payload)
        scan_id = res.get_json()["data"]["scan_id"]

    # 2. Check /api/history
    h_res = client.get("/api/history")
    assert h_res.status_code == 200
    h_data = h_res.get_json()
    assert h_data["total_count"] >= 1

    # 3. Check individual scan view /scan/<id>
    view_res = client.get(f"/scan/{scan_id}")
    assert view_res.status_code == 200
    assert b"Security Incident Report" in view_res.data

    # 4. Check TXT export
    txt_res = client.get(f"/export/{scan_id}/txt")
    assert txt_res.status_code == 200
    assert txt_res.mimetype == "text/plain"
    assert b"THREAT REPORT" in txt_res.data

    # 5. Check JSON export
    json_res = client.get(f"/export/{scan_id}/json")
    assert json_res.status_code == 200
    assert json_res.mimetype == "application/json"
    exported_obj = json_res.get_json()
    assert exported_obj["id"] == scan_id

    # 6. Delete scan
    del_res = client.delete(f"/api/scan/{scan_id}")
    assert del_res.status_code == 200

    # 7. Clear all history
    clear_res = client.post("/api/history/clear")
    assert clear_res.status_code == 200
