"""
Unit tests for the SQLite Database Layer.
Verifies CRUD operations, parameterized search and filtering, JSON unpacking, and aggregation metrics.
"""

import pytest
from app.database import (
    init_db,
    save_scan,
    get_scans,
    get_scan_by_id,
    delete_scan,
    clear_all_scans,
    get_statistics
)


@pytest.fixture
def temp_db(tmp_path):
    """Provides a fresh temporary SQLite database path for isolated testing."""
    db_file = str(tmp_path / "test_phish.db")
    init_db(db_file)
    return db_file


def test_save_and_retrieve_scan(temp_db):
    """Tests inserting a scan and retrieving it by ID with unpacked JSON fields."""
    scan_data = {
        "sender": "alerts@paypa1.xyz",
        "subject": "Account Alert",
        "body": "Please confirm password at http://192.168.1.1/login",
        "final_risk_score": 85,
        "risk_category": "Critical",
        "verdict": "Phishing",
        "rule_score": 50,
        "ai_score": 35,
        "ai_status": "online",
        "indicators": [
            {"id": "URL_IP_HOST", "name": "Direct IP Host", "severity": "critical", "points": 15}
        ],
        "ai_analysis": {
            "model": "llama3.2:3b",
            "confidence": 0.95,
            "reasoning": "Credential theft detected"
        },
        "recommended_actions": ["Do not click links", "Change passwords"]
    }

    scan_id = save_scan(temp_db, scan_data)
    assert scan_id is not None
    assert scan_id > 0

    retrieved = get_scan_by_id(temp_db, scan_id)
    assert retrieved is not None
    assert retrieved["id"] == scan_id
    assert retrieved["sender"] == "alerts@paypa1.xyz"
    assert retrieved["risk_score"] == 85
    assert retrieved["risk_category"] == "Critical"
    assert retrieved["verdict"] == "Phishing"
    assert isinstance(retrieved["indicators"], list)
    assert len(retrieved["indicators"]) == 1
    assert retrieved["indicators"][0]["id"] == "URL_IP_HOST"
    assert isinstance(retrieved["recommended_actions"], list)
    assert len(retrieved["recommended_actions"]) == 2


def test_search_and_filter_scans(temp_db):
    """Tests keyword search and category/verdict filtering."""
    # Seed 2 scans
    save_scan(temp_db, {
        "sender": "phisher@badsite.com",
        "subject": "Urgent Invoice",
        "body": "Pay immediately",
        "final_risk_score": 80,
        "risk_category": "Critical",
        "verdict": "Phishing"
    })
    save_scan(temp_db, {
        "sender": "colleague@university.edu",
        "subject": "Meeting Notes",
        "body": "See you in lab",
        "final_risk_score": 5,
        "risk_category": "Low",
        "verdict": "Safe"
    })

    # Search for "Invoice"
    scans, count = get_scans(temp_db, search_query="Invoice")
    assert count == 1
    assert scans[0]["sender"] == "phisher@badsite.com"

    # Filter by category "Low"
    low_scans, low_count = get_scans(temp_db, category="Low")
    assert low_count == 1
    assert low_scans[0]["verdict"] == "Safe"

    # Filter by verdict "Phishing"
    phish_scans, phish_count = get_scans(temp_db, verdict="Phishing")
    assert phish_count == 1


def test_delete_scan_and_clear_all(temp_db):
    """Tests deleting single scan and clearing entire history."""
    id1 = save_scan(temp_db, {"sender": "a@b.com", "body": "test1", "final_risk_score": 10, "risk_category": "Low", "verdict": "Safe"})
    id2 = save_scan(temp_db, {"sender": "c@d.com", "body": "test2", "final_risk_score": 20, "risk_category": "Low", "verdict": "Safe"})

    # Delete 1
    deleted = delete_scan(temp_db, id1)
    assert deleted is True
    assert get_scan_by_id(temp_db, id1) is None

    # Clear all
    cleared = clear_all_scans(temp_db)
    assert cleared >= 1
    remaining, count = get_scans(temp_db)
    assert count == 0


def test_get_statistics(temp_db):
    """Tests calculation of aggregate metrics."""
    save_scan(temp_db, {"body": "test", "final_risk_score": 80, "risk_category": "Critical", "verdict": "Phishing"})
    save_scan(temp_db, {"body": "test", "final_risk_score": 60, "risk_category": "High", "verdict": "Phishing"})
    save_scan(temp_db, {"body": "test", "final_risk_score": 10, "risk_category": "Low", "verdict": "Safe"})

    stats = get_statistics(temp_db)
    assert stats["total_scans"] == 3
    assert stats["phishing_count"] == 2
    assert stats["safe_count"] == 1
    assert stats["avg_risk_score"] == 50.0
    assert stats["category_distribution"]["Critical"] == 1
    assert stats["category_distribution"]["High"] == 1
    assert stats["category_distribution"]["Low"] == 1


def test_get_nonexistent_scan(temp_db):
    """Verifies that querying a missing scan returns None safely."""
    assert get_scan_by_id(temp_db, 99999) is None
    assert delete_scan(temp_db, 99999) is False
