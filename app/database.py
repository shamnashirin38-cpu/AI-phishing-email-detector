"""
SQLite Database Layer for AI Phishing Email Detection System.

Features:
- Thread-safe parameterized queries to prevent SQL injection.
- Storing scan metadata, indicators, AI findings, and recommendations.
- Full-text search across sender, subject, and findings.
- Category and verdict filtering with pagination.
- Deletion of individual records and clear all functionality.
- Aggregate cybersecurity statistics for the home dashboard.
"""

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def get_db_connection(db_path: str) -> sqlite3.Connection:
    """Creates a connection with Row factory enabled."""
    # Ensure directory exists if not an in-memory database
    if db_path != ":memory:":
        parent_dir = Path(db_path).parent
        parent_dir.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str):
    """Initializes the database schema if tables do not exist."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS email_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                sender TEXT,
                subject TEXT,
                body_snippet TEXT,
                full_body TEXT,
                risk_score INTEGER NOT NULL,
                risk_category TEXT NOT NULL,
                verdict TEXT NOT NULL,
                rule_score INTEGER,
                ai_score INTEGER,
                ai_status TEXT,
                indicators_json TEXT,
                ai_analysis_json TEXT,
                recommendations_json TEXT
            );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON email_scans (timestamp DESC);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_verdict ON email_scans (verdict);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_category ON email_scans (risk_category);")
        conn.commit()


def save_scan(db_path: str, scan_data: dict) -> int:
    """
    Saves an email analysis report to the database using safe parameterized queries.
    Returns the newly inserted scan ID.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    body = scan_data.get("body", "")
    body_snippet = (body[:250] + "...") if len(body) > 250 else body

    indicators_json = json.dumps(scan_data.get("indicators", []))
    ai_analysis_json = json.dumps(scan_data.get("ai_analysis", {}))
    recommendations_json = json.dumps(scan_data.get("recommended_actions", []))

    query = """
        INSERT INTO email_scans (
            timestamp, sender, subject, body_snippet, full_body,
            risk_score, risk_category, verdict, rule_score, ai_score,
            ai_status, indicators_json, ai_analysis_json, recommendations_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """

    params = (
        timestamp,
        scan_data.get("sender", "").strip(),
        scan_data.get("subject", "").strip(),
        body_snippet,
        body,
        int(scan_data.get("final_risk_score", 0)),
        scan_data.get("risk_category", "Low"),
        scan_data.get("verdict", "Safe"),
        scan_data.get("rule_score"),
        scan_data.get("ai_score"),
        scan_data.get("ai_status", "offline"),
        indicators_json,
        ai_analysis_json,
        recommendations_json
    )

    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        return cursor.lastrowid


def get_scans(
    db_path: str,
    search_query: str = "",
    category: str = "",
    verdict: str = "",
    page: int = 1,
    per_page: int = 10
) -> tuple[list[dict], int]:
    """
    Fetches paginated scans with optional keyword search and category/verdict filtering.
    Returns: (list_of_scans, total_matching_records)
    """
    conditions = []
    params = []

    if search_query:
        like_term = f"%{search_query.strip()}%"
        conditions.append("(sender LIKE ? OR subject LIKE ? OR body_snippet LIKE ? OR indicators_json LIKE ?)")
        params.extend([like_term, like_term, like_term, like_term])

    if category and category.lower() != "all":
        conditions.append("LOWER(risk_category) = LOWER(?)")
        params.append(category.strip())

    if verdict and verdict.lower() != "all":
        conditions.append("LOWER(verdict) = LOWER(?)")
        params.append(verdict.strip())

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    # Count total
    count_query = f"SELECT COUNT(*) FROM email_scans {where_clause}"
    
    # Fetch paginated rows
    offset = max(0, (page - 1) * per_page)
    data_query = f"""
        SELECT id, timestamp, sender, subject, body_snippet,
               risk_score, risk_category, verdict, rule_score, ai_score, ai_status
        FROM email_scans
        {where_clause}
        ORDER BY id DESC
        LIMIT ? OFFSET ?;
    """

    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()[0]

        cursor.execute(data_query, params + [per_page, offset])
        rows = cursor.fetchall()

        scans = [dict(row) for row in rows]
        return scans, total_count


def get_scan_by_id(db_path: str, scan_id: int) -> dict | None:
    """Fetches a single scan report by ID, unpacking its JSON fields."""
    query = "SELECT * FROM email_scans WHERE id = ?;"
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None

        data = dict(row)
        try:
            data["indicators"] = json.loads(data.get("indicators_json") or "[]")
        except Exception:
            data["indicators"] = []

        try:
            data["ai_analysis"] = json.loads(data.get("ai_analysis_json") or "{}")
        except Exception:
            data["ai_analysis"] = {}

        try:
            data["recommended_actions"] = json.loads(data.get("recommendations_json") or "[]")
        except Exception:
            data["recommended_actions"] = []

        return data


def delete_scan(db_path: str, scan_id: int) -> bool:
    """Deletes a single scan by ID. Returns True if deleted."""
    query = "DELETE FROM email_scans WHERE id = ?;"
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(query, (scan_id,))
        conn.commit()
        return cursor.rowcount > 0


def clear_all_scans(db_path: str) -> int:
    """Clears all records from scan history. Returns total rows cleared."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM email_scans;")
        deleted_count = cursor.rowcount
        conn.commit()
        return deleted_count


def get_statistics(db_path: str) -> dict:
    """Returns aggregated metrics for the dashboard summary cards."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM email_scans;")
        total_scans = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM email_scans WHERE LOWER(verdict) = 'phishing';")
        phishing_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM email_scans WHERE LOWER(verdict) = 'safe';")
        safe_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM email_scans WHERE LOWER(verdict) = 'suspicious';")
        suspicious_count = cursor.fetchone()[0]

        cursor.execute("SELECT AVG(risk_score) FROM email_scans;")
        avg_score_raw = cursor.fetchone()[0]
        avg_risk_score = round(avg_score_raw, 1) if avg_score_raw is not None else 0

        # Category distribution
        cursor.execute("""
            SELECT risk_category, COUNT(*) FROM email_scans
            GROUP BY risk_category;
        """)
        category_rows = cursor.fetchall()
        categories = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        for cat, cnt in category_rows:
            if cat in categories:
                categories[cat] = cnt

        # Recent scans
        cursor.execute("""
            SELECT id, timestamp, sender, subject, risk_score, risk_category, verdict
            FROM email_scans
            ORDER BY id DESC
            LIMIT 5;
        """)
        recent_scans = [dict(r) for r in cursor.fetchall()]

        return {
            "total_scans": total_scans,
            "phishing_count": phishing_count,
            "safe_count": safe_count,
            "suspicious_count": suspicious_count,
            "avg_risk_score": avg_risk_score,
            "category_distribution": categories,
            "recent_scans": recent_scans
        }
