"""
Flask Application Routes and API Endpoints.

Handles:
- Web views: Dashboard, Analysis, History, Scan Details, About Project
- REST API: Email analysis, Ollama status, Search/Filter History, Deletions, Exports
"""

import json
from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
    Response,
    current_app,
    abort
)

from app.rules import RuleEngine
from app.ai import OllamaClient
from app.database import (
    save_scan,
    get_scans,
    get_scan_by_id,
    delete_scan,
    clear_all_scans,
    get_statistics
)
from app.utils import (
    compute_final_risk,
    validate_email_input,
    export_scan_to_txt,
    export_scan_to_json,
    SAMPLE_EMAILS
)

main_bp = Blueprint("main", __name__)


def get_rule_engine() -> RuleEngine:
    return RuleEngine()


def get_ollama_client() -> OllamaClient:
    return OllamaClient(
        base_url=current_app.config["OLLAMA_BASE_URL"],
        model=current_app.config["OLLAMA_MODEL"],
        timeout=current_app.config["OLLAMA_TIMEOUT"]
    )


# =========================================================================
# WEB PAGE VIEWS
# =========================================================================

@main_bp.route("/")
def index():
    """Home dashboard with security statistics, recent scans, and system status."""
    db_path = current_app.config["DATABASE_PATH"]
    stats = get_statistics(db_path)
    
    ollama_client = get_ollama_client()
    ollama_status = ollama_client.check_status()

    return render_template(
        "index.html",
        stats=stats,
        ollama_status=ollama_status,
        active_page="dashboard"
    )


@main_bp.route("/analyze")
def analyze_view():
    """Email analysis interface with sample email loader."""
    ollama_client = get_ollama_client()
    ollama_status = ollama_client.check_status()
    
    return render_template(
        "analyze.html",
        samples=SAMPLE_EMAILS,
        ollama_status=ollama_status,
        active_page="analyze"
    )


@main_bp.route("/history")
def history_view():
    """Scan history page with search and category filters."""
    return render_template("history.html", active_page="history")


@main_bp.route("/scan/<int:scan_id>")
def scan_detail_view(scan_id: int):
    """Detailed view for a single completed scan."""
    db_path = current_app.config["DATABASE_PATH"]
    scan = get_scan_by_id(db_path, scan_id)
    if not scan:
        abort(404, description=f"Scan #{scan_id} not found.")

    return render_template("scan_detail.html", scan=scan, active_page="history")


@main_bp.route("/about")
def about_view():
    """About project page detailing architecture, methodology, and college viva concepts."""
    return render_template("about.html", active_page="about")


# =========================================================================
# REST API ENDPOINTS
# =========================================================================

@main_bp.route("/api/status", methods=["GET"])
def api_status():
    """Pings Ollama local API to return live connectivity and model status."""
    ollama_client = get_ollama_client()
    status = ollama_client.check_status()
    return jsonify(status)


@main_bp.route("/api/sample-emails", methods=["GET"])
def api_samples():
    """Returns preset sample emails for quick testing."""
    return jsonify({"samples": SAMPLE_EMAILS})


@main_bp.route("/api/analyze", methods=["POST"])
def api_analyze():
    """
    Core analysis endpoint.
    1. Validates sender, subject, body
    2. Runs rule engine (0-60 pts)
    3. Queries Ollama AI (0-40 pts, graceful fallback if offline)
    4. Computes hybrid risk score (0-100)
    5. Saves report to SQLite database
    6. Returns structured response
    """
    data = request.get_json(silent=True) or request.form.to_dict()
    sender = data.get("sender", "")
    subject = data.get("subject", "")
    body = data.get("body", "")

    # Input validation
    is_valid, err_msg, cleaned = validate_email_input(sender, subject, body)
    if not is_valid:
        return jsonify({"success": False, "error": err_msg}), 400

    # 1. Rule-Based Analysis
    rule_engine = get_rule_engine()
    rule_result = rule_engine.analyze(
        sender=cleaned["sender"],
        subject=cleaned["subject"],
        body=cleaned["body"]
    )

    # 2. Ollama AI Analysis
    ollama_client = get_ollama_client()
    ai_result = ollama_client.analyze_email(
        sender=cleaned["sender"],
        subject=cleaned["subject"],
        body=cleaned["body"],
        rule_indicators=rule_result.get("indicators", [])
    )

    # 3. Combined Risk Scoring
    final_assessment = compute_final_risk(rule_result, ai_result)

    # 4. Save to Database
    db_path = current_app.config["DATABASE_PATH"]
    scan_record = {
        "sender": cleaned["sender"],
        "subject": cleaned["subject"],
        "body": cleaned["body"],
        "final_risk_score": final_assessment["final_risk_score"],
        "risk_category": final_assessment["risk_category"],
        "verdict": final_assessment["verdict"],
        "rule_score": final_assessment["rule_score"],
        "ai_score": final_assessment["ai_score"],
        "ai_status": final_assessment["ai_status"],
        "indicators": final_assessment["indicators"],
        "ai_analysis": {
            "model": final_assessment.get("ai_model"),
            "confidence": final_assessment.get("ai_confidence"),
            "reasoning": final_assessment.get("ai_reasoning"),
            "available": final_assessment.get("ai_available")
        },
        "recommended_actions": final_assessment["recommended_actions"]
    }

    scan_id = save_scan(db_path, scan_record)
    final_assessment["scan_id"] = scan_id
    final_assessment["sender"] = cleaned["sender"]
    final_assessment["subject"] = cleaned["subject"]

    return jsonify({
        "success": True,
        "data": final_assessment
    })


@main_bp.route("/api/history", methods=["GET"])
def api_history():
    """Returns paginated and filtered scan history."""
    search_query = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    verdict = request.args.get("verdict", "").strip()
    
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(50, max(5, int(request.args.get("per_page", 10))))
    except ValueError:
        page, per_page = 1, 10

    db_path = current_app.config["DATABASE_PATH"]
    scans, total_count = get_scans(
        db_path,
        search_query=search_query,
        category=category,
        verdict=verdict,
        page=page,
        per_page=per_page
    )

    total_pages = max(1, (total_count + per_page - 1) // per_page)

    return jsonify({
        "success": True,
        "scans": scans,
        "total_count": total_count,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages
    })


@main_bp.route("/api/scan/<int:scan_id>", methods=["GET"])
def api_get_scan(scan_id: int):
    """Returns JSON details of an individual scan."""
    db_path = current_app.config["DATABASE_PATH"]
    scan = get_scan_by_id(db_path, scan_id)
    if not scan:
        return jsonify({"success": False, "error": f"Scan #{scan_id} not found."}), 404
    return jsonify({"success": True, "scan": scan})


@main_bp.route("/api/scan/<int:scan_id>", methods=["DELETE"])
def api_delete_scan(scan_id: int):
    """Deletes an individual scan record."""
    db_path = current_app.config["DATABASE_PATH"]
    deleted = delete_scan(db_path, scan_id)
    if not deleted:
        return jsonify({"success": False, "error": f"Scan #{scan_id} not found or already deleted."}), 404
    return jsonify({"success": True, "message": f"Scan #{scan_id} successfully deleted."})


@main_bp.route("/api/history/clear", methods=["POST", "DELETE"])
def api_clear_history():
    """Clears all scan history with confirmation."""
    db_path = current_app.config["DATABASE_PATH"]
    cleared_count = clear_all_scans(db_path)
    return jsonify({
        "success": True,
        "message": f"Successfully cleared {cleared_count} scan records."
    })


@main_bp.route("/export/<int:scan_id>/<format_type>", methods=["GET"])
def export_scan(scan_id: int, format_type: str):
    """Exports a single scan as downloadable TXT or JSON."""
    db_path = current_app.config["DATABASE_PATH"]
    scan = get_scan_by_id(db_path, scan_id)
    if not scan:
        abort(404, description=f"Scan #{scan_id} not found.")

    format_type = format_type.lower()
    if format_type == "txt":
        content = export_scan_to_txt(scan)
        filename = f"phishing_report_scan_{scan_id}.txt"
        return Response(
            content,
            mimetype="text/plain",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    elif format_type == "json":
        content = export_scan_to_json(scan)
        filename = f"phishing_report_scan_{scan_id}.json"
        return Response(
            content,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    else:
        abort(400, description="Invalid export format. Supported formats are 'txt' and 'json'.")
