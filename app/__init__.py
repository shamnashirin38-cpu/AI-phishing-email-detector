"""
Application factory for the AI-Powered Phishing Email Detection System.
"""

from flask import Flask, render_template
from app.config import Config
from app.database import init_db


def create_app(config_class=Config):
    """Initializes and configures the Flask application."""
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static"
    )
    app.config.from_object(config_class)

    # Initialize SQLite database schema
    init_db(app.config["DATABASE_PATH"])

    # Register blueprints
    from app.routes import main_bp
    app.register_blueprint(main_bp)

    # Register standard HTTP error handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template("base.html", error_title="404 - Page Not Found", error_message=str(e.description or "The requested resource could not be located.")), 404

    @app.errorhandler(413)
    def request_entity_too_large(e):
        return render_template("base.html", error_title="413 - Payload Too Large", error_message="The email content submitted exceeds the maximum allowable size."), 413

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template("base.html", error_title="500 - Internal Server Error", error_message="An unexpected server error occurred while processing the request."), 500

    return app
