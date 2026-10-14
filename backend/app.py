import os
import logging
from flask import Flask, jsonify
from flask_cors import CORS
import sys
from pathlib import Path

# Add backend directory to sys.path so direct execution works seamlessly
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

try:
    from config import Config
    from routes import (
        health_bp,
        validate_bp,
        analyze_bp,
        knowledge_bp,
        ai_bp,
        reports_bp
    )
except ImportError:
    from .config import Config
    from .routes import (
        health_bp,
        validate_bp,
        analyze_bp,
        knowledge_bp,
        ai_bp,
        reports_bp
    )


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("smart_code_inspect")


def create_app(config_class=Config) -> Flask:
    """Application factory for Smart Code Inspection Platform."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Restrict CORS to the local development origins used by the dashboard.
    # Use the IPv4 loopback as the default because some browsers resolve
    # `localhost` to IPv6 (::1) while the Flask app binds to 127.0.0.1 by default.
    allowed_origins = {
        config_class.FRONTEND_ORIGIN,
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://[::1]:5173",
        "http://[::1]:4173",
        "http://[::1]:3000"
    }
    CORS(
        app,
        resources={r"/api/*": {"origins": "*"}},
        supports_credentials=False,
        methods=["GET", "POST", "OPTIONS"]
    )

    # Payload safety limits
    app.config["MAX_CONTENT_LENGTH"] = config_class.MAX_SOURCE_BYTES + 65536

    # Register blueprints under /api prefix
    app.register_blueprint(health_bp, url_prefix="/api")
    app.register_blueprint(validate_bp, url_prefix="/api")
    app.register_blueprint(analyze_bp, url_prefix="/api")
    app.register_blueprint(knowledge_bp, url_prefix="/api")
    app.register_blueprint(ai_bp, url_prefix="/api")
    app.register_blueprint(reports_bp, url_prefix="/api")

    # Centralized JSON error handlers
    @app.errorhandler(400)
    def handle_bad_request(err):
        return jsonify({"error": "Bad Request: Malformed JSON or invalid parameters."}), 400

    @app.errorhandler(404)
    def handle_not_found(err):
        return jsonify({"error": "Resource not found."}), 404

    @app.errorhandler(405)
    def handle_method_not_allowed(err):
        return jsonify({"error": "Method Not Allowed."}), 405

    @app.errorhandler(413)
    def handle_payload_too_large(err):
        return jsonify({"error": "Request entity too large: Exceeds maximum allowed size limit."}), 413

    @app.errorhandler(500)
    def handle_internal_error(err):
        logger.error("Internal Server Error: %s", str(err))
        return jsonify({"error": "Internal server error encountered. Inspection halted safely."}), 500

    return app


app = create_app()

if __name__ == "__main__":
    logger.info("Starting Smart Code Inspection Backend on %s:%s", Config.HOST, Config.PORT)
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.FLASK_DEBUG)
