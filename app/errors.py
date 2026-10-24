# HTTP and application error handlers for the Flask web application.
# Catches 400, 403, 404, 500, and CSRF errors and renders appropriate user-friendly error views.

from flask import jsonify, render_template, request
from flask_wtf.csrf import CSRFError


def register_error_handlers(app):
    def prefers_json():
        return (
            request.is_json
            or request.path.startswith("/api/")
            or request.path.startswith("/health")
            or request.accept_mimetypes.best == "application/json"
        )

    @app.errorhandler(400)
    def bad_request(error):
        if prefers_json():
            return jsonify({"error": "Bad Request", "message": str(error)}), 400
        return render_template("errors/400.html", error=error), 400

    @app.errorhandler(404)
    def not_found(error):
        if prefers_json():
            return jsonify({"error": "Not Found", "message": "The requested resource was not found."}), 404
        return render_template("errors/404.html"), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        if prefers_json():
            return jsonify({"error": "Method Not Allowed", "message": "HTTP method not allowed on this endpoint."}), 405
        return render_template("errors/400.html", error="Method Not Allowed"), 405

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        if prefers_json():
            return jsonify({"error": "CSRF Token Invalid", "message": error.description}), 400
        return render_template("errors/csrf_error.html", reason=error.description), 400

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Internal Server Error: {error}")
        if prefers_json():
            return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred."}), 500
        return render_template("errors/500.html"), 500
