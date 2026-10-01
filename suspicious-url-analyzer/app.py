import sqlite3

from flask import Flask, render_template, request

from analyzers.reputation import check_url_reputation
from analyzers.url_analyzer import URLValidationError, analyze_url
from database.database import init_db, save_scan
from services.risk_engine import calculate_risk

app = Flask(__name__)


@app.route("/")
def index():
    """Show the homepage."""
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """Receive a submitted URL and show it on the results page."""
    submitted_url = request.form["url"].strip()

    if not submitted_url:
        return render_template(
            "index.html",
            error="Please enter a URL.",
        )

    try:
        result = analyze_url(submitted_url)
    except URLValidationError as error:
        return render_template("index.html", error=str(error))

    risk = calculate_risk(result["indicators"])
    reputation = check_url_reputation(submitted_url)
    scan_id = None
    save_error = None

    try:
        init_db()
        scan_id = save_scan(result["parsed"], risk)
    except sqlite3.Error:
        app.logger.exception("The analysis could not be saved")
        save_error = (
            "The analysis completed, but the result could not be saved "
            "to scan history."
        )

    return render_template(
        "results.html",
        parsed=result["parsed"],
        indicators=result["indicators"],
        risk=risk,
        reputation=reputation,
        scan_id=scan_id,
        save_error=save_error,
    )


if __name__ == "__main__":
    app.run(debug=True)
