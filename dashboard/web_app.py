"""Flask web dashboard for AllamSec."""

import json
from contextlib import closing
from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request

from database.db_manager import (
    DEFAULT_DB_PATH,
    get_connection,
    initialize_database,
)


APP_VERSION = "0.7.0"


def create_app(db_path=None):
    """Create and configure the AllamSec dashboard."""

    app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static",
    static_url_path="/static",
)

    app.config["DATABASE_PATH"] = str(
        db_path if db_path is not None else DEFAULT_DB_PATH
    )

    app.config["JSON_SORT_KEYS"] = False

    initialize_database(app.config["DATABASE_PATH"])

    def fetch_one(query, parameters=()):
        with closing(
            get_connection(app.config["DATABASE_PATH"])
        ) as connection:
            row = connection.execute(
                query, parameters
            ).fetchone()

            return dict(row) if row else None

    def fetch_all(query, parameters=()):
        with closing(
            get_connection(app.config["DATABASE_PATH"])
        ) as connection:
            rows = connection.execute(
                query, parameters
            ).fetchall()

            return [dict(row) for row in rows]

    def get_statistics():
        """Collect the main security dashboard statistics."""

        totals = fetch_one("""
            SELECT
                (SELECT COUNT(*) FROM security_events)
                    AS total_events,
                (SELECT COUNT(*) FROM security_alerts)
                    AS total_alerts,
                (SELECT COUNT(*) FROM security_alerts
                 WHERE severity = 'CRITICAL')
                    AS critical_alerts,
                (SELECT COALESCE(MAX(risk_score), 0)
                 FROM security_alerts)
                    AS highest_risk_score
        """)

        severity_rows = fetch_all("""
            SELECT severity, COUNT(*) AS total
            FROM security_alerts
            GROUP BY severity
        """)

        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }

        for row in severity_rows:
            if row["severity"] in severity_counts:
                severity_counts[row["severity"]] = row["total"]

        totals["severity_counts"] = severity_counts

        totals["authentication_events"] = fetch_one("""
            SELECT COUNT(*) AS total
            FROM security_events
            WHERE event_source = 'authentication'
        """)["total"]

        totals["network_events"] = fetch_one("""
            SELECT COUNT(*) AS total
            FROM security_events
            WHERE event_source = 'network'
        """)["total"]

        return totals

    def parse_alert(row):
        """Decode an alert's stored JSON data."""

        if row is None:
            return None

        row["details"] = json.loads(row["alert_data"])
        return row

    def get_alerts(limit=100):
        rows = fetch_all("""
            SELECT *
            FROM security_alerts
            ORDER BY risk_score DESC, id DESC
            LIMIT ?
        """, (limit,))

        return [parse_alert(row) for row in rows]

    def get_events(limit=100):
        rows = fetch_all("""
            SELECT *
            FROM security_events
            ORDER BY event_timestamp DESC, id DESC
            LIMIT ?
        """, (limit,))

        for row in rows:
            row["details"] = json.loads(row["event_data"])

        return rows

    @app.context_processor
    def inject_globals():
        return {
            "app_name": "AllamSec",
            "app_version": APP_VERSION,
        }

    @app.route("/")
    def index():
        statistics = get_statistics()
        alerts = get_alerts(limit=8)
        events = get_events(limit=6)

        return render_template(
            "index.html",
            page="overview",
            stats=statistics,
            alerts=alerts,
            events=events,
        )

    @app.route("/alerts")
    def alerts_page():
        severity = request.args.get(
            "severity", "ALL"
        ).upper()

        allowed = {
            "ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"
        }

        if severity not in allowed:
            abort(400, description="Invalid severity filter.")

        if severity == "ALL":
            alerts = get_alerts(limit=500)
        else:
            rows = fetch_all("""
                SELECT *
                FROM security_alerts
                WHERE severity = ?
                ORDER BY risk_score DESC, id DESC
                LIMIT 500
            """, (severity,))

            alerts = [parse_alert(row) for row in rows]

        return render_template(
            "alerts.html",
            page="alerts",
            alerts=alerts,
            selected_severity=severity,
            stats=get_statistics(),
        )

    @app.route("/alerts/<int:alert_id>")
    def alert_detail(alert_id):
        row = fetch_one("""
            SELECT *
            FROM security_alerts
            WHERE id = ?
        """, (alert_id,))

        if row is None:
            abort(404)

        return render_template(
            "alert_detail.html",
            page="alerts",
            alert=parse_alert(row),
        )

    @app.route("/events")
    def events_page():
        source = request.args.get(
            "source", "all"
        ).lower()

        if source not in ("all", "authentication", "network"):
            abort(400, description="Invalid event source.")

        if source == "all":
            events = get_events(limit=500)
        else:
            rows = fetch_all("""
                SELECT *
                FROM security_events
                WHERE event_source = ?
                ORDER BY event_timestamp DESC, id DESC
                LIMIT 500
            """, (source,))

            events = []

            for row in rows:
                row["details"] = json.loads(
                    row["event_data"]
                )
                events.append(row)

        return render_template(
            "events.html",
            page="events",
            events=events,
            selected_source=source,
            stats=get_statistics(),
        )

    @app.route("/api/stats")
    def api_stats():
        return jsonify(get_statistics())

    @app.route("/api/alerts")
    def api_alerts():
        alerts = get_alerts(limit=100)
        return jsonify(alerts)

    @app.route("/health")
    def health():
        return jsonify({
            "application": "AllamSec",
            "version": APP_VERSION,
            "status": "online",
        })

    return app


app = create_app()


if __name__ == "__main__":
    print("=" * 55)
    print("AllamSec Web Dashboard")
    print(f"Version: {APP_VERSION}")
    print("Open: http://127.0.0.1:5000")
    print("=" * 55)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )