"""AllamSec security monitoring web dashboard."""

import json
from contextlib import closing

from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from database.db_manager import (
    ALERT_STATUSES,
    DEFAULT_DB_PATH,
    get_connection,
    get_threat_analytics,
    initialize_alert_management,
    initialize_database,
    update_alert_investigation,
)


APP_VERSION = "0.8.0"


def create_app(db_path=None):
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
    app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024

    initialize_database(app.config["DATABASE_PATH"])
    initialize_alert_management(app.config["DATABASE_PATH"])

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
        return render_template(
            "index.html",
            page="overview",
            stats=get_statistics(),
            alerts=get_alerts(limit=8),
            events=get_events(limit=6),
        )

    @app.route("/alerts")
    def alerts_page():
        severity = request.args.get(
            "severity", "ALL"
        ).upper()

        status = request.args.get(
            "status", "ALL"
        ).upper()

        search = request.args.get(
            "search", ""
        ).strip()[:100]

        if severity not in (
            "ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"
        ):
            abort(400, description="Invalid severity filter.")

        if status not in ("ALL", *ALERT_STATUSES):
            abort(400, description="Invalid status filter.")

        conditions = []
        parameters = []

        if severity != "ALL":
            conditions.append("severity = ?")
            parameters.append(severity)

        if status != "ALL":
            conditions.append("status = ?")
            parameters.append(status)

        if search:
            conditions.append("""
                (
                    source_ip LIKE ? OR
                    destination_ip LIKE ? OR
                    username LIKE ? OR
                    alert_type LIKE ?
                )
            """)

            pattern = (
                "%"
                + search.replace("\\", "\\\\")
                        .replace("%", "\\%")
                        .replace("_", "\\_")
                + "%"
            )

            conditions[-1] = conditions[-1].replace(
                "LIKE ?", "LIKE ? ESCAPE '\\'"
            )

            parameters.extend([pattern] * 4)

        query = "SELECT * FROM security_alerts"

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY risk_score DESC, id DESC LIMIT 500"

        rows = fetch_all(query, parameters)

        return render_template(
            "alerts.html",
            page="alerts",
            alerts=[parse_alert(row) for row in rows],
            selected_severity=severity,
            selected_status=status,
            search_query=search,
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
            allowed_statuses=ALERT_STATUSES,
        )

    @app.route("/alerts/<int:alert_id>/update", methods=["POST"])
    def update_alert(alert_id):
        status = request.form.get("status", "")
        notes = request.form.get("notes", "")

        if status not in ALERT_STATUSES:
            abort(400, description="Invalid investigation status.")

        if len(notes) > 5000:
            abort(400, description="Notes are too long.")

        updated = update_alert_investigation(
            alert_id,
            status,
            notes,
            db_path=app.config["DATABASE_PATH"],
        )

        if not updated:
            abort(404)

        return redirect(
            url_for("alert_detail", alert_id=alert_id)
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
                row["details"] = json.loads(row["event_data"])
                events.append(row)

        return render_template(
            "events.html",
            page="events",
            events=events,
            selected_source=source,
            stats=get_statistics(),
        )

    @app.route("/analytics")
    def analytics_page():
        return render_template(
            "analytics.html",
            page="analytics",
        )

    @app.route("/api/stats")
    def api_stats():
        return jsonify(get_statistics())

    @app.route("/api/alerts")
    def api_alerts():
        return jsonify(get_alerts(limit=100))

    @app.route("/api/analytics")
    def api_analytics():
        return jsonify(
            get_threat_analytics(
                app.config["DATABASE_PATH"]
            )
        )

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