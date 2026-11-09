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


APP_VERSION = "0.9.0"


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

    
    @app.get("/api/windows-events")
    def api_windows_events():
        """Return recent Windows authentication events."""

        from contextlib import closing
        import json

        from flask import jsonify, request
        from database.db_manager import get_connection

        allowed_types = {
            "ALL", "SUCCESS_LOGIN", "FAILED_LOGIN"
        }

        event_type = request.args.get(
            "type", "ALL"
        ).upper()

        logon_type = request.args.get(
            "logon_type", "ALL"
        ).upper()

        search = request.args.get(
            "search", ""
        ).strip()[:100]

        if event_type not in allowed_types:
            return jsonify({
                "error": "Invalid event type."
            }), 400

        query = """
            SELECT id, event_source, event_type,
                   event_timestamp, source_ip,
                   username, event_data
            FROM security_events
            WHERE event_source = 'authentication'
            ORDER BY event_timestamp DESC, id DESC
            LIMIT 5000
        """

        with closing(get_connection(db_path or DEFAULT_DB_PATH)) as connection:
            rows = connection.execute(query).fetchall()

        results = []

        for row in rows:
            try:
                metadata = json.loads(
                    row["event_data"] or "{}"
                )
            except (ValueError, TypeError):
                metadata = {}

            if metadata.get("event_origin") != "windows_security":
                continue

            if (
                event_type != "ALL"
                and row["event_type"] != event_type
            ):
                continue

            if (
                logon_type != "ALL"
                and metadata.get(
                    "logon_type_name", ""
                ).upper() != logon_type
            ):
                continue

            username = row["username"] or ""
            source_ip = row["source_ip"] or ""

            searchable = " ".join([
                username,
                source_ip,
                str(metadata.get("computer", "")),
                str(metadata.get("windows_event_id", "")),
            ]).lower()

            if search and search.lower() not in searchable:
                continue

            results.append({
                "id": row["id"],
                "timestamp": row["event_timestamp"],
                "event_type": row["event_type"],
                "username": username,
                "source_ip": source_ip,
                "windows_event_id": metadata.get(
                    "windows_event_id"
                ),
                "logon_type": metadata.get(
                    "logon_type"
                ),
                "logon_type_name": metadata.get(
                    "logon_type_name", "UNKNOWN"
                ),
                "computer": metadata.get("computer"),
                "windows_record_id": metadata.get(
                    "windows_record_id"
                ),
                "is_remote_authentication": metadata.get(
                    "is_remote_authentication", False
                ),
            })

            if len(results) >= 500:
                break

        return jsonify({
            "total": len(results),
            "events": results,
        })


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

        platform = request.args.get(
            "platform", "all"
        ).lower()

        allowed_sources = {
            "all", "authentication", "network"
        }

        allowed_platforms = {
            "all",
            "windows",
            "linux",
            "other",
        }

        if source not in allowed_sources:
            abort(400, description="Invalid event source.")

        if platform not in allowed_platforms:
            abort(400, description="Invalid platform filter.")

        conditions = []
        parameters = []

        if source != "all":
            conditions.append("event_source = ?")
            parameters.append(source)

        if platform != "all":
            # Platform filters apply only to authentication logs.
            conditions.append("event_source = 'authentication'")

            if platform == "windows":
                conditions.append(
                    "json_extract(event_data, '$.event_origin') "
                    "= 'windows_security'"
                )

            elif platform == "linux":
                conditions.append(
                    "json_extract(event_data, '$.event_origin') "
                    "= 'linux_ssh'"
                )

            elif platform == "other":
                conditions.append(
                    "("
                    "json_extract(event_data, '$.event_origin') IS NULL "
                    "OR json_extract(event_data, '$.event_origin') "
                    "NOT IN ('windows_security', 'linux_ssh')"
                    ")"
                )

        query = "SELECT * FROM security_events"

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += (
            " ORDER BY event_timestamp DESC, id DESC "
            "LIMIT 500"
        )

        events = fetch_all(query, tuple(parameters))

        for event in events:
            try:
                event["details"] = json.loads(
                    event["event_data"] or "{}"
                )
            except (ValueError, TypeError):
                event["details"] = {}

            origin = event["details"].get("event_origin")

            if origin == "windows_security":
                event["platform_name"] = "Windows"
            elif origin == "linux_ssh":
                event["platform_name"] = "Linux SSH"
            elif event["event_source"] == "network":
                event["platform_name"] = "Network"
            else:
                event["platform_name"] = "Other"

        return render_template(
            "events.html",
            page="events",
            events=events,
            selected_source=source,
            selected_platform=platform,
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
    
    @app.get("/windows-events")
    def windows_events_page():
        return render_template(
            "windows_events.html",
            page="windows_events",
            app_version=APP_VERSION,
        )

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