from flask import Flask, render_template, request
from scanner import check_security_headers
from database import initialize_database, get_connection
from urllib.parse import urlparse
import ipaddress
import socket

app = Flask(__name__)

# Create the database table when the app starts.
initialize_database()


@app.route("/")
def home():
    connection = get_connection()

    total_scans = connection.execute(
        "SELECT COUNT(*) FROM scans"
    ).fetchone()[0]

    total_findings = connection.execute(
        
        "SELECT COALESCE(SUM(findings_count), 0) FROM scans"
    ).fetchone()[0]

    last_scan_row = connection.execute(
        "SELECT status FROM scans ORDER BY id DESC LIMIT 1"
    ).fetchone()
    recent_scans = connection.execute(
        "SELECT target, status, findings_count, scanned_at FROM scans ORDER BY id DESC LIMIT 5"
    ).fetchall()
    connection.close()

    last_scan = last_scan_row["status"] if last_scan_row else "Not yet"

    return render_template(
        "index.html",
        total_scans=total_scans,
        total_findings=total_findings,
        last_scan=last_scan,
        recent_scans=recent_scans

    )


@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target", "").strip()

    if not target.startswith(("http://", "https://")):
        return "Please enter a valid HTTP or HTTPS URL.", 400

    parsed = urlparse(target)
    host = parsed.hostname

    if not host:
        return "Invalid target URL.", 400

    try:
        addresses = socket.getaddrinfo(host, None)
        ips = {ipaddress.ip_address(item[4][0]) for item in addresses}
    except (socket.gaierror, ValueError):
        return "Target host could not be resolved.", 400

    if not ips or not all(
        ip.is_private or ip.is_loopback for ip in ips
    ):
        return (
            "For this prototype, use only localhost or "
            "a private lab target you are authorized to test.",
            400
        )

    result = check_security_headers(target)

    if result["error"]:
        return f"Scan request failed: {result['error']}", 502

    connection = get_connection()

    connection.execute(
        """
        INSERT INTO scans (target, status, findings_count)
        VALUES (?, ?, ?)
        """,
        (target, result["status"], len(result["findings"]))
    )

    connection.commit()
    connection.close()

    return render_template(
        "results.html",
        target=target,
        result=result
    )


if __name__ == "__main__":
    app.run(debug=True)