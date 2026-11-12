import os
import json
import logging
import hmac
import uuid
from pathlib import Path
from urllib.parse import urlparse
from flask import Flask, Response, render_template, request, jsonify, send_file, redirect, url_for
from werkzeug.utils import secure_filename

from backend.config import Config
from backend.database.db import init_db, query_db, execute_db
from backend.analyzer.statistics import TrafficStatistics
from backend.capture.live_capture import LiveCaptureService
from backend.capture.socket_traffic import TrafficGenerator
from backend.capture.pcap_handler import PCAPHandler
from backend.detector.detection_engine import DetectionEngine
from backend.forensics.evidence_vault import EvidenceVaultService
from backend.forensics.chain_of_custody import ChainOfCustodyService
from backend.forensics.report_generator import ForensicReportGenerator
from backend.simulation.ns2_parser import NS2TraceAnalyzer
from backend.evaluation.evaluator import EvaluationFramework

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

app = Flask(
    __name__,
    template_folder="frontend/templates",
    static_folder="frontend/static"
)
app.config.from_object(Config)


@app.before_request
def require_configured_password():
    """Require HTTP Basic authentication when a deployment password is set."""
    if request.endpoint == "health" or not app.config.get("APP_PASSWORD"):
        return None

    credentials = request.authorization
    username = app.config.get("APP_USERNAME", "analyst")
    password = app.config["APP_PASSWORD"]
    if (credentials is None
            or not hmac.compare_digest(credentials.username or "", username)
            or not hmac.compare_digest(credentials.password or "", password)):
        return Response(
            "Authentication required", 401,
            {"WWW-Authenticate": 'Basic realm="Network Tool", charset="UTF-8"'}
        )

    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        origin = request.headers.get("Origin")
        if origin and urlparse(origin).netloc.casefold() != request.host.casefold():
            return jsonify({"success": False, "error": "Cross-origin request rejected"}), 403
    return None


@app.after_request
def set_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


@app.get("/health")
def health():
    """Lightweight readiness endpoint for the hosting platform."""
    try:
        query_db("SELECT 1", one=True)
        return jsonify({"status": "ok"}), 200
    except Exception:
        logger.exception("Health check failed")
        return jsonify({"status": "unavailable"}), 503

# Ensure DB initialized on startup
with app.app_context():
    init_db()

# ==============================================================================
# PAGE ROUTING (10 CORE SECTIONS + EVALUATION)
# ==============================================================================

@app.route("/")
@app.route("/overview")
def page_overview():
    stats = TrafficStatistics.get_overview_statistics()
    recent_incidents = query_db("SELECT * FROM incidents ORDER BY detected_at DESC LIMIT 6")
    top_hosts = TrafficStatistics.get_top_hosts(limit=5)
    top_ports = TrafficStatistics.get_top_ports(limit=5)
    return render_template(
        "overview.html",
        active_page="overview",
        stats=stats,
        recent_incidents=recent_incidents,
        top_hosts=top_hosts,
        top_ports=top_ports
    )

@app.route("/live-traffic")
def page_live_traffic():
    interfaces = LiveCaptureService.get_network_interfaces()
    status = LiveCaptureService.get_status()
    recent_sessions = query_db("SELECT * FROM capture_sessions ORDER BY start_time DESC LIMIT 8")
    return render_template(
        "live_traffic.html",
        active_page="live_traffic",
        interfaces=interfaces,
        status=status,
        recent_sessions=recent_sessions
    )

@app.route("/packet-analyzer")
def page_packet_analyzer():
    sessions = query_db("SELECT id, session_name FROM capture_sessions ORDER BY start_time DESC LIMIT 20")
    protocols = query_db("SELECT DISTINCT protocol FROM packets ORDER BY protocol ASC")
    return render_template(
        "packet_analyzer.html",
        active_page="packet_analyzer",
        sessions=sessions,
        protocols=[p["protocol"] for p in protocols]
    )

@app.route("/incident-detection")
def page_incident_detection():
    incidents = query_db("SELECT * FROM incidents ORDER BY detected_at DESC")
    settings_rows = query_db("SELECT * FROM detection_settings")
    settings = {r["setting_key"]: r["setting_value"] for r in settings_rows}
    return render_template(
        "incident_detection.html",
        active_page="incident_detection",
        incidents=incidents,
        settings=settings
    )

@app.route("/timeline")
def page_timeline():
    incident_id = request.args.get("incident_id")
    incidents = query_db("SELECT id, title, incident_type, severity FROM incidents ORDER BY detected_at DESC")
    
    where = "WHERE incident_id = ?" if incident_id else ""
    params = [incident_id] if incident_id else []
    events = query_db(f"""
        SELECT e.*, i.title as incident_title, i.incident_type
        FROM incident_events e
        LEFT JOIN incidents i ON e.incident_id = i.id
        {where}
        ORDER BY e.timestamp DESC
        LIMIT 100
    """, params)

    selected_incident = None
    if incident_id:
        selected_incident = query_db("SELECT * FROM incidents WHERE id = ?", (incident_id,), one=True)

    return render_template(
        "timeline.html",
        active_page="timeline",
        incidents=incidents,
        events=events,
        selected_incident_id=incident_id,
        selected_incident=selected_incident
    )

@app.route("/evidence-vault")
def page_evidence_vault():
    evidence_list = query_db("""
        SELECT e.*, i.incident_type, i.severity as incident_severity
        FROM evidence e
        LEFT JOIN incidents i ON e.incident_id = i.id
        ORDER BY e.collected_at DESC
    """)
    return render_template(
        "evidence_vault.html",
        active_page="evidence_vault",
        evidence_list=evidence_list
    )

@app.route("/chain-of-custody")
def page_chain_of_custody():
    evidence_id = request.args.get("evidence_id")
    action_filter = request.args.get("action", "ALL")
    search = request.args.get("q", "")
    records = ChainOfCustodyService.get_audit_trail(evidence_id, action_filter, search)
    evidence_items = query_db("SELECT id, original_filename FROM evidence ORDER BY collected_at DESC")
    return render_template(
        "chain_of_custody.html",
        active_page="chain_of_custody",
        records=records,
        evidence_items=evidence_items,
        selected_evidence_id=evidence_id,
        selected_action=action_filter,
        search_query=search
    )

@app.route("/ns2-simulation")
def page_ns2_simulation():
    recent_sims = query_db("SELECT * FROM simulation_results ORDER BY execution_timestamp DESC LIMIT 10")
    sample_trace = Path(__file__).resolve().parent / "simulation" / "sample_traces" / "sample_simulation.tr"
    has_sample = sample_trace.exists()
    return render_template(
        "ns2_simulation.html",
        active_page="ns2_simulation",
        recent_sims=recent_sims,
        has_sample=has_sample
    )

@app.route("/reports")
def page_reports():
    reports = query_db("""
        SELECT r.*, i.incident_type, i.severity
        FROM forensic_reports r
        LEFT JOIN incidents i ON r.incident_id = i.id
        ORDER BY r.generated_at DESC
    """)
    incidents = query_db("SELECT id, title, incident_type, severity FROM incidents ORDER BY detected_at DESC")
    return render_template(
        "reports.html",
        active_page="reports",
        reports=reports,
        incidents=incidents
    )

@app.route("/evaluation")
def page_evaluation():
    return render_template(
        "evaluation.html",
        active_page="evaluation"
    )

@app.route("/settings")
def page_settings():
    settings_rows = query_db("SELECT * FROM detection_settings")
    settings = {r["setting_key"]: r["setting_value"] for r in settings_rows}
    interfaces = LiveCaptureService.get_network_interfaces()
    return render_template(
        "settings.html",
        active_page="settings",
        settings=settings,
        interfaces=interfaces,
        db_path=Config.DATABASE_PATH,
        evidence_path=Config.EVIDENCE_PATH,
        reports_path=Config.REPORTS_PATH
    )


# ==============================================================================
# REST API ENDPOINTS
# ==============================================================================

# --- Analytics & Statistics APIs ---
@app.route("/api/stats/overview")
def api_stats_overview():
    session_id = request.args.get("session_id")
    stats = TrafficStatistics.get_overview_statistics(session_id)
    return jsonify(stats)

@app.route("/api/stats/activity-timeline")
def api_stats_activity_timeline():
    session_id = request.args.get("session_id")
    buckets = int(request.args.get("buckets", 25))
    timeline = TrafficStatistics.get_traffic_activity_timeline(session_id, buckets)
    return jsonify(timeline)

@app.route("/api/stats/protocol-distribution")
def api_stats_protocol_distribution():
    session_id = request.args.get("session_id")
    dist = TrafficStatistics.get_protocol_distribution(session_id)
    return jsonify(dist)

@app.route("/api/stats/incident-distribution")
def api_stats_incident_distribution():
    session_id = request.args.get("session_id")
    dist = TrafficStatistics.get_incident_type_distribution(session_id)
    return jsonify(dist)

# --- Live Capture APIs ---
@app.route("/api/capture/interfaces")
def api_capture_interfaces():
    return jsonify(LiveCaptureService.get_network_interfaces())

@app.route("/api/capture/status")
def api_capture_status():
    return jsonify(LiveCaptureService.get_status())

@app.route("/api/capture/start", methods=["POST"])
def api_capture_start():
    data = request.get_json(silent=True) or {}
    interface = data.get("interface")
    packet_limit = int(data.get("packet_limit", Config.DEFAULT_CAPTURE_PACKET_LIMIT))
    success, message = LiveCaptureService.start_capture(interface, packet_limit)
    return jsonify({"success": success, "message": message})

@app.route("/api/capture/stop", methods=["POST"])
def api_capture_stop():
    success, result = LiveCaptureService.stop_capture()
    return jsonify({"success": success, "result": result})

# --- PCAP Upload API ---
@app.route("/api/capture/upload-pcap", methods=["POST"])
def api_capture_upload():
    if "pcap_file" not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"}), 400

    file = request.files["pcap_file"]
    if not file.filename:
        return jsonify({"success": False, "error": "No filename specified"}), 400

    original_filename = secure_filename(file.filename)
    if not (original_filename.lower().endswith(".pcap") or original_filename.lower().endswith(".pcapng")):
        return jsonify({"success": False, "error": "Only .pcap and .pcapng files are supported"}), 400

    temp_save_path = Path(Config.UPLOADS_PATH) / f"{uuid.uuid4().hex}_{original_filename}"
    file.save(temp_save_path)

    try:
        result = PCAPHandler.process_pcap_file(temp_save_path, original_filename, is_demo=0)
        return jsonify({"success": True, "data": result})
    except Exception as e:
        logger.error(f"Error processing uploaded PCAP: {e}")
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        temp_save_path.unlink(missing_ok=True)

# --- Simulated Traffic APIs (Localhost restricted) ---
@app.route("/api/simulation/traffic/normal", methods=["POST"])
def api_sim_traffic_normal():
    raw_res = TrafficGenerator.generate_normal_traffic(count=20)
    sim_res = TrafficGenerator.record_and_correlate_simulation("normal")
    return jsonify({"success": True, "result": raw_res, "session": sim_res})

@app.route("/api/simulation/traffic/port-scan", methods=["POST"])
def api_sim_traffic_port_scan():
    raw_res = TrafficGenerator.simulate_port_scan(start_port=8000, num_ports=25)
    sim_res = TrafficGenerator.record_and_correlate_simulation("port_scan")
    return jsonify({"success": True, "result": raw_res, "session": sim_res})

@app.route("/api/simulation/traffic/syn-flood", methods=["POST"])
def api_sim_traffic_syn_flood():
    raw_res = TrafficGenerator.simulate_syn_flood(target_port=9090, count=110)
    sim_res = TrafficGenerator.record_and_correlate_simulation("syn_flood")
    return jsonify({"success": True, "result": raw_res, "session": sim_res})

@app.route("/api/simulation/traffic/brute-force", methods=["POST"])
def api_sim_traffic_brute_force():
    raw_res = TrafficGenerator.simulate_brute_force_login(service_port=22, attempts=14)
    sim_res = TrafficGenerator.record_and_correlate_simulation("brute_force")
    return jsonify({"success": True, "result": raw_res, "session": sim_res})

@app.route("/api/simulation/traffic/data-exfil", methods=["POST"])
def api_sim_traffic_data_exfil():
    raw_res = TrafficGenerator.simulate_data_exfiltration(target_port=9095, total_kb=300)
    sim_res = TrafficGenerator.record_and_correlate_simulation("data_exfil")
    return jsonify({"success": True, "result": raw_res, "session": sim_res})

# --- Packets Query API ---
@app.route("/api/packets")
def api_packets():
    session_id = request.args.get("session_id")
    protocol = request.args.get("protocol")
    src_ip = request.args.get("src_ip")
    dst_ip = request.args.get("dst_ip")
    port = request.args.get("port")
    suspicious_only = request.args.get("suspicious") == "1"
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 50))
    offset = (page - 1) * limit

    conditions = []
    params = []

    if session_id:
        conditions.append("session_id = ?")
        params.append(session_id)
    if protocol:
        conditions.append("protocol = ?")
        params.append(protocol)
    if src_ip:
        conditions.append("src_ip LIKE ?")
        params.append(f"%{src_ip}%")
    if dst_ip:
        conditions.append("dst_ip LIKE ?")
        params.append(f"%{dst_ip}%")
    if port:
        conditions.append("(src_port = ? OR dst_port = ?)")
        params.extend([int(port), int(port)])
    if suspicious_only:
        conditions.append("is_suspicious = 1")

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    count_row = query_db(f"SELECT COUNT(*) as total FROM packets {where_clause}", params, one=True)
    total_records = count_row["total"] if count_row else 0

    query = f"""
        SELECT * FROM packets {where_clause}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    """
    rows = query_db(query, params + [limit, offset])

    return jsonify({
        "total": total_records,
        "page": page,
        "limit": limit,
        "packets": rows
    })

@app.route("/api/packets/<int:packet_id>")
def api_packet_detail(packet_id):
    pkt = query_db("SELECT * FROM packets WHERE id = ?", (packet_id,), one=True)
    if not pkt:
        return jsonify({"error": "Packet not found"}), 404
    return jsonify(pkt)

# --- Incident APIs ---
@app.route("/api/incidents")
def api_incidents():
    inc_type = request.args.get("type")
    severity = request.args.get("severity")
    status = request.args.get("status")

    conditions = []
    params = []

    if inc_type and inc_type != "ALL":
        conditions.append("incident_type = ?")
        params.append(inc_type)
    if severity and severity != "ALL":
        conditions.append("severity = ?")
        params.append(severity)
    if status and status != "ALL":
        conditions.append("status = ?")
        params.append(status)

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    query = f"SELECT * FROM incidents {where_clause} ORDER BY detected_at DESC"
    rows = query_db(query, params)
    return jsonify(rows)

@app.route("/api/incidents/<incident_id>")
def api_incident_detail(incident_id):
    inc = query_db("SELECT * FROM incidents WHERE id = ?", (incident_id,), one=True)
    if not inc:
        return jsonify({"error": "Incident not found"}), 404

    events = query_db("SELECT * FROM incident_events WHERE incident_id = ? ORDER BY timestamp ASC", (incident_id,))
    notes = query_db("SELECT * FROM investigation_notes WHERE incident_id = ? ORDER BY created_at ASC", (incident_id,))
    evidence = query_db("SELECT * FROM evidence WHERE incident_id = ? OR session_id = ? ORDER BY id DESC LIMIT 1",
                        (incident_id, inc.get("session_id")), one=True)

    return jsonify({
        "incident": inc,
        "events": events,
        "notes": notes,
        "evidence": evidence
    })

@app.route("/api/incidents/<incident_id>/status", methods=["POST"])
def api_update_incident_status(incident_id):
    data = request.get_json(silent=True) or {}
    new_status = data.get("status")
    analyst = data.get("analyst", "Lead Examiner")

    if new_status not in ["New", "Investigating", "Resolved"]:
        return jsonify({"error": "Invalid status"}), 400

    DetectionEngine.update_incident_status(incident_id, new_status, analyst)
    return jsonify({"success": True, "status": new_status})

@app.route("/api/incidents/<incident_id>/notes", methods=["POST"])
def api_add_incident_note(incident_id):
    data = request.get_json(silent=True) or {}
    author = data.get("author", "Forensic Examiner")
    note_text = data.get("note_text", "").strip()

    if not note_text:
        return jsonify({"error": "Note text is required"}), 400

    DetectionEngine.add_investigation_note(incident_id, author, note_text)
    return jsonify({"success": True})

# --- Evidence Vault APIs ---
@app.route("/api/evidence/<evidence_id>/verify", methods=["POST"])
def api_verify_evidence(evidence_id):
    data = request.get_json(silent=True) or {}
    verifier = data.get("verifier", "Forensic Analyst")
    try:
        res = EvidenceVaultService.verify_evidence_integrity(evidence_id, verifier)
        return jsonify({"success": True, "result": res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/evidence/<evidence_id>/simulate-tamper", methods=["POST"])
def api_simulate_tamper(evidence_id):
    try:
        res = EvidenceVaultService.simulate_tampering_for_demo(evidence_id)
        return jsonify({"success": True, "result": res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/evidence/<evidence_id>/download")
def api_download_evidence(evidence_id):
    evd = query_db("SELECT * FROM evidence WHERE id = ?", (evidence_id,), one=True)
    if not evd:
        return "Evidence record not found", 404

    path = Path(evd["file_path"])
    if not path.exists():
        return "File missing from disk", 404

    # Log access in Chain of Custody
    ChainOfCustodyService.record_action(
        evidence_id=evidence_id,
        action="EVIDENCE_ACCESSED",
        actor="Analyst / Examiner",
        actor_role="Forensic Investigator",
        file_hash=evd["sha256_hash"],
        description=f"Preserved evidence file '{evd['stored_filename']}' downloaded for offline examination.",
        verification_result="DOWNLOADED"
    )

    return send_file(str(path), as_attachment=True, download_name=evd["original_filename"])

# --- Chain of Custody API ---
@app.route("/api/chain-of-custody")
def api_chain_of_custody():
    evidence_id = request.args.get("evidence_id")
    action = request.args.get("action", "ALL")
    search = request.args.get("q", "")
    records = ChainOfCustodyService.get_audit_trail(evidence_id, action, search)
    return jsonify(records)

# --- NS-2 Simulation APIs ---
@app.route("/api/ns2/run-sample", methods=["POST"])
def api_ns2_run_sample():
    data = request.get_json(silent=True) or {}
    scenario = data.get("scenario", "normal")
    sample_dir = Path(__file__).resolve().parent / "simulation" / "sample_traces"
    sample_dir.mkdir(parents=True, exist_ok=True)
    target_tr = sample_dir / f"ns2_{scenario}_trace.tr"

    scenario_titles = {
        "normal": "Normal Network Communication (CBR/FTP)",
        "flooding": "High-Rate UDP Flooding Attack",
        "lossy": "Bottleneck & Packet Loss Scenario"
    }

    # Generate trace
    NS2TraceAnalyzer.generate_sample_trace(target_tr, scenario=scenario)
    analysis = NS2TraceAnalyzer.analyze_trace_file(target_tr, scenario_name=scenario_titles.get(scenario, "Simulation"))
    return jsonify({"success": True, "analysis": analysis})

@app.route("/api/ns2/upload-trace", methods=["POST"])
def api_ns2_upload_trace():
    if "trace_file" not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"}), 400

    file = request.files["trace_file"]
    if not file.filename:
        return jsonify({"success": False, "error": "No filename provided"}), 400

    safe_name = secure_filename(file.filename)
    if not safe_name:
        return jsonify({"success": False, "error": "Invalid trace filename"}), 400
    dest_path = Path(Config.UPLOADS_PATH) / uuid.uuid4().hex / safe_name
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    file.save(dest_path)

    try:
        analysis = NS2TraceAnalyzer.analyze_trace_file(dest_path, scenario_name=f"Custom Trace: {safe_name}")
        return jsonify({"success": True, "analysis": analysis})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- Forensic Report APIs ---
@app.route("/api/reports/generate/<incident_id>", methods=["POST"])
def api_generate_report(incident_id):
    data = request.get_json(silent=True) or {}
    generated_by = data.get("examiner", "Lead Forensic Analyst")
    try:
        report_info = ForensicReportGenerator.create_report_for_incident(incident_id, generated_by)
        return jsonify({"success": True, "report": report_info})
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/reports/<report_id>/download")
def api_download_report(report_id):
    rep = query_db("SELECT * FROM forensic_reports WHERE id = ?", (report_id,), one=True)
    if not rep:
        return "Report not found", 404

    path = Path(rep["file_path"])
    if not path.exists():
        return "Report file not found on disk", 404

    return send_file(str(path), as_attachment=True, download_name=Path(rep["file_path"]).name)

# --- Evaluation & Benchmarking API ---
@app.route("/api/evaluation/run", methods=["POST"])
def api_evaluation_run():
    try:
        res = EvaluationFramework.run_full_evaluation()
        return jsonify({"success": True, "evaluation": res})
    except Exception as e:
        logger.error(f"Evaluation error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

# --- Demo Mode Seeder & Cleaner APIs ---
@app.route("/api/demo/seed", methods=["POST"])
def api_demo_seed():
    try:
        res = EvaluationFramework.seed_demo_data()
        return jsonify({"success": True, "result": res})
    except Exception as e:
        logger.error(f"Error seeding demo data: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/demo/clear", methods=["POST"])
def api_demo_clear():
    try:
        EvaluationFramework.clear_demo_data()
        return jsonify({"success": True, "message": "Demo data safely cleared. Evidence Vault and Chain of Custody preserved."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# --- Settings API ---
@app.route("/api/settings", methods=["POST"])
def api_save_settings():
    data = request.get_json(silent=True) or {}
    for key, val in data.items():
        execute_db("""
            UPDATE detection_settings
            SET setting_value = ?
            WHERE setting_key = ?
        """, (str(val), key))
    return jsonify({"success": True, "message": "Settings updated successfully"})

if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=app.config.get("DEBUG", False)
    )
