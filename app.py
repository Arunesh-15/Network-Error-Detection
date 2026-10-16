import threading
import io
import csv
from flask import Flask, render_template, jsonify, request, Response
from flask_socketio import SocketIO
from capture import monitor, start_capture, get_available_interfaces

app = Flask(__name__)
app.config["SECRET_KEY"] = "network_sentinel_secret_key_2026"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/stats")
def api_stats():
    return jsonify(monitor.get_stats())


@app.route("/api/recent")
def api_recent():
    with monitor.lock:
        return jsonify(list(monitor.history))


@app.route("/api/errors")
def api_errors():
    with monitor.lock:
        return jsonify(list(monitor.error_history))


@app.route("/api/interfaces")
def api_interfaces():
    return jsonify(get_available_interfaces())


@app.route("/api/pause", methods=["POST"])
def api_pause():
    data = request.get_json(silent=True) or {}
    # If state explicitly passed use it, otherwise toggle
    target_state = data.get("paused")
    if target_state is None:
        target_state = not monitor.is_paused
    
    current_state = monitor.set_pause(target_state)
    fresh_stats = monitor.get_stats()
    socketio.emit("pause_state_changed", {"is_paused": current_state, "stats": fresh_stats})
    return jsonify({"status": "success", "is_paused": current_state, "stats": fresh_stats})


@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    data = request.get_json(silent=True) or {}
    error_type = data.get("type", "TCP_RST")
    count = int(data.get("count", 1))
    
    generated = []
    for _ in range(min(count, 20)):
        if error_type == "NORMAL":
            pkt = monitor.generate_simulated_packet(force_error_type="NONE")
        elif error_type == "BURST":
            import random
            err = random.choice(["TCP_RST", "ICMP_UNREACHABLE", "OVERSIZED_MTU"]) if random.random() < 0.4 else None
            pkt = monitor.generate_simulated_packet(force_error_type=err)
        else:
            pkt = monitor.generate_simulated_packet(force_error_type=error_type)
        
        socketio.emit("packet", pkt)
        generated.append(pkt)

    return jsonify({"status": "success", "count": len(generated), "stats": monitor.get_stats()})


@app.route("/api/reset", methods=["POST"])
def api_reset():
    monitor.reset()
    fresh_stats = monitor.get_stats()
    socketio.emit("stats_reset", fresh_stats)
    return jsonify({"status": "success", "stats": fresh_stats})


@app.route("/api/export")
def api_export():
    format_type = request.args.get("format", "csv").lower()
    export_filter = request.args.get("filter", "all").lower()

    with monitor.lock:
        if export_filter == "errors":
            packets = list(monitor.error_history)
        else:
            packets = list(monitor.history)

    if format_type == "json":
        return jsonify(packets)

    # Default CSV Export
    output = io.StringIO()
    fieldnames = [
        "id", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
        "protocol", "length", "flags", "is_error", "error_type", "error_detail"
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()
    for pkt in packets:
        writer.writerow(pkt)
    
    output.seek(0)
    filename = "network_errors_log.csv" if export_filter == "errors" else "network_packet_log.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )


@socketio.on("connect")
def handle_connect():
    with monitor.lock:
        recent = list(monitor.history)[-50:]
        recent_errs = list(monitor.error_history)
    socketio.emit("init_state", {
        "stats": monitor.get_stats(),
        "recent_packets": recent,
        "recent_errors": recent_errs
    })


def send_packet(data):
    socketio.emit("packet", data)


def capture_thread():
    start_capture(send_packet)


if __name__ == "__main__":
    t = threading.Thread(target=capture_thread, daemon=True)
    t.start()
    print("[CyberPulse] Network Error Detection Server starting on http://127.0.0.1:5000")
    socketio.run(app, host="127.0.0.1", port=5000, debug=False, allow_unsafe_werkzeug=True)