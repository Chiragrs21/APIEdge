from flask import Flask, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import pyshark
import threading
import time
import json
import logging
import datetime
import psutil
import collections
import statistics
from scapy.all import sniff, IP
import signal
import sys

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*")

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Shared data structures
packets = collections.deque(maxlen=1000)  # Store recent packets
# Store request rates for the last 5 minutes
request_rates = collections.deque(maxlen=300)
port_status = {}  # Current open ports
alerts = []  # Security alerts

# Traffic baseline
traffic_baseline = {
    'mean': 10,  # Default baseline, will be updated as data is collected
    'std_dev': 5
}

# Packet capture interface
INTERFACE = r"\Device\NPF_{8137EB5C-B404-4356-BD24-17FD3B77E50F}"

# Target IP and Port to monitor
TARGET_IP = "138.68.79.95"
TARGET_PORT = "80"

# Counter for captured packets
packet_count = 0


def decode_hex_data(hex_data):
    """Helper function to decode hex data to utf-8"""
    try:
        clean_hex = hex_data.replace(':', '')
        payload_bytes = bytes.fromhex(clean_hex)
        return payload_bytes.decode('utf-8', 'ignore')
    except Exception as e:
        logger.error(f"Error decoding payload: {e}")
        return f"Error decoding payload: {e}"


def parse_json(payload):
    """Helper function to parse JSON data"""
    try:
        json_data = json.loads(payload)
        return json_data
    except json.JSONDecodeError:
        return None


def get_open_ports():
    """Get all open ports and the programs using them"""
    open_ports = {}

    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN':
            try:
                process = psutil.Process(conn.pid)
                program = process.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                program = "Unknown"

            port = conn.laddr.port
            open_ports[str(port)] = {
                "status": "OPEN",
                "program": program
            }

    return open_ports


logger = logging.getLogger(__name__)


def analyze_payload(payload, uri="", http_headers=None):
    """
    Analyzes HTTP payload content for SQL injection, command injection, and XSS attacks.
    Payload format: {"email": str, "password": str}
    Returns a dictionary with detection results, attack types, details, and risk score.
    """
    results = {"detected": False, "attack_types": [],
               "details": {}, "risk_score": 0}
    logger.debug(f"Received payload for analysis: {repr(payload)}")
    if not payload or not isinstance(payload, str):
        logger.debug(f"Payload is empty or not a string: {type(payload)}")
        return results
    payload = payload.strip()
    if not payload:
        logger.debug("Payload is empty after stripping")
        return results
    try:
        if '\r\n\r\n' in payload:
            headers, body = payload.split('\r\n\r\n', 1)
        elif '\n\n' in payload:
            headers, body = payload.split('\n\n', 1)
        else:
            logger.debug("No body separator found")
            return results
        logger.debug(f"Extracted body: {repr(body)}")
        json_data = json.loads(body)
        if not isinstance(json_data, dict) or set(json_data.keys()) != {"email", "password"}:
            logger.debug(
                f"Payload does not match expected format: {json_data}")
            return results
        email_value = str(json_data.get("email", "")).lower()
        password_value = str(json_data.get("password", "")).lower()
    except json.JSONDecodeError as e:
        logger.error(
            f"Failed to parse JSON body: {e} | Raw payload: {repr(payload)}")
        return results
    except Exception as e:
        logger.error(
            f"Error processing payload: {e} | Raw payload: {repr(payload)}")
        return results

    logger.debug(f"Parsed JSON: email='{email_value}', password='[hidden]'")

    def add_detection(attack_type, patterns_found, confidence, excerpt=""):
        if attack_type not in results["details"]:
            results["details"][attack_type] = {
                "confidence": confidence, "patterns": patterns_found, "excerpt": excerpt}
            results["attack_types"].append(attack_type)
            results["detected"] = True
            results["risk_score"] = max(results["risk_score"], confidence)
        else:
            results["details"][attack_type]["confidence"] = max(
                results["details"][attack_type]["confidence"], confidence)
            results["details"][attack_type]["patterns"].extend(patterns_found)
            results["risk_score"] = max(results["risk_score"], confidence)

    # SQL Injection Detection
    sql_patterns_high = [
        "union select", "information_schema", "sys.tables", "waitfor delay",
        "sleep(", "benchmark(", "pg_sleep", "--", ";--", "/*", "*/",
        "@@version", "1=1--", "' or '1'='1", "\" or \"1\"=\"1", "or 1=1",
        "' or 1=1--", "admin'--", "' or 'x'='x"
    ]
    sql_patterns_medium = [
        ";", "' or ", "1=1", "true;", "' and '", "' or '", " or true",
        "' LIKE '", "1' or '", "\" or ", "\"=\"", "#", "-- "
    ]
    email_sql_high = [p for p in sql_patterns_high if p in email_value]
    email_sql_medium = [p for p in sql_patterns_medium if p in email_value]
    pass_sql_high = [p for p in sql_patterns_high if p in password_value]
    pass_sql_medium = [p for p in sql_patterns_medium if p in password_value]
    sql_high_matches = email_sql_high + pass_sql_high
    sql_medium_matches = email_sql_medium + pass_sql_medium
    if sql_high_matches or sql_medium_matches:
        sql_confidence = 90 if sql_high_matches else (
            75 if len(sql_medium_matches) >= 2 else 60)
        excerpt = f"email: \"{email_value}\"" if email_sql_high or email_sql_medium else f"password: [hidden]"
        add_detection("sql_injection", sql_high_matches +
                      sql_medium_matches, sql_confidence, excerpt)

    # Command Injection Detection
    cmd_patterns = [
        ";ls", "|ls", "&ls", "&&ls", "`ls`",
        ";cat ", "|cat ", "&cat ", "&&cat ", "`cat`",
        ";id", "|id", "&id", "&&id", "`id`",
        ";whoami", "|whoami", "&whoami", "&&whoami", "`whoami`",
        ";ping", "|ping", "&ping", "&&ping", "`ping`",
        ";bash", "|bash", "&bash", "&&bash", "`bash`"
    ]
    email_cmd_matches = [p for p in cmd_patterns if p in email_value]
    pass_cmd_matches = [p for p in cmd_patterns if p in password_value]
    cmd_matches = email_cmd_matches + pass_cmd_matches
    if cmd_matches:
        cmd_confidence = 90
        excerpt = f"email: \"{email_value}\"" if email_cmd_matches else f"password: [hidden]"
        add_detection("command_injection", cmd_matches,
                      cmd_confidence, excerpt)

    # XSS Detection
    xss_patterns_high = [
        "<script>", "</script>", "javascript:", "alert(", "onerror=", "onload=",
        "document.cookie", "eval(", "exec(", "<img src=", "src='", "src=\"",
        "<iframe", "<svg", "onmouseover=", "onfocus="
    ]
    xss_patterns_medium = [
        "<", ">", "&lt;", "&gt;", "&#x", "%3c", "%3e", "script", "js",
        "on(", "url(", "data:", "vbscript:"
    ]
    email_xss_high = [p for p in xss_patterns_high if p in email_value]
    email_xss_medium = [p for p in xss_patterns_medium if p in email_value]
    pass_xss_high = [p for p in xss_patterns_high if p in password_value]
    pass_xss_medium = [p for p in xss_patterns_medium if p in password_value]
    xss_high_matches = email_xss_high + pass_xss_high
    xss_medium_matches = email_xss_medium + pass_xss_medium
    if xss_high_matches or xss_medium_matches:
        xss_confidence = 90 if xss_high_matches else (
            75 if len(xss_medium_matches) >= 2 else 60)
        excerpt = f"email: \"{email_value}\"" if email_xss_high or email_xss_medium else f"password: [hidden]"
        add_detection("xss", xss_high_matches +
                      xss_medium_matches, xss_confidence, excerpt)

    # Finalize risk score for multiple attack types
    if results["detected"] and len(results["attack_types"]) > 1:
        confidences = [results["details"][at]["confidence"]
                       for at in results["attack_types"]]
        results["risk_score"] = sum(sorted(confidences, reverse=True)[:2]) / 2

    return results


def process_http_packet(packet, alerts):
    # Skip non-HTTP packets or packets without payload
    if packet.get('protocol') != 'HTTP' or 'payload' not in packet:
        return False

    current_time = time.time()
    src_ip = packet.get('src_ip', 'unknown')
    dst_ip = packet.get('dst_ip', 'unknown')

    # Extract relevant HTTP information
    uri = packet.get('http_uri', '')
    http_method = packet.get('http_method', '')
    payload = packet.get('payload', '')
    headers = packet.get('http_headers', {})

    # Skip obviously legitimate requests
    safe_extensions = ['.jpg', '.png', '.gif',
                       '.css', '.js', '.ico', '.svg', '.woff']
    if any(uri.lower().endswith(ext) for ext in safe_extensions):
        return False

    # Don't process empty payloads
    if not payload or len(payload.strip()) < 5:
        return False

    # Log packet summary for debugging
    logger.debug(f"Analyzing HTTP {http_method} {uri} from {src_ip}")

    # Analyze the payload for attacks
    attack_analysis = analyze_payload(payload, uri, headers)

    # If attack detected, create an alert
    if attack_analysis["detected"]:
        # Track attack by IP
        if not hasattr(process_http_packet, 'ip_tracking'):
            process_http_packet.ip_tracking = {}

        if src_ip not in process_http_packet.ip_tracking:
            process_http_packet.ip_tracking[src_ip] = {
                'first_seen': current_time,
                'last_seen': current_time,
                'attack_count': 0,
                'attack_types': set()
            }

        # Update IP tracking data
        process_http_packet.ip_tracking[src_ip]['last_seen'] = current_time
        process_http_packet.ip_tracking[src_ip]['attack_count'] += 1
        process_http_packet.ip_tracking[src_ip]['attack_types'].update(
            attack_analysis["attack_types"])

        # Determine alert severity based on risk score
        severity = "low"
        if attack_analysis["risk_score"] >= 80:
            severity = "critical"
        elif attack_analysis["risk_score"] >= 65:
            severity = "high"
        elif attack_analysis["risk_score"] >= 40:
            severity = "medium"

        # Increase severity if repeat offender
        if process_http_packet.ip_tracking[src_ip]['attack_count'] > 3:
            severity_levels = {'low': 'medium',
                               'medium': 'high', 'high': 'critical'}
            if severity in severity_levels:
                severity = severity_levels[severity]

        # Create a detailed alert
        alert = {
            'id': int(time.time()*1000),
            'type': 'http_attack',
            'attack_types': attack_analysis["attack_types"],
            'message': f"Attack detected from {src_ip}: {', '.join(attack_analysis['attack_types'])}",
            'timestamp': current_time,
            'severity': severity,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'http_method': http_method,
            'uri': uri,
            'confidence': attack_analysis["risk_score"],
            'details': attack_analysis["details"],
            'attack_count': process_http_packet.ip_tracking[src_ip]['attack_count'],
        }

        # Add relevant excerpts from the payload
        for attack_type in attack_analysis["attack_types"]:
            if attack_analysis["details"][attack_type]["excerpt"]:
                alert[f"{attack_type}_excerpt"] = attack_analysis["details"][attack_type]["excerpt"]

        # Clean up old IPs from tracking (keep for 1 hour max)
        cleanup_time = current_time - 3600
        for ip in list(process_http_packet.ip_tracking.keys()):
            if process_http_packet.ip_tracking[ip]['last_seen'] < cleanup_time:
                del process_http_packet.ip_tracking[ip]

        # Add alert and emit event
        alerts.append(alert)
        socketio.emit('http_attack', alert)

        # Block repeat offenders
        if process_http_packet.ip_tracking[src_ip]['attack_count'] >= 4:
            block_alert = {
                'id': int(time.time()*1000 + 1),  # Ensure unique ID
                'type': 'ip_blocked',
                'message': f"IP {src_ip} blocked after {process_http_packet.ip_tracking[src_ip]['attack_count']} attack attempts",
                'timestamp': current_time,
                'severity': 'critical',
                'src_ip': src_ip,
                'attack_types': list(process_http_packet.ip_tracking[src_ip]['attack_types'])
            }
            alerts.append(block_alert)
            socketio.emit('ip_blocked', block_alert)

            # Add blocking code here (e.g., firewall API call)
            # Example: block_ip(src_ip)

        return True

    return False


def packet_analyzer():
    """Analyze network packets and emit events for security threats"""
    baseline_window = collections.deque(maxlen=100)

    while True:
        try:
            # Calculate current request rate (requests per second)
            current_time = time.time()
            recent_packets = [
                p for p in packets if current_time - p['timestamp'] <= 10]
            current_rate = len(recent_packets) / 10 if recent_packets else 0

            # Store request rate
            request_rate = {
                'timestamp': current_time,
                'count': current_rate
            }
            request_rates.append(request_rate)
            socketio.emit('request_rate', request_rate)

            # Update traffic baseline
            baseline_window.append(current_rate)
            if len(baseline_window) >= 50:
                traffic_baseline['mean'] = statistics.mean(baseline_window)
                traffic_baseline['std_dev'] = statistics.stdev(
                    baseline_window) if len(baseline_window) > 1 else 0

            # Traffic anomaly detection
            if current_rate > 0 and traffic_baseline['mean'] > 0:
                increase_factor = current_rate / traffic_baseline['mean']
                if increase_factor > 3:
                    alert = {
                        'id': int(time.time()*1000),
                        'type': 'traffic',
                        'message': f'Traffic spike detected! {current_rate:.1f} req/s ({increase_factor:.1f}x normal)',
                        'timestamp': current_time,
                        'severity': 'high',
                        'current_rate': current_rate,
                        'increase_factor': increase_factor
                    }
                    alerts.append(alert)
                    socketio.emit('anomaly_alert', alert)

            # Process HTTP packets for attack detection
            http_packets = [p for p in list(
                packets)[-30:] if p.get('protocol') == 'HTTP']
            for packet in http_packets:
                process_http_packet(packet, alerts)

            # Update port status
            current_port_status = get_open_ports()

            # Check for new open ports
            for port, info in current_port_status.items():
                if port not in port_status or port_status[port]['status'] != 'OPEN':
                    alert = {
                        'id': int(time.time()*1000),
                        'type': 'port',
                        'message': f"Port {port} opened by {info['program']}",
                        'timestamp': current_time,
                        'severity': 'warning',
                        'port': port,
                        'program': info['program']
                    }
                    alerts.append(alert)
                    socketio.emit('port_change', alert)

            port_status.update(current_port_status)
            socketio.emit('port_status', port_status)

            time.sleep(0.05)  # Run analysis every second

        except Exception as e:
            logger.error(f"Error in packet analyzer: {e}")
            time.sleep(5)  # Wait before retrying


def packet_sniffer():
    """Capture network packets using pyshark with focus on target IP and port"""
    global packet_count

    try:
        logger.info(f"Starting packet sniffer on interface {INTERFACE}")
        logger.info(f"Filtering for IP: {TARGET_IP}, Port: {TARGET_PORT}")

        # Create a display filter to focus on the target IP and port
        display_filter = f"ip.addr == {TARGET_IP} && tcp.port == {TARGET_PORT}"

        # Using LiveCapture with the display filter
        capture = pyshark.LiveCapture(
            interface=INTERFACE,
            display_filter=display_filter
        )

        # Sniff packets continuously
        for packet in capture.sniff_continuously():
            packet_count += 1
            current_time = time.time()

            try:
                # Extract basic packet info
                packet_info = {
                    'timestamp': current_time,
                    'packet_count': packet_count,
                    'protocol': packet.transport_layer if hasattr(packet, 'transport_layer') else packet.highest_layer
                }

                # Extract IP info if available
                if hasattr(packet, 'ip'):
                    packet_info.update({
                        'src_ip': packet.ip.src,
                        'dst_ip': packet.ip.dst
                    })

                # Extract port info if available
                if hasattr(packet, 'tcp'):
                    packet_info.update({
                        'src_port': packet.tcp.srcport,
                        'dst_port': packet.tcp.dstport,
                        'flags': packet.tcp.flags
                    })
                elif hasattr(packet, 'udp'):
                    packet_info.update({
                        'src_port': packet.udp.srcport,
                        'dst_port': packet.udp.dstport
                    })

                # Extract HTTP info with improved payload handling
                if 'HTTP' in packet:
                    packet_info['protocol'] = 'HTTP'

                    # Get HTTP method and URI
                    if hasattr(packet.http, 'request_method'):
                        packet_info['http_method'] = packet.http.request_method
                        packet_info['http_uri'] = packet.http.request_uri if hasattr(
                            packet.http, 'request_uri') else 'Unknown'

                    # Get HTTP host if available
                    if hasattr(packet.http, 'host'):
                        packet_info['http_host'] = packet.http.host

                    # Collect HTTP headers
                    packet_info['http_headers'] = {}
                    if hasattr(packet.http, 'field_names'):
                        for field in packet.http.field_names:
                            if field not in ['request_method', 'request_uri', 'host']:
                                packet_info['http_headers'][field] = getattr(
                                    packet.http, field, 'N/A')

                    # Method 1: Extract payload from HTTP file_data
                    if hasattr(packet.http, 'file_data'):
                        payload = decode_hex_data(packet.http.file_data)
                        packet_info['payload'] = payload

                        # Try to parse JSON payload
                        if payload and (payload.strip().startswith('{') or payload.strip().startswith('[')):
                            json_data = parse_json(payload)
                            if json_data:
                                packet_info['json_payload'] = json_data

                    # Method 2: Extract from TCP payload as fallback
                    elif hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
                        payload = decode_hex_data(packet.tcp.payload)
                        packet_info['payload'] = payload

                # Add packet to our collection
                packets.append(packet_info)

                # Emit to connected clients
                socketio.emit('new_packet', packet_info)

                # Log basic packet info
                logger.info(
                    f"Captured packet #{packet_count} from {packet_info.get('src_ip', 'unknown')} to {packet_info.get('dst_ip', 'unknown')}")

            except Exception as e:
                logger.error(f"Error processing packet: {e}")

    except pyshark.capture.capture.TSharkCrashException:
        logger.error("TShark crashed. Falling back to scapy.")
        fallback_to_scapy()
    except FileNotFoundError:
        logger.error(
            "Could not find Wireshark/TShark executable. Falling back to scapy.")
        fallback_to_scapy()
    except Exception as e:
        logger.error(f"PyShark error: {e}. Falling back to scapy.")
        fallback_to_scapy()


def fallback_to_scapy():
    """Fallback to scapy for packet capture if pyshark fails"""
    global packet_count

    logger.info("Using scapy for packet capture")
    logger.info(f"Filtering for IP: {TARGET_IP}, Port: {TARGET_PORT}")

    def process_scapy_packet(packet):
        global packet_count

        try:
            # Check if packet matches our target IP and port
            if IP in packet and packet.haslayer('TCP'):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet['TCP'].sport
                dst_port = packet['TCP'].dport

                # Filter for packets related to our target IP and port
                if ((src_ip == TARGET_IP and str(src_port) == TARGET_PORT) or
                        (dst_ip == TARGET_IP and str(dst_port) == TARGET_PORT)):

                    packet_count += 1
                    current_time = time.time()

                    packet_info = {
                        'timestamp': current_time,
                        'packet_count': packet_count,
                        'protocol': 'TCP',
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'flags': str(packet['TCP'].flags)
                    }

                    # Process HTTP if possible
                    if packet.haslayer('Raw'):
                        payload = packet['Raw'].load.decode('utf-8', 'ignore')
                        if payload.startswith('GET ') or payload.startswith('POST '):
                            packet_info['protocol'] = 'HTTP'
                            packet_info['payload'] = payload

                            # Try to extract HTTP method and URI
                            lines = payload.split('\r\n')
                            if lines and ' ' in lines[0]:
                                parts = lines[0].split(' ')
                                if len(parts) >= 2:
                                    packet_info['http_method'] = parts[0]
                                    packet_info['http_uri'] = parts[1]

                            # Try to find host header
                            for line in lines:
                                if line.lower().startswith('host:'):
                                    packet_info['http_host'] = line[5:].strip()

                            # Try to parse JSON payload
                            if '{' in payload and '}' in payload:
                                try:
                                    body_start = payload.find('{')
                                    body_end = payload.rfind('}') + 1
                                    json_str = payload[body_start:body_end]
                                    json_data = parse_json(json_str)
                                    if json_data:
                                        packet_info['json_payload'] = json_data
                                except:
                                    pass

                    packets.append(packet_info)
                    socketio.emit('new_packet', packet_info)

                    # Log basic packet info
                    logger.info(
                        f"Captured packet #{packet_count} from {src_ip} to {dst_ip}")
        except Exception as e:
            logger.error(f"Error processing scapy packet: {e}")

    # BPF filter for scapy to focus on target IP and port
    bpf_filter = f"host {TARGET_IP} and port {TARGET_PORT}"
    sniff(filter=bpf_filter, prn=process_scapy_packet, store=0)


# API Routes
@app.route('/api/packets/recent', methods=['GET'])
def get_recent_packets():
    return jsonify(list(packets)[-100:])


@app.route('/api/stats/request_rate', methods=['GET'])
def get_request_rates():
    return jsonify(list(request_rates))


@app.route('/api/ports', methods=['GET'])
def get_ports():
    return jsonify(port_status)


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    return jsonify(alerts)


@socketio.on('connect')
def handle_connect():
    logger.info(f"Client connected: {request.sid}")

    # Send initial data
    emit('port_status', port_status)

    if alerts:
        for alert in alerts[-5:]:
            emit('alert', alert)


@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"Client disconnected: {request.sid}")


if __name__ == '__main__':
    # Start background threads
    threading.Thread(target=packet_sniffer, daemon=True).start()
    threading.Thread(target=packet_analyzer, daemon=True).start()

    # Initialize port status
    port_status = get_open_ports()

    # Start the server
    logger.info(f"Starting server on http://localhost:5000")
    logger.info(f"Monitoring traffic from/to {TARGET_IP}:{TARGET_PORT}")
    socketio.run(app, host='0.0.0.0', port=5000,
                 debug=True, use_reloader=False)
