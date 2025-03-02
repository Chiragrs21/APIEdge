import pyshark
import json
import signal
import sys
from datetime import datetime

# Define target IP and Port
TARGET_IP = "138.68.79.95"  # Change this to your target IP
TARGET_PORT = "80"  # Change this to your target port

INTERFACE = r"\Device\NPF_{8137EB5C-B404-4356-BD24-17FD3B77E50F}"

# Counter for captured packets
packet_count = 0


def signal_handler(sig, frame):
    """Handle Ctrl+C to exit gracefully"""
    print(f"\nCapture stopped. Total packets captured: {packet_count}")
    sys.exit(0)


def decode_hex_data(hex_data):
    """Helper function to decode hex data to utf-8"""
    try:
        clean_hex = hex_data.replace(':', '')
        payload_bytes = bytes.fromhex(clean_hex)
        return payload_bytes.decode('utf-8', 'ignore')
    except Exception as e:
        return f"Error decoding payload: {e}"


def parse_json(payload):
    """Helper function to parse JSON data"""
    try:
        json_data = json.loads(payload)
        return json.dumps(json_data, indent=4)
    except json.JSONDecodeError:
        return "Payload is not valid JSON."


def save_to_file(packet_data, filename=None):
    """Save packet data to a file"""
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"packet_capture_{timestamp}.txt"

    with open(filename, 'a', encoding='utf-8') as f:
        f.write(packet_data + "\n\n")

    return filename


def main():
    global packet_count

    print(f"Listening on {INTERFACE}...")
    print(
        f"Filtering for HTTP POST requests from IP: {TARGET_IP}, Port: {TARGET_PORT}")
    print("Press Ctrl+C to stop the capture")

    try:
        # Register signal handler for clean exit
        signal.signal(signal.SIGINT, signal_handler)

        # Capture only HTTP POST requests from the target IP and port
        capture = pyshark.LiveCapture(
            interface=INTERFACE,
            display_filter=f"http.request.method == POST && ip.addr == {TARGET_IP} && tcp.port == {TARGET_PORT}"
        )

        # Sniff packets continuously
        for packet in capture.sniff_continuously():
            if "HTTP" in packet and hasattr(packet.http, "request_method") and packet.http.request_method == "POST":
                packet_count += 1
                output = ["\n========== HTTP POST Request Captured =========="]
                output.append(f"Packet #: {packet_count}")
                output.append(
                    f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                output.append(f"Source IP: {packet.ip.src}")
                output.append(f"Destination IP: {packet.ip.dst}")
                output.append(f"Host: {packet.http.host}")
                output.append(f"Path: {packet.http.request_uri}")

                output.append("\nHeaders:")
                for field in packet.http.field_names:
                    if field not in ['request_method', 'request_uri', 'host']:
                        output.append(
                            f"  {field}: {getattr(packet.http, field, 'N/A')}")

                # Capture and decode the payload
                payload = None

                # Method 1: Decode HTTP File Data
                if hasattr(packet.http, 'file_data'):
                    payload = decode_hex_data(packet.http.file_data)
                    output.append("\nDecoded Payload (HTTP File Data):")
                    output.append(payload)

                    # Try to parse as JSON
                    if payload.strip().startswith('{') or payload.strip().startswith('['):
                        json_result = parse_json(payload)
                        output.append("\nParsed JSON Data:")
                        output.append(json_result)

                # Method 2: Decode raw TCP payload as a fallback
                elif hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
                    payload = decode_hex_data(packet.tcp.payload)
                    output.append("\nDecoded Payload (TCP Payload):")
                    output.append(payload)

                else:
                    output.append("\nNo payload data found.")

                output.append(
                    "\n===============================================")

                # Join all output lines and print
                packet_data = '\n'.join(output)
                print(packet_data)

                # Save to file
                filename = save_to_file(packet_data)
                print(f"Packet data saved to {filename}")

    except pyshark.capture.capture.TSharkCrashException:
        print("Error: TShark crashed. Please check if Wireshark is properly installed.")
    except FileNotFoundError:
        print("Error: Could not find Wireshark/TShark executable. Please ensure Wireshark is installed.")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
