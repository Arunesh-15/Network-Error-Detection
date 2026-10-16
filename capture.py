import time
import datetime
import threading
import random
from collections import deque
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, conf
try:
    from scapy.arch.windows import get_windows_if_list
except ImportError:
    get_windows_if_list = None


class PacketMonitor:
    def __init__(self):
        self.lock = threading.Lock()
        self.packet_count = 0
        self.error_count = 0
        self.total_bytes = 0
        self.start_time = time.time()
        self.is_paused = False
        
        # General packet sliding window
        self.history = deque(maxlen=250)
        
        # Dedicated Error Ring Buffer: NEVER overwritten by high-volume normal traffic
        self.error_history = deque(maxlen=300)
        
        # Throughput rate calculation (timestamp, bytes)
        self.rate_window = deque(maxlen=200)
        
        # Protocol breakdown counters
        self.protocols = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "DNS": 0,
            "ARP": 0,
            "OTHER": 0
        }
        
        # Error categorization counters
        self.error_types = {
            "TCP_RST": 0,
            "ICMP_UNREACHABLE": 0,
            "ICMP_TTL_EXPIRED": 0,
            "ICMP_ECHO_REPLY": 0,
            "OVERSIZED_MTU": 0,
            "SUSPICIOUS_SCAN": 0
        }
        
        self.active_interface_name = "Wi-Fi"
        self.is_sniffing = False
        self.simulation_mode = False

        # Seed with initial baseline packets so dashboard renders immediately
        self._seed_baseline()

    def _seed_baseline(self):
        base_time = time.time() - 8
        for i in range(7):
            t_str = datetime.datetime.fromtimestamp(base_time + i).strftime("%H:%M:%S.000")
            pkt = {
                "id": i + 1,
                "timestamp": t_str,
                "src_ip": "192.168.1.105",
                "dst_ip": "142.250.190.46",
                "src_port": 54120 + i,
                "dst_port": 443,
                "protocol": "TCP",
                "length": random.choice([64, 128, 512, 1024, 1420]),
                "flags": "ACK",
                "is_error": 0,
                "error_type": None,
                "error_detail": "",
                "total_errors": 0,
                "total_packets": i + 1
            }
            self.packet_count += 1
            self.total_bytes += pkt["length"]
            self.protocols["TCP"] += 1
            self.history.append(pkt)
            self.rate_window.append((base_time + i, pkt["length"]))

        # Seed 1 initial error packet for immediate verification
        err_time = datetime.datetime.fromtimestamp(base_time + 7).strftime("%H:%M:%S.000")
        sample_err = {
            "id": 8,
            "timestamp": err_time,
            "src_ip": "192.168.1.254",
            "dst_ip": "192.168.1.105",
            "src_port": 65432,
            "dst_port": 54127,
            "protocol": "TCP",
            "length": 54,
            "flags": "RST,ACK",
            "is_error": 1,
            "error_type": "TCP_RST",
            "error_detail": "TCP Reset (RST) - Closed port / Connection rejected",
            "total_errors": 1,
            "total_packets": 8
        }
        self.packet_count += 1
        self.error_count += 1
        self.total_bytes += 54
        self.protocols["TCP"] += 1
        self.error_types["TCP_RST"] += 1
        self.history.append(sample_err)
        self.error_history.append(sample_err)
        self.rate_window.append((base_time + 7, 54))

    def set_pause(self, state):
        with self.lock:
            self.is_paused = bool(state)
        return self.is_paused

    def reset(self):
        with self.lock:
            self.packet_count = 0
            self.error_count = 0
            self.total_bytes = 0
            self.start_time = time.time()
            self.history.clear()
            self.error_history.clear()
            self.rate_window.clear()
            for k in self.protocols:
                self.protocols[k] = 0
            for k in self.error_types:
                self.error_types[k] = 0

    def get_stats(self):
        with self.lock:
            now = time.time()
            uptime = max(1, int(now - self.start_time))
            
            # Purge rate window older than 2.0 seconds
            while self.rate_window and now - self.rate_window[0][0] > 2.0:
                self.rate_window.popleft()
            
            window_bytes = sum(b for _, b in self.rate_window)
            window_pkts = len(self.rate_window)
            
            duration = 2.0 if self.rate_window else 1.0
            kbps = round((window_bytes * 8 / 1024) / duration, 2)
            pps = round(window_pkts / duration, 1)
            
            err_rate = round((self.error_count / self.packet_count * 100), 2) if self.packet_count > 0 else 0.0
            avg_len = round(self.total_bytes / self.packet_count, 1) if self.packet_count > 0 else 0
            
            return {
                "total_packets": self.packet_count,
                "total_errors": self.error_count,
                "error_rate": err_rate,
                "total_bytes": self.total_bytes,
                "bandwidth_kbps": kbps if not self.is_paused else 0.0,
                "packets_per_sec": pps if not self.is_paused else 0.0,
                "avg_packet_length": avg_len,
                "uptime_seconds": uptime,
                "protocols": dict(self.protocols),
                "error_types": dict(self.error_types),
                "active_interface": self.active_interface_name,
                "simulation_mode": self.simulation_mode,
                "is_paused": self.is_paused,
                "stored_errors_count": len(self.error_history)
            }

    def analyze_scapy_packet(self, pkt):
        # If capture is paused, ignore packet completely
        if self.is_paused:
            return None

        length = len(pkt)
        timestamp_str = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        now = time.time()
        
        src_ip = "Unknown"
        dst_ip = "Unknown"
        src_port = None
        dst_port = None
        proto = "OTHER"
        flags_str = ""
        is_error = 0
        error_type = None
        error_detail = ""

        # Layer 3 IP resolution
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
        elif pkt.haslayer(ARP):
            src_ip = getattr(pkt[ARP], 'psrc', 'Unknown')
            dst_ip = getattr(pkt[ARP], 'pdst', 'Unknown')
            proto = "ARP"

        # Layer 4 / Application Layer resolution
        if pkt.haslayer(DNS):
            proto = "DNS"
        elif pkt.haslayer(TCP):
            proto = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags_int = int(pkt[TCP].flags)
            flags_list = []
            if flags_int & 0x01: flags_list.append("FIN")
            if flags_int & 0x02: flags_list.append("SYN")
            if flags_int & 0x04: flags_list.append("RST")
            if flags_int & 0x08: flags_list.append("PSH")
            if flags_int & 0x10: flags_list.append("ACK")
            if flags_int & 0x20: flags_list.append("URG")
            flags_str = ",".join(flags_list) if flags_list else "NONE"

            # Check 1: TCP Reset (RST) flag -> Connection forcefully aborted or port closed
            if flags_int & 0x04:
                is_error = 1
                error_type = "TCP_RST"
                error_detail = "TCP Reset (RST) - Connection forcefully aborted or port closed"

            # Check 2: Suspicious flags scan (NULL or SYN+FIN)
            elif flags_int == 0 or (flags_int & 0x03 == 0x03):
                is_error = 1
                error_type = "SUSPICIOUS_SCAN"
                error_detail = "Abnormal TCP Flag Combination (Possible Port Scan)"

        elif pkt.haslayer(UDP):
            if proto != "DNS":
                proto = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            if src_port == 53 or dst_port == 53:
                proto = "DNS"

        elif pkt.haslayer(ICMP):
            proto = "ICMP"
            icmp_type = pkt[ICMP].type
            # Check 3: Destination Unreachable
            if icmp_type == 3:
                is_error = 1
                error_type = "ICMP_UNREACHABLE"
                error_detail = f"ICMP Destination Unreachable (Code {pkt[ICMP].code})"
            # Check 4: TTL Expired
            elif icmp_type == 11:
                is_error = 1
                error_type = "ICMP_TTL_EXPIRED"
                error_detail = "ICMP Time-To-Live (TTL) Expired in transit"
            # Check 5: ICMP Echo Reply (Demonstration / Ping Reply trigger)
            elif icmp_type == 0:
                is_error = 1
                error_type = "ICMP_ECHO_REPLY"
                error_detail = "ICMP Echo Reply - Active Ping Response Detected"

        # Check 6: Oversized Packet (Exceeding standard Ethernet MTU 1518 bytes)
        if length > 1518 and not is_error:
            is_error = 1
            error_type = "OVERSIZED_MTU"
            error_detail = f"Oversized Frame: {length} bytes exceeds standard 1518B MTU"

        # Update monitor state
        with self.lock:
            self.packet_count += 1
            self.total_bytes += length
            if proto in self.protocols:
                self.protocols[proto] += 1
            else:
                self.protocols["OTHER"] += 1

            if is_error:
                self.error_count += 1
                if error_type in self.error_types:
                    self.error_types[error_type] += 1

            self.rate_window.append((now, length))

            packet_info = {
                "id": self.packet_count,
                "timestamp": timestamp_str,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "length": length,
                "flags": flags_str,
                "is_error": is_error,
                "error_type": error_type,
                "error_detail": error_detail,
                "total_errors": self.error_count,
                "total_packets": self.packet_count
            }
            self.history.append(packet_info)
            if is_error:
                # Dedicated error storage: NEVER evicted by normal traffic flood!
                self.error_history.append(packet_info)

        return packet_info

    def generate_simulated_packet(self, force_error_type=None):
        """Generates realistic synthetic packet data for demo/interview simulations."""
        timestamp_str = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        now = time.time()
        
        common_destinations = [
            ("142.250.190.46", 443, "HTTPS (Google)"),
            ("104.16.132.229", 443, "HTTPS (Cloudflare)"),
            ("8.8.8.8", 53, "DNS (Google Primary)"),
            ("1.1.1.1", 53, "DNS (Cloudflare)"),
            ("192.168.1.1", 80, "HTTP (Router Gateway)"),
            ("192.168.1.254", 65432, "Closed Port Test")
        ]
        
        target = random.choice(common_destinations)
        local_ip = "192.168.1.105"
        
        is_error = 0
        error_type = None
        error_detail = ""
        proto = "TCP"
        src_port = random.randint(49152, 65535)
        dst_port = target[1]
        length = random.randint(64, 1480)
        flags_str = "ACK"

        if force_error_type == "TCP_RST" or (force_error_type is None and random.random() < 0.05):
            is_error = 1
            error_type = "TCP_RST"
            error_detail = "TCP Reset (RST) - Connection forcefully aborted / rejected"
            proto = "TCP"
            flags_str = "RST,ACK"
            length = 54
            dst_port = 65432

        elif force_error_type == "ICMP_UNREACHABLE":
            is_error = 1
            error_type = "ICMP_UNREACHABLE"
            error_detail = "ICMP Destination Host Unreachable (Type 3, Code 1)"
            proto = "ICMP"
            flags_str = ""
            length = 70
            src_port = None
            dst_port = None

        elif force_error_type == "ICMP_TTL_EXPIRED":
            is_error = 1
            error_type = "ICMP_TTL_EXPIRED"
            error_detail = "ICMP Time-To-Live (TTL) Expired in transit (Type 11)"
            proto = "ICMP"
            flags_str = ""
            length = 68
            src_port = None
            dst_port = None

        elif force_error_type == "ICMP_ECHO_REPLY":
            is_error = 1
            error_type = "ICMP_ECHO_REPLY"
            error_detail = "ICMP Echo Reply - Active Ping Response Detected"
            proto = "ICMP"
            flags_str = ""
            length = 74
            src_port = None
            dst_port = None

        elif force_error_type == "OVERSIZED_MTU":
            is_error = 1
            error_type = "OVERSIZED_MTU"
            error_detail = "Oversized Frame: 2450 bytes exceeds standard 1518B MTU"
            proto = "TCP"
            flags_str = "PSH,ACK"
            length = 2450

        elif force_error_type == "SUSPICIOUS_SCAN":
            is_error = 1
            error_type = "SUSPICIOUS_SCAN"
            error_detail = "Abnormal TCP Flag Combination (SYN+FIN Scan signature)"
            proto = "TCP"
            flags_str = "SYN,FIN"
            length = 60

        else:
            # Normal traffic simulation
            r = random.random()
            if r < 0.65:
                proto = "TCP"
                flags_str = random.choice(["ACK", "PSH,ACK", "SYN,ACK"])
                length = random.choice([66, 128, 512, 1024, 1420, 1514])
            elif r < 0.85:
                proto = "UDP"
                flags_str = ""
                length = random.randint(70, 480)
            elif r < 0.95:
                proto = "DNS"
                flags_str = ""
                dst_port = 53
                length = random.randint(74, 180)
            else:
                proto = "ARP"
                flags_str = ""
                length = 42
                src_port = None
                dst_port = None

        with self.lock:
            self.packet_count += 1
            self.total_bytes += length
            if proto in self.protocols:
                self.protocols[proto] += 1
            else:
                self.protocols["OTHER"] += 1

            if is_error:
                self.error_count += 1
                if error_type in self.error_types:
                    self.error_types[error_type] += 1

            self.rate_window.append((now, length))

            packet_info = {
                "id": self.packet_count,
                "timestamp": timestamp_str,
                "src_ip": local_ip if is_error != 1 or error_type == "OVERSIZED_MTU" else target[0],
                "dst_ip": target[0] if is_error != 1 or error_type == "OVERSIZED_MTU" else local_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "length": length,
                "flags": flags_str,
                "is_error": is_error,
                "error_type": error_type,
                "error_detail": error_detail,
                "total_errors": self.error_count,
                "total_packets": self.packet_count
            }
            self.history.append(packet_info)
            if is_error:
                self.error_history.append(packet_info)

        return packet_info


# Global Singleton Monitor Instance
monitor = PacketMonitor()


def get_available_interfaces():
    """Returns detected network adapters with names, GUIDs, and IP addresses."""
    interfaces = []
    if get_windows_if_list:
        try:
            for iface in get_windows_if_list():
                ips = iface.get('ips', [])
                valid_ips = [ip for ip in ips if not ip.startswith('169.254.')]
                interfaces.append({
                    "name": iface.get("name", "Unknown"),
                    "description": iface.get("description", ""),
                    "guid": iface.get("guid", ""),
                    "ips": valid_ips,
                    "is_active": len(valid_ips) > 0
                })
        except Exception:
            pass
    return interfaces


def find_best_interface():
    """
    Identifies the primary active internet adapter (Wi-Fi or real physical Ethernet).
    Explicitly filters out VirtualBox, VMware, and disconnected adapters.
    """
    if get_windows_if_list:
        try:
            adapters = get_windows_if_list()
            # 1. First priority: Wi-Fi / Wireless with active IP
            for iface in adapters:
                ips = [ip for ip in iface.get('ips', []) if not ip.startswith('169.254.') and not ip.startswith('127.') and not ip.startswith('192.168.56.')]
                name = iface.get('name', '').lower()
                if ips and ('wi-fi' in name or 'wireless' in name or 'wlan' in name):
                    return iface.get('name'), iface.get('guid')

            # 2. Second priority: Physical Ethernet (excluding VirtualBox, TAP, VPN)
            for iface in adapters:
                ips = [ip for ip in iface.get('ips', []) if not ip.startswith('169.254.') and not ip.startswith('127.') and not ip.startswith('192.168.56.')]
                name = iface.get('name', '').lower()
                desc = iface.get('description', '').lower()
                if ips and 'virtual' not in name and 'virtual' not in desc and 'tap' not in name and 'vpn' not in name:
                    return iface.get('name'), iface.get('guid')

            # 3. Third priority: Any adapter with an assigned IP
            for iface in adapters:
                ips = [ip for ip in iface.get('ips', []) if not ip.startswith('169.254.') and not ip.startswith('127.')]
                if ips:
                    return iface.get('name'), iface.get('guid')
        except Exception as e:
            print(f"[PacketMonitor] Adapter discovery error: {e}")
            
    return "Default", None


def start_capture(callback, target_iface=None):
    """
    Main sniffing loop with thread-safe queue and smooth emission.
    Automatically prioritizes the active Wi-Fi adapter.
    """
    monitor.is_sniffing = True
    best_name, best_guid = find_best_interface()
    monitor.active_interface_name = best_name

    packet_queue = deque(maxlen=500)
    queue_lock = threading.Lock()

    # Worker thread to emit queued packets to the callback at a controlled rate
    def dispatch_worker():
        while monitor.is_sniffing:
            if monitor.is_paused:
                time.sleep(0.1)
                continue

            batch = []
            with queue_lock:
                while packet_queue and len(batch) < 15:
                    batch.append(packet_queue.popleft())
            
            if batch:
                for pkt_info in batch:
                    try:
                        callback(pkt_info)
                    except Exception:
                        pass
                time.sleep(0.04)  # ~25 FPS delivery rate
            else:
                time.sleep(0.08)

    dispatch_thread = threading.Thread(target=dispatch_worker, daemon=True)
    dispatch_thread.start()

    def on_packet_arrived(pkt):
        if monitor.is_paused:
            return
        try:
            info = monitor.analyze_scapy_packet(pkt)
            if info:
                with queue_lock:
                    packet_queue.append(info)
        except Exception:
            pass

    npf_device = f"\\Device\\NPF_{best_guid}" if best_guid else None
    print(f"[CyberPulse] Live capture starting on: {best_name} ({npf_device or 'default'})")

    try:
        # Sniff on selected or best detected interface
        if target_iface:
            sniff(iface=target_iface, prn=on_packet_arrived, store=False)
        elif npf_device:
            sniff(iface=npf_device, prn=on_packet_arrived, store=False)
        else:
            sniff(prn=on_packet_arrived, store=False)
    except Exception as e:
        print(f"[CyberPulse] Live capture warning: {e}. Switching to auto-simulation mode.")
        monitor.simulation_mode = True
        while monitor.is_sniffing:
            if monitor.is_paused:
                time.sleep(0.2)
                continue
            time.sleep(random.uniform(0.15, 0.45))
            sim_pkt = monitor.generate_simulated_packet()
            with queue_lock:
                packet_queue.append(sim_pkt)