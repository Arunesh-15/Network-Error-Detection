# ⚡ CyberPulse: Real-Time Network Packet & Error Detection Sentinel

An enterprise-grade, real-time network traffic sniffer, protocol telemetry stream, and autonomous anomaly detection system built with **Python (Scapy)**, **Flask**, **Flask-SocketIO**, and **Chart.js**.

---

## 🎯 Key Features & Capabilities

1. **Live Packet Sniffing & Inspection**:
   - Deep packet inspection across Layer 2 (Ethernet/ARP), Layer 3 (IPv4/IPv6), Layer 4 (TCP/UDP/ICMP), and Application Layer (DNS/HTTP/TLS).
   - Real-time packet length extraction (bytes) mapped directly to a dynamic streaming area chart.

2. **Autonomous Network Error & Anomaly Detection**:
   - **TCP Reset (RST) Flag Detection (`0x04`)**: Identifies abruptly terminated connections, rejected connections, or connection resets caused by closed ports or firewall interventions.
   - **ICMP Destination Unreachable (Type 3)**: Flags unreachable networks, hosts, protocols, or ports.
   - **ICMP Time-To-Live Expired (Type 11)**: Detects routing loops or hops exceeding packet TTL.
   - **ICMP Echo Reply (Type 0)**: Captures active ICMP ping replies for interactive diagnostics and error testing.
   - **Oversized Frame / MTU Violations (> 1518 Bytes)**: Detects potential packet fragmentation issues or jumbo frame misconfigurations.
   - **Abnormal Flag Scans (NULL & SYN+FIN Scans)**: Flags stealth port scan signatures.

3. **High-Performance Architecture**:
   - **Decoupled Queue & Throttling**: Features a thread-safe packet queue with a rate-controlled dispatch worker (~25 FPS), ensuring the browser Canvas and WebSocket engine never stutter even on high-throughput gigabit interfaces.
   - **Immediate Initial Rendering**: Zero blank screens upon launching; immediate historical snapshot rendering via WebSocket `init_state`.

4. **Security Operations Center (SOC) Dashboard**:
   - **Real-Time KPIs**: Total Packets, Detected Errors, Error Rate (%), Live Throughput (Kbps), Average Packet Size (Bytes).
   - **Dynamic Visualizations**: Real-Time Packet Length Stream with highlighted error spikes, Protocol Distribution Donut Chart, and Error Classification Bar Chart.
   - **Live Security Log Table**: Detailed per-packet inspection with color-coded protocol badges, source/destination sockets, flags, and diagnostic status.
   - **Interview Simulation Toolbar**: One-click interactive error triggers (`Test TCP RST`, `Test ICMP Error`, `Traffic Burst`) to easily demonstrate detection mechanisms on demand.
   - **Data Export**: Full CSV / JSON export of captured packet logs.

---

## 🚀 How to Execute the Project

### Option A: Quick 1-Click Launch (Windows)
Double-click `start.bat` in the project root directory. It will automatically initialize the environment and start the web server.

### Option B: Command-Line Execution
1. Open PowerShell / Command Prompt in this folder:
   ```powershell
   cd D:\Network_Error_Detection2
   ```

2. Activate the existing virtual environment:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

3. Run the application:
   ```powershell
   python app.py
   ```

4. Open your browser and navigate to:
   ```
   http://127.0.0.1:5000/
   ```

> [!NOTE]
> For live physical packet capture, Scapy relies on the **Npcap** packet driver. If you encounter permission warnings on raw sockets, launch your terminal with **Run as Administrator**.

---

## 🧪 How to Demonstrate & Trigger Errors (For Interviews)

### Method 1: Using the Built-in Dashboard Toolbar (Recommended for Interviews)
On the top-right toolbar of the dashboard, click any of the test buttons:
- **`⚡ Test TCP RST`**: Injects a connection reset packet. You will see a red spike on the graph, the error counter increment, and an alert entry in the security table.
- **`⚡ Test ICMP Error`**: Injects an ICMP Destination Unreachable packet.
- **`⚡ Traffic Burst`**: Injects a high-speed burst of mixed packets with anomalies.

### Method 2: Real Network Triggers
- **Trigger ICMP Error**:
  ```powershell
  ping -t 8.8.8.8
  ```
  Every ping reply (ICMP Type 0) triggers the detection rule.
- **Trigger TCP Reset**:
  ```powershell
  Test-NetConnection -ComputerName 127.0.0.1 -Port 65432
  ```
  Hitting an unassigned port forces the operating system to respond with a TCP RST packet.

---

## 💡 Top Interview Talking Points & Design Decisions

| Question / Concept | What to Highlight in an Interview |
| :--- | :--- |
| **Why did you decouple Scapy capture from the WebSocket emission?** | High-speed networks can produce thousands of packets per second. Blasting raw WebSocket messages per packet creates message queue congestion and freezes the browser DOM/Canvas. By implementing a thread-safe buffer queue and rate-controlled worker (~25 FPS), we maintain real-time fidelity with buttery-smooth 60Hz UI rendering. |
| **How does your anomaly engine classify network errors?** | We inspect packet headers layer by layer: TCP bitmasks for the RST flag (`flags & 0x04`) indicating aborted handshakes, ICMP header types (`Type 3` for unreachable, `Type 11` for TTL expiration), and payload byte lengths against standard 1518B Ethernet MTU. |
| **Why did you implement a Dedicated Error Ring Buffer?** | In real-world networks, normal traffic flows at hundreds of packets per second. In a naive shared FIFO queue, critical security incidents and error anomalies would be evicted within seconds by incoming normal traffic. By decoupling errors into a dedicated `error_history` buffer, every detected anomaly is permanently preserved and immediately queryable in the 'Errors Only' audit tab. |
| **How does True Capture Pause work?** | Pausing is not merely a client-side visual freeze; it signals the backend ingestion worker via `/api/pause` to halt packet counting, rate calculations, and buffer mutations. This gives operators a frozen, deterministic forensic snapshot of telemetry without packet drift. |
| **How do you handle client state on initial connect?** | When a client opens the dashboard, the server emits an `init_state` payload containing current telemetry metrics and a sliding window of recent packets. This prevents the "cold-start blank chart" problem common in naive implementations. |
| **How would you scale this in production?** | For enterprise deployments, capture workers run as distributed agents (e.g., using DPDK, eBPF, or AF_PACKET), streaming telemetry into a message broker like Apache Kafka or Redis Streams, consumed by an analytics engine before being broadcast via WebSockets. |
