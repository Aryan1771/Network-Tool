# Network Incident Investigation and Automated Forensic System

---

## 1. Project Overview

The **Network Incident Investigation and Automated Forensic System** is a professional-grade, local digital forensic and network incident response platform. It is engineered to capture network packets, analyze protocol headers, automatically detect behavioral security intrusions using rule-based algorithmic thresholds, reconstruct incident timelines, preserve digital evidence using SHA-256 cryptographic hashing, maintain an append-only chain of custody (ISO/IEC 27037 compliant), execute NS-2 network simulation trace processing via AWK, and compile downloadable PDF forensic investigation reports.

The application runs entirely locally on a single machine without relying on external cloud APIs, external AI services, or paid third-party infrastructure.

---

## 2. System Components

The architecture is organized into four technical subsystems:

| Subsystem | Focus | Core Technical Modules |
| :--- | :--- | :--- |
| **Traffic Capture** | **Traffic Capture & Socket Programming** | `backend/capture/live_capture.py`<br/>`backend/capture/socket_traffic.py`<br/>`backend/capture/pcap_handler.py`<br/>Multithreaded sniffing, raw socket generators (normal TCP/UDP, SYN floods, port scans, brute-force bursts). |
| **Packet Analysis** | **Packet Analysis & Incident Detection** | `backend/analyzer/packet_parser.py`<br/>`backend/detector/rules.py`<br/>`backend/detector/detection_engine.py`<br/>`backend/detector/correlator.py`<br/>Metadata-only header dissection, 4 algorithmic detection rules, correlation windows, and deduplication logic. |
| **Digital Forensics** | **Digital Forensics & Evidence Integrity** | `backend/forensics/hasher.py`<br/>`backend/forensics/evidence_vault.py`<br/>`backend/forensics/chain_of_custody.py`<br/>`backend/forensics/report_generator.py`<br/>SHA-256 checksums, read-only evidence vaults, tamper detection, append-only custody logs, and ReportLab PDF compilation. |
| **Dashboard & Simulation** | **SOC Dashboard & Network Simulation** | `backend/simulation/ns2_parser.py`<br/>`simulation/tcl/*` & `simulation/awk/*`<br/>`frontend/templates/*` & `frontend/static/*`<br/>Flask backend routing, Chart.js visualizations, NS-2 trace processing, topology mapping, and evaluation benchmark framework. |

---

## 3. System Architecture & Data Flow

```
                      +------------------------------------------+
                      |         TRAFFIC INGESTION LAYER          |
                      |  1. Live Scapy Sniffer (Npcap / Linux)   |
                      |  2. Historical PCAP / PCAPNG Upload     |
                      |  3. Python Socket Traffic Generator      |
                      +--------------------+---------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |      PACKET ANALYZER & DISSECTOR         |
                      |  • Strips L2/L3/L4 Metadata Headers      |
                      |  • Privacy Enforced: Payloads Discarded  |
                      |  • Flow & Connection Metrics Computed    |
                      +--------------------+---------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |      AUTOMATED DETECTION ENGINE          |
                      |  • Rule A: Port Scan (>20 ports / 10s)   |
                      |  • Rule B: SYN Flood (>100 pps, <10% ack)|
                      |  • Rule C: Brute-Force (>10 conn / 60s)  |
                      |  • Rule D: Data Exfiltration (>5x base)  |
                      +--------------------+---------------------+
                                           |
                 +-------------------------+-------------------------+
                 |                                                   |
                 v                                                   v
+----------------------------------+               +----------------------------------+
|      DIGITAL EVIDENCE VAULT      |               |     FORENSIC TIMELINE & SOC      |
|  • Read-Only File Protection     |               |  • Sequential Event Correlation  |
|  • Streaming SHA-256 Hashing     |               |  • Incident Lifecycle Tracker    |
|  • Automated Tamper Detection    |               |  • Analyst Investigation Notes   |
|  • Append-Only Chain of Custody  |               |  • Downloadable PDF Dossiers     |
+----------------------------------+               +----------------------------------+
                 |                                                   |
                 +-------------------------+-------------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |       NS-2 TRACE & AWK PROCESSOR         |
                      |  • Bottleneck Topology (4 Nodes, DropTail)|
                      |  • AWK Calculations: Throughput, Delay,  |
                      |    Packet Delivery Ratio (PDR), Drops    |
                      +------------------------------------------+
```

---

## 4. Key Features & Detection Algorithms

### A. Port Scan Detection (`RULE-01-PORT-SCAN`)
- **Condition:** A single source IP probes **more than 20 distinct destination ports within 10 seconds** (configurable in Settings).
- **Forensic Attributes:** Probing host IP, unique target port count, port range, detection window, and severity **MEDIUM**.

### B. TCP SYN Flood Detection (`RULE-02-SYN-FLOOD`)
- **Condition:** Volumetric incoming SYN traffic exceeds **100 packets per second**, and the connection handshake completion ratio ($\frac{\text{ACK}}{\text{SYN}}$) is **below 10%**.
- **Forensic Attributes:** Source IP, victim host, observed SYN/sec rate, handshake completion ratio, and severity **HIGH**.
- *Technical Note:* Incomplete single-direction PCAP traces without reverse path captures naturally report 0% handshakes; bidirectional capture is required for complete handshake observation.

### C. Brute-Force Login Detection (`RULE-03-BRUTE-FORCE`)
- **Condition:** **More than 10 repeated connection attempts** targeting authentication service ports (e.g., 22 SSH, 21 FTP, 23 Telnet, 80/443 HTTP, 3389 RDP) within **60 seconds**.
- **Forensic Attributes:** Monitored service name, port, target IP, attempt velocity, and severity **MEDIUM**.
- *Clarification:* Operates at the transport layer by tracking connection initiation handshakes; verified password failure logs require application-level authentication audits.

### D. Data Exfiltration Detection (`RULE-04-DATA-EXFILTRATION`)
- **Condition:** Outbound data volume from an internal host to an external destination exceeds **5 times the baseline normal volume** within the monitoring window.
- **Forensic Attributes:** Origin host, remote sink IP, total bytes transferred, baseline deviation ratio, and severity **HIGH**.

### E. Digital Evidence Vault & Tamper Detection
- Every capture session (.pcap, upload, or simulation) is stored in `data/evidence/` with file attributes set to **read-only**.
- Cryptographic **SHA-256** checksums are computed and stored in SQLite.
- **Verify Integrity Button:** Recalculates the SHA-256 hash across 64 KB streaming blocks. If the file is altered, the system immediately flags **TAMPER DETECTED**.
- **Tamper Demonstration Tool:** Allows flipping 1 single byte in a test file to demonstrate to examiners that cryptographic verification immediately detects modifications.

### F. Chain of Custody Audit Trail (ISO/IEC 27037)
- Maintains an append-only audit trail logging all evidence lifecycle actions: `EVIDENCE_COLLECTED`, `HASH_CALCULATED`, `EVIDENCE_PRESERVED`, `INTEGRITY_VERIFIED`, `EVIDENCE_ACCESSED`, `REPORT_GENERATED`, and `TAMPER_DETECTED`.

### G. Downloadable PDF Forensic Reports
- Uses ReportLab Platypus to compile official, courtroom-ready forensic reports complete with project headers, executive summaries, technical parameters, evidence SHA-256 hashes, correlated timelines, chain-of-custody tables, and analyst signature blocks.

### H. NS-2 Simulation & AWK Trace Processing
- Includes complete TCL scripts (`normal_traffic.tcl`, `flooding_attack.tcl`, `packet_loss_scenario.tcl`) representing a 4-node bottleneck topology ($n_0 \to n_1 \to n_2 \to n_3$).
- Includes AWK analysis scripts (`throughput.awk`, `delay.awk`, `pdr.awk`, `loss.awk`) calculating:
  - **Throughput (Kbps)**
  - **Average End-to-End Delay (ms)**
  - **Packet Delivery Ratio (PDR %)**
  - **Packet Loss Ratio (%)**
- Features a built-in Python parser that produces identical metrics on Windows without requiring a native Unix environment, while providing full scripts for Ubuntu execution.

---

## 5. Technology Stack

- **Backend:** Python 3 (3.10+ / 3.14 compatible), Flask 3.1, Scapy 2.8, SQLite3 (WAL mode), hashlib, psutil, ReportLab 5.1.
- **Networking:** Socket programming (`socket.AF_INET`, `SOCK_STREAM`, `SOCK_DGRAM`), Scapy sniffing, Wireshark/TShark compatibility, NS-2 network simulator, AWK scripting.
- **Frontend:** HTML5, CSS3 (Enterprise Dark SOC theme), Vanilla JavaScript, Chart.js, Lucide Icons.

---

## 6. Project Structure

```
network-tool-project\
├── backend/
│   ├── analyzer/
│   │   ├── packet_parser.py       # Header metadata extraction (privacy-enforced)
│   │   └── statistics.py          # Network traffic aggregation metrics
│   ├── capture/
│   │   ├── live_capture.py        # Background multithreaded Scapy sniffer
│   │   ├── pcap_handler.py        # PCAP/PCAPNG ingestion & evidence preservation
│   │   └── socket_traffic.py      # TCP/UDP traffic generator (127.0.0.1 safe)
│   ├── database/
│   │   ├── db.py                  # Thread-local SQLite connection manager
│   │   └── schema.sql             # Relational schema (11 tables)
│   ├── detector/
│   │   ├── correlator.py          # Timeline event builder & deduplicator
│   │   ├── detection_engine.py    # Master detection orchestration engine
│   │   └── rules.py               # 4 algorithmic detection rules
│   ├── evaluation/
│   │   └── evaluator.py           # Benchmark suite & demo data seeder
│   ├── forensics/
│   │   ├── chain_of_custody.py    # ISO/IEC 27037 append-only audit logger
│   │   ├── evidence_vault.py      # Cryptographic vault & tamper detector
│   │   ├── hasher.py              # SHA-256 streaming hashing module
│   │   └── report_generator.py    # Courtroom-ready ReportLab PDF compiler
│   ├── simulation/
│   │   └── ns2_parser.py          # NS-2 12-column trace file processor
│   └── config.py                  # Threshold defaults & file paths
├── frontend/
│   ├── static/
│   │   ├── css/styles.css         # Dark SOC UI stylesheet
│   │   └── js/
│   │       ├── api.js             # REST API client & toast alerts
│   │       ├── charts.js          # Chart.js visualization engine
│   │       └── main.js            # Master UI interactivity & poller
│   └── templates/                 # Jinja2 HTML templates
│       ├── base.html              # Persistent sidebar & top nav layout
│       ├── overview.html          # Main SOC monitoring dashboard
│       ├── live_traffic.html      # Sniffer, PCAP uploader, socket generator
│       ├── packet_analyzer.html   # Searchable packet table & header inspector
│       ├── incident_detection.html# Incident cards & lifecycle tracker
│       ├── timeline.html          # Correlated incident milestone timeline
│       ├── evidence_vault.html    # Cryptographic SHA-256 evidence vault
│       ├── chain_of_custody.html  # Append-only audit log
│       ├── ns2_simulation.html    # Topology diagram, TCL/AWK metrics
│       ├── reports.html           # Downloadable PDF report archive
│       ├── evaluation.html        # Ground-truth test runner
│       └── settings.html          # Detection thresholds & demo reset
├── simulation/
│   ├── awk/                       # AWK trace calculation scripts
│   │   ├── delay.awk
│   │   ├── loss.awk
│   │   ├── pdr.awk
│   │   └── throughput.awk
│   ├── sample_traces/             # Sample standard NS-2 trace files
│   └── tcl/                       # TCL simulation topology scripts
│       ├── flooding_attack.tcl
│       ├── normal_traffic.tcl
│       └── packet_loss_scenario.tcl
├── tests/                         # Unit tests
│   ├── test_detection.py
│   ├── test_forensics.py
│   └── test_ns2_parser.py
├── app.py                         # Flask web application & REST API
├── run.py                         # Application launcher entry point
├── requirements.txt               # Python package dependencies
├── .env.example                   # Environment variable template
├── .gitignore
└── README.md
```

---

## 7. Installation & Setup Instructions

### Prerequisites
- Python 3.10, 3.11, 3.12, 3.13, or 3.14.
- Windows or Ubuntu Linux.
- Windows users: Install [Npcap](https://npcap.com/) (select *"Install Npcap in WinPcap API-compatible Mode"* during installation) for live interface packet sniffing.

### Windows Setup
1. Clone or extract the project directory:
   ```cmd
   cd network-tool-project
   ```
2. Install Python dependencies:
   ```cmd
   py -m pip install -r requirements.txt
   ```
3. Run the application:
   ```cmd
   py run.py
   ```
4. Open your browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

### Ubuntu Linux Setup
1. Install system prerequisites, NS-2, NAM, and AWK:
   ```bash
   sudo apt update
   sudo apt install -y python3 python3-pip ns2 nam gawk libpcap-dev
   ```
2. Install Python dependencies:
   ```bash
   pip3 install -r requirements.txt
   ```
3. Run the application:
   ```bash
   python3 run.py
   ```
4. Access the web dashboard at `http://127.0.0.1:5000`.

---

## 8. Verification & Demonstration Guide

Use these steps to explore the system and its technical workflows:

### Step 1: Automated Ground-Truth Evaluation
1. In the sidebar, click **Evaluation & Tests**.
2. Click **Execute Benchmark Suite**.
3. The system executes all 7 controlled test scenarios:
   - Normal Baseline Traffic (0 false positives)
   - Port Scan Detection (100% detection)
   - SYN Flood Detection (100% detection)
   - Brute-Force Login Detection (100% detection)
   - Data Exfiltration Detection (100% detection)
   - SHA-256 Tamper Detection (100% detection)
   - Automated PDF Report Compilation (100% compiled)
4. Verify that **100% Detection Accuracy** and **0.0% False Positive Rate** are displayed.
5. Click **Export Results JSON** to save the empirical test report.

### Step 2: Live Socket Traffic Generation
1. In the sidebar, click **Live Traffic**.
2. Under **Source C: Socket Generator**, click **Simulate Port Scan**.
3. The background thread will initiate 25 rapid TCP connection attempts across local ports 8000–8024.
4. Navigate to **Incident Detection** to observe the newly created `RULE-01-PORT-SCAN` incident ticket.

### Step 3: Digital Evidence Vault & Tamper Detection
1. In the sidebar, click **Evidence Vault**.
2. Locate an evidence artifact (e.g., `EVD-2026-0001`).
3. Click **Verify** — the system streams the file bytes, recalculates SHA-256, and confirms `VERIFIED (INTACT)`.
4. Click **Test Tamper** — this intentionally alters 1 byte in the evidence file.
5. Notice the immediate update to **TAMPER DETECTED** in prominent red.
6. Open **Chain of Custody** to verify that a permanent `TAMPER_DETECTED` audit entry was recorded.

### Step 4: Download Courtroom-Ready Forensic PDF Report
1. In the sidebar, click **Forensic Reports**.
2. Locate any incident and click **PDF Download**.
3. Open the downloaded PDF in your viewer.
4. Review the report: neutral headers, executive summary, detection thresholds, evidence SHA-256 digest, correlated timeline, and forensic signature attestation block.

### Step 5: NS-2 Simulation Trace Analysis
1. In the sidebar, click **NS-2 Simulation**.
2. Review the 4-node bottleneck topology diagram ($n_0 \to n_1 \to n_2 \to n_3$).
3. Under **Pre-Configured Scenarios**, click **Scenario 2: Flooding Attack**.
4. Observe the calculated metrics: Throughput (Kbps), Average End-to-End Delay (ms), Packet Delivery Ratio (PDR %), and Packet Loss Ratio (%).
5. Review the time-series throughput graph illustrating traffic degradation under buffer saturation.

---

## 9. Running Unit Tests

To run the complete automated test suite from the terminal:
```bash
py -m unittest discover tests
```
*Expected Output:*
```text
.......
----------------------------------------------------------------------
Ran 7 tests in 0.107s

OK
```

---

## 10. Technical Limitations & Notes

1. **Scope:** This platform supports network incident analysis and digital evidence handling based on ISO/IEC 27037 principles. It is not a legally certified forensic platform.
2. **Handshake Estimation in One-Way PCAPs:** Estimating TCP three-way handshake completion ($\frac{\text{ACK}}{\text{SYN}}$) assumes bidirectional capture. If an ingested PCAP contains only ingress packets, zero handshakes will be visible.
3. **Payload Privacy:** In accordance with modern digital forensic privacy standards, application payload bytes are stripped at capture time; all detections operate strictly on network and transport layer headers.
4. **Localhost Restriction:** All attack simulations are hardcoded to `127.0.0.1` and will never target external or public network entities.

---
