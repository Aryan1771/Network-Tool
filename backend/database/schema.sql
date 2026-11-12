-- Network Incident Investigation and Automated Forensic System Database Schema
-- JIIT Computer Networks Lab (24B15CS313)

CREATE TABLE IF NOT EXISTS capture_sessions (
    id TEXT PRIMARY KEY,
    session_name TEXT NOT NULL,
    source_type TEXT NOT NULL, -- 'live', 'pcap', 'simulation'
    interface TEXT,
    pcap_filename TEXT,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP,
    packet_count INTEGER DEFAULT 0,
    byte_count INTEGER DEFAULT 0,
    status TEXT DEFAULT 'running', -- 'running', 'stopped', 'completed', 'failed'
    is_demo INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    datetime_str TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT NOT NULL,
    packet_size INTEGER NOT NULL,
    tcp_flags TEXT,
    src_mac TEXT,
    dst_mac TEXT,
    info TEXT,
    is_suspicious INTEGER DEFAULT 0,
    is_demo INTEGER DEFAULT 0,
    FOREIGN KEY(session_id) REFERENCES capture_sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_packets_session ON packets(session_id);
CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);
CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip);
CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip);
CREATE INDEX IF NOT EXISTS idx_packets_proto ON packets(protocol);
CREATE INDEX IF NOT EXISTS idx_packets_suspicious ON packets(is_suspicious);

CREATE TABLE IF NOT EXISTS network_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    flow_key TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT NOT NULL,
    start_time REAL NOT NULL,
    end_time REAL NOT NULL,
    packet_count INTEGER DEFAULT 0,
    byte_count INTEGER DEFAULT 0,
    syn_count INTEGER DEFAULT 0,
    ack_count INTEGER DEFAULT 0,
    fin_count INTEGER DEFAULT 0,
    rst_count INTEGER DEFAULT 0,
    is_completed_handshake INTEGER DEFAULT 0,
    FOREIGN KEY(session_id) REFERENCES capture_sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_flows_session ON network_flows(session_id);
CREATE INDEX IF NOT EXISTS idx_flows_key ON network_flows(flow_key);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    session_id TEXT,
    incident_type TEXT NOT NULL, -- 'PORT_SCAN', 'SYN_FLOOD', 'BRUTE_FORCE', 'DATA_EXFILTRATION'
    severity TEXT NOT NULL, -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    target_ports TEXT,
    protocol TEXT NOT NULL,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    rule_name TEXT NOT NULL,
    threshold_details TEXT,
    status TEXT DEFAULT 'New', -- 'New', 'Investigating', 'Resolved'
    analyst_assignee TEXT DEFAULT 'Forensic Analyst (Team JIIT)',
    is_demo INTEGER DEFAULT 0,
    FOREIGN KEY(session_id) REFERENCES capture_sessions(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_incidents_type ON incidents(incident_type);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_src ON incidents(src_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

CREATE TABLE IF NOT EXISTS incident_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    datetime_str TEXT NOT NULL,
    event_type TEXT NOT NULL, -- 'INITIATION', 'SUSPICIOUS_PACKET', 'THRESHOLD_EXCEEDED', 'ALERT_GENERATED', 'EVIDENCE_PRESERVED', 'INVESTIGATION_ACTION', 'STATUS_CHANGE', 'NOTE_ADDED'
    summary TEXT NOT NULL,
    details TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    port INTEGER,
    severity TEXT,
    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_events_incident ON incident_events(incident_id);
CREATE INDEX IF NOT EXISTS idx_events_time ON incident_events(timestamp);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    incident_id TEXT,
    session_id TEXT,
    original_filename TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    sha256_hash TEXT NOT NULL,
    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    collected_by TEXT DEFAULT 'Automated Forensic Engine',
    source_type TEXT NOT NULL, -- 'Live Sniff', 'PCAP Upload', 'Simulation'
    verification_status TEXT DEFAULT 'VERIFIED', -- 'VERIFIED', 'TAMPERED', 'UNVERIFIED'
    last_verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_readonly INTEGER DEFAULT 1,
    notes TEXT,
    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE SET NULL,
    FOREIGN KEY(session_id) REFERENCES capture_sessions(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_incident ON evidence(incident_id);
CREATE INDEX IF NOT EXISTS idx_evidence_hash ON evidence(sha256_hash);

CREATE TABLE IF NOT EXISTS chain_of_custody (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id TEXT UNIQUE NOT NULL,
    evidence_id TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    action TEXT NOT NULL, -- 'EVIDENCE_COLLECTED', 'HASH_CALCULATED', 'EVIDENCE_PRESERVED', 'INTEGRITY_VERIFIED', 'EVIDENCE_ANALYZED', 'EVIDENCE_ACCESSED', 'REPORT_GENERATED', 'STATUS_UPDATED', 'TAMPER_DETECTED'
    actor TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    verification_result TEXT,
    description TEXT NOT NULL,
    notes TEXT,
    FOREIGN KEY(evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_coc_evidence ON chain_of_custody(evidence_id);
CREATE INDEX IF NOT EXISTS idx_coc_timestamp ON chain_of_custody(timestamp);

CREATE TABLE IF NOT EXISTS investigation_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    author TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    note_text TEXT NOT NULL,
    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS simulation_results (
    id TEXT PRIMARY KEY,
    scenario_name TEXT NOT NULL,
    trace_filename TEXT NOT NULL,
    trace_file_path TEXT NOT NULL,
    total_packets INTEGER DEFAULT 0,
    throughput_kbps REAL DEFAULT 0.0,
    avg_delay_ms REAL DEFAULT 0.0,
    pdr_percent REAL DEFAULT 0.0,
    packet_loss_ratio REAL DEFAULT 0.0,
    execution_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS forensic_reports (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    evidence_id TEXT,
    report_title TEXT NOT NULL,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    generated_by TEXT DEFAULT 'Team JIIT Forensic System',
    file_path TEXT NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    sha256_hash TEXT NOT NULL,
    summary TEXT,
    status TEXT DEFAULT 'Completed',
    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    FOREIGN KEY(evidence_id) REFERENCES evidence(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS detection_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value TEXT NOT NULL,
    data_type TEXT NOT NULL, -- 'int', 'float', 'string', 'json'
    description TEXT NOT NULL
);
