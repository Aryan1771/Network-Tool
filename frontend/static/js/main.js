/**
 * Forensic System Master Frontend Controller
 * JIIT Computer Networks Lab (24B15CS313)
 */

document.addEventListener("DOMContentLoaded", () => {
  initClock();
  initCaptureStatusPoller();
  initLucideIcons();
  setupGlobalModals();
});

// Real-Time System Clock (UTC and IST)
function initClock() {
  const clockEl = document.getElementById("system-clock");
  if (!clockEl) return;

  function update() {
    const now = new Date();
    const utc = now.toISOString().replace("T", " ").substring(0, 19) + " UTC";
    clockEl.innerText = utc;
  }
  update();
  setInterval(update, 1000);
}

// Render Lucide SVG Icons safely
function initLucideIcons() {
  if (window.lucide && typeof lucide.createIcons === "function") {
    lucide.createIcons();
  }
}

// Background Capture Status Monitor
let capturePollingInterval = null;
function initCaptureStatusPoller() {
  const indicator = document.getElementById("capture-indicator");
  const badgeText = document.getElementById("capture-status-text");

  async function check() {
    try {
      const status = await API.get("/api/capture/status");
      if (indicator && badgeText) {
        if (status.is_running) {
          indicator.className = "status-indicator active";
          badgeText.innerText = `SNIFFING (${status.packet_count} pkts)`;
        } else {
          indicator.className = "status-indicator";
          badgeText.innerText = "CAPTURE IDLE";
        }
      }
    } catch (e) {
      // ignore transient poll error
    }
  }

  check();
  capturePollingInterval = setInterval(check, 3000);
}

// Global Modal Utilities
function setupGlobalModals() {
  document.querySelectorAll("[data-close-modal]").forEach(btn => {
    btn.addEventListener("click", () => {
      const modalId = btn.getAttribute("data-close-modal");
      const modal = document.getElementById(modalId);
      if (modal) modal.classList.remove("open");
    });
  });

  window.addEventListener("click", (e) => {
    if (e.target.classList.contains("modal-overlay")) {
      e.target.classList.remove("open");
    }
  });
}

function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.classList.add("open");
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.classList.remove("open");
}

// -------------------------------------------------------------
// Live Traffic Capture Actions
// -------------------------------------------------------------
async function startLiveCapture() {
  const ifaceSelect = document.getElementById("capture-interface-select");
  const limitInput = document.getElementById("capture-limit-input");

  const iface = ifaceSelect ? ifaceSelect.value : null;
  const limit = limitInput ? parseInt(limitInput.value) || 1000 : 1000;

  try {
    const res = await API.post("/api/capture/start", { interface: iface, packet_limit: limit });
    if (res.success) {
      showToast("Live capture session initiated successfully!", "success");
      setTimeout(() => window.location.reload(), 1000);
    } else {
      showToast(`Failed to start capture: ${res.message}`, "danger");
    }
  } catch (err) {
    showToast(`Error: ${err.message}`, "danger");
  }
}

async function stopLiveCapture() {
  try {
    const res = await API.post("/api/capture/stop");
    if (res.success) {
      showToast(`Capture stopped. ${res.result.packets_captured} packets preserved in Evidence Vault.`, "success");
      setTimeout(() => window.location.reload(), 1200);
    } else {
      showToast("Failed to stop capture: No active session.", "warning");
    }
  } catch (err) {
    showToast(`Error: ${err.message}`, "danger");
  }
}

// -------------------------------------------------------------
// Simulated Traffic Triggers (Restricted to Localhost)
// -------------------------------------------------------------
async function triggerSimulation(scenario) {
  const endpoints = {
    normal: "/api/simulation/traffic/normal",
    port_scan: "/api/simulation/traffic/port-scan",
    syn_flood: "/api/simulation/traffic/syn-flood",
    brute_force: "/api/simulation/traffic/brute-force",
    data_exfil: "/api/simulation/traffic/data-exfil"
  };

  const url = endpoints[scenario];
  if (!url) return;

  showToast(`Simulating ${scenario.replace('_', ' ').toUpperCase()} on localhost...`, "info");
  try {
    const res = await API.post(url);
    if (res.success) {
      showToast(`Simulation completed: ${JSON.stringify(res.result.scenario)}`, "success");
      setTimeout(() => window.location.reload(), 1500);
    }
  } catch (err) {
    showToast(`Simulation error: ${err.message}`, "danger");
  }
}

// -------------------------------------------------------------
// PCAP Upload Handler
// -------------------------------------------------------------
async function uploadPCAPFile(formEl) {
  const formData = new FormData(formEl);
  showToast("Uploading and analyzing PCAP forensic artifact...", "info");

  try {
    const res = await API.upload("/api/capture/upload-pcap", formData);
    if (res.success) {
      showToast(`PCAP Ingestion Complete: ${res.data.packets_analyzed} packets analyzed, ${res.data.incidents_detected} incidents detected.`, "success");
      setTimeout(() => window.location.href = "/incident-detection", 1500);
    } else {
      showToast(`PCAP Upload failed: ${res.error}`, "danger");
    }
  } catch (err) {
    showToast(`Upload error: ${err.message}`, "danger");
  }
}

// -------------------------------------------------------------
// Evidence Vault: Integrity Verification & Tamper Simulation
// -------------------------------------------------------------
async function verifyEvidenceIntegrity(evidenceId) {
  showToast(`Recalculating SHA-256 for evidence ${evidenceId}...`, "info");
  try {
    const res = await API.post(`/api/evidence/${evidenceId}/verify`);
    if (res.success) {
      const result = res.result;
      if (result.status === "VERIFIED") {
        showToast(`Integrity VERIFIED: SHA-256 Hash matches baseline (${result.recalculated_hash.substring(0, 16)}...)`, "success");
      } else {
        showToast(`ALERT: TAMPER DETECTED! Recalculated hash does not match baseline!`, "danger");
      }
      setTimeout(() => window.location.reload(), 1500);
    }
  } catch (err) {
    showToast(`Verification error: ${err.message}`, "danger");
  }
}

async function simulateTampering(evidenceId) {
  if (!confirm(`Demonstration Warning:\nThis will intentionally inject 1 altered byte into evidence file ${evidenceId} to demonstrate cryptographic tampering detection in the lab.\nProceed?`)) {
    return;
  }

  try {
    const res = await API.post(`/api/evidence/${evidenceId}/simulate-tamper`);
    if (res.success) {
      showToast(`Tampering injected! Cryptographic verification triggered: ${res.result.status}`, "danger");
      setTimeout(() => window.location.reload(), 1500);
    }
  } catch (err) {
    showToast(`Tamper test error: ${err.message}`, "danger");
  }
}

// -------------------------------------------------------------
// Forensic PDF Report Generation
// -------------------------------------------------------------
async function generateForensicReport(incidentId) {
  showToast(`Generating official PDF forensic report for incident ${incidentId}...`, "info");
  try {
    const res = await API.post(`/api/reports/generate/${incidentId}`, { examiner: "Lead Forensic Analyst (Team JIIT)" });
    if (res.success) {
      showToast(`PDF Forensic Report generated successfully: ${res.report.filename}`, "success");
      setTimeout(() => window.location.href = "/reports", 1200);
    } else {
      showToast(`Report generation failed: ${res.error}`, "danger");
    }
  } catch (err) {
    showToast(`Error: ${err.message}`, "danger");
  }
}

// -------------------------------------------------------------
// Demo Mode Control
// -------------------------------------------------------------
async function seedDemoData() {
  showToast("Seeding comprehensive forensic lab demonstration scenarios...", "info");
  try {
    const res = await API.post("/api/demo/seed");
    if (res.success) {
      showToast(`Demo data seeded: ${res.result.incidents_created} incidents created across 4 attack categories.`, "success");
      setTimeout(() => window.location.reload(), 1500);
    }
  } catch (err) {
    showToast(`Seeding error: ${err.message}`, "danger");
  }
}

async function clearDemoData() {
  if (!confirm("Are you sure you want to reset demo data? Real physical evidence and authentic chain-of-custody records will be safely preserved.")) {
    return;
  }

  try {
    const res = await API.post("/api/demo/clear");
    if (res.success) {
      showToast(res.message, "success");
      setTimeout(() => window.location.reload(), 1200);
    }
  } catch (err) {
    showToast(`Error: ${err.message}`, "danger");
  }
}
