/**
 * Forensic Data Visualizations (Chart.js Engine)
 * Theme: Dark Minimal SOC styling
 */

const Charts = {
  themeDefaults() {
    Chart.defaults.color = "#94a3b8";
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.font.size = 11;
    Chart.defaults.plugins.tooltip.backgroundColor = "#111827";
    Chart.defaults.plugins.tooltip.borderColor = "#2d3b52";
    Chart.defaults.plugins.tooltip.borderWidth = 1;
    Chart.defaults.plugins.tooltip.titleColor = "#f8fafc";
    Chart.defaults.plugins.tooltip.bodyColor = "#cbd5e1";
    Chart.defaults.plugins.tooltip.padding = 8;
  },

  createTrafficActivityChart(canvasId, timelineData) {
    this.themeDefaults();
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    return new Chart(ctx, {
      type: "line",
      data: {
        labels: timelineData.labels || [],
        datasets: [
          {
            label: "Total Packets",
            data: timelineData.packets || [],
            borderColor: "#10b981",
            backgroundColor: "rgba(16, 185, 129, 0.08)",
            borderWidth: 2,
            fill: true,
            tension: 0.35,
            pointRadius: 2,
            pointHoverRadius: 4
          },
          {
            label: "TCP Traffic",
            data: timelineData.tcp || [],
            borderColor: "#3b82f6",
            borderWidth: 1.5,
            borderDash: [3, 3],
            fill: false,
            tension: 0.35,
            pointRadius: 0
          },
          {
            label: "UDP Traffic",
            data: timelineData.udp || [],
            borderColor: "#f59e0b",
            borderWidth: 1.5,
            borderDash: [3, 3],
            fill: false,
            tension: 0.35,
            pointRadius: 0
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: {
            position: "top",
            labels: { boxWidth: 10, usePointStyle: true }
          }
        },
        scales: {
          x: {
            grid: { color: "rgba(255, 255, 255, 0.04)" },
            ticks: { maxTicksLimit: 12 }
          },
          y: {
            beginAtZero: true,
            grid: { color: "rgba(255, 255, 255, 0.06)" }
          }
        }
      }
    });
  },

  createIncidentDistributionChart(canvasId, incidentCounts) {
    this.themeDefaults();
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    const labels = ["Port Scan", "SYN Flood", "Brute Force", "Data Exfiltration"];
    const values = [
      incidentCounts["PORT_SCAN"] || 0,
      incidentCounts["SYN_FLOOD"] || 0,
      incidentCounts["BRUTE_FORCE"] || 0,
      incidentCounts["DATA_EXFILTRATION"] || 0
    ];

    return new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: labels,
        datasets: [{
          data: values,
          backgroundColor: [
            "#eab308", // Medium yellow
            "#ef4444", // High/Critical red
            "#f97316", // High orange
            "#8b5cf6"  // Exfil purple
          ],
          borderColor: "#111827",
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "right",
            labels: { boxWidth: 8, usePointStyle: true }
          }
        },
        cutout: "65%"
      }
    });
  },

  createProtocolBarChart(canvasId, protocolsData) {
    this.themeDefaults();
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    const labels = protocolsData.map(p => p.protocol);
    const counts = protocolsData.map(p => p.count);

    return new Chart(ctx, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [{
          label: "Packet Count",
          data: counts,
          backgroundColor: "#1e293b",
          borderColor: "#3b82f6",
          borderWidth: 1,
          borderRadius: 3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false } },
          y: { beginAtZero: true, grid: { color: "rgba(255, 255, 255, 0.05)" } }
        }
      }
    });
  },

  createNS2ThroughputChart(canvasId, timeLabels, throughputSeries) {
    this.themeDefaults();
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    return new Chart(ctx, {
      type: "line",
      data: {
        labels: timeLabels,
        datasets: [{
          label: "Throughput (Kbps)",
          data: throughputSeries,
          borderColor: "#10b981",
          backgroundColor: "rgba(16, 185, 129, 0.1)",
          borderWidth: 2,
          fill: true,
          tension: 0.2,
          pointRadius: 3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: "rgba(255, 255, 255, 0.04)" } },
          y: { beginAtZero: true, grid: { color: "rgba(255, 255, 255, 0.05)" } }
        }
      }
    });
  }
};
