/**
 * Forensic System REST API Client
 */

const API = {
  async get(url) {
    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      return await res.json();
    } catch (err) {
      console.error(`API GET ${url} failed:`, err);
      throw err;
    }
  },

  async post(url, data = {}) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      return await res.json();
    } catch (err) {
      console.error(`API POST ${url} failed:`, err);
      throw err;
    }
  },

  async upload(url, formData) {
    try {
      const res = await fetch(url, {
        method: "POST",
        body: formData
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      return await res.json();
    } catch (err) {
      console.error(`API Upload ${url} failed:`, err);
      throw err;
    }
  }
};

// UI Notification Toast
function showToast(message, type = "info") {
  let toastContainer = document.getElementById("toast-container");
  if (!toastContainer) {
    toastContainer = document.createElement("div");
    toastContainer.id = "toast-container";
    toastContainer.style.cssText = `
      position: fixed; bottom: 20px; right: 20px; z-index: 9999;
      display: flex; flex-direction: column; gap: 8px; pointer-events: none;
    `;
    document.body.appendChild(toastContainer);
  }

  const toast = document.createElement("div");
  const colors = {
    info: { bg: "#1e293b", border: "#3b82f6", text: "#93c5fd" },
    success: { bg: "#064e3b", border: "#10b981", text: "#6ee7b7" },
    danger: { bg: "#7f1d1d", border: "#ef4444", text: "#fca5a5" },
    warning: { bg: "#713f12", border: "#eab308", text: "#fde047" }
  };
  const c = colors[type] || colors.info;

  toast.style.cssText = `
    background: ${c.bg}; border: 1px solid ${c.border}; color: ${c.text};
    padding: 10px 16px; border-radius: 4px; font-size: 12px; font-weight: 500;
    box-shadow: 0 4px 12px rgba(0,0,0,0.5); pointer-events: auto;
    transition: opacity 0.3s ease;
  `;
  toast.innerText = message;
  toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}
