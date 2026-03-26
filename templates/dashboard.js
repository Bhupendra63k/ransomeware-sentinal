let alerts = [];
let devices = {};
let metrics = {};
let countdown = 5;


// ── Render: Alerts ───────────────────────────────────────────

function renderDevices(filter = "") {
  const list = document.getElementById("device-list");
  const countEl = document.getElementById("device-count");
  if (!list) return;

  const all = Object.entries(devices);
  const filtered = filter
    ? all.filter(([name]) => name.toLowerCase().includes(filter.toLowerCase()))
    : all;

  countEl.textContent = filtered.length;
  countEl.className = `section-count ${
    filtered.some(([, d]) => d.status_class === "danger") ? "danger" : "clean"
  }`;

  if (filtered.length === 0) {
    list.innerHTML = `<div class="empty-state">NO DEVICES</div>`;
    return;
  }

  list.innerHTML = filtered.map(([name, info]) => `
    <div class="device-item">
      <div class="device-icon ${info.status_class}">${info.icon}</div>
      <div class="device-info">
        <div class="device-name">${escapeHtml(name)}</div>
        <div class="device-ip">${info.ip}</div>
      </div>
      <span class="device-status ${info.status_class}">${info.status}</span>
      <div class="alert-file">${escapeHtml(a.file)}</div>
      <button onclick="killProcess('${a.file}')">KILL</button>
    </div>
  `).join("");
}

function filterDevices() {
  const val = document.getElementById("deviceSearch").value;
  renderDevices(val);
}

// ── Render: Metrics ──────────────────────────────────────────

function renderMetrics() {
  const el = (id, val) => {
    const node = document.getElementById(id);
    if (node) animateCount(node, parseInt(node.textContent) || 0, val);
  };
  el("m-threats", metrics.active_threats);
  el("m-devices", metrics.total_devices);
  el("m-blocked", metrics.blocked_today);
}

function animateCount(el, from, to) {
  const steps = 20;
  const step = (to - from) / steps;
  let current = from;
  let i = 0;
  const timer = setInterval(() => {
    current += step;
    el.textContent = Math.round(current);
    if (++i >= steps) {
      el.textContent = to;
      clearInterval(timer);
    }
  }, 30);
}

// ── Clock ────────────────────────────────────────────────────

function updateClock() {
  const el = document.getElementById("current-time");
  if (!el) return;
  const now = new Date();
  el.textContent = now.toLocaleTimeString("en-GB", { hour12: false });
}

function flashDanger() {
  document.body.style.outline = "2px solid var(--danger)";
  setTimeout(() => { document.body.style.outline = ""; }, 300);
}

// ── Actions ──────────────────────────────────────────────────
function clearAlerts() {
  fetch("/clear_alerts", { method: "POST" });
  alerts = [];
  renderAlerts();
}
// ── Threat Map Canvas ─────────────────────────────────────────
async function fetchData() {
  try {
    const res = await fetch("/status");
    const data = await res.json();

    // Alerts
    alerts = (data.alerts || []).map((a, i) => ({
      id: i,
      time: a.time || "00:00:00",
      device: a.device || "unknown",
      alert: a.alert || "unknown",
      file: a.file || "-",
      severity: "critical"
    }));

    // Devices
    devices = {};
    Object.entries(data.devices || {}).forEach(([name, info]) => {
      devices[name] = {
        status: info.status || "CLEAN",
        status_class: info.status_class || "clean",
        ip: info.ip || "N/A",
        icon: "💻"
      };
    });

    // Metrics
    metrics = {
      active_threats: alerts.length,
      total_devices: Object.keys(devices).length,
      blocked_today: alerts.length
    };

    renderAlerts();
    renderDevices();
    renderMetrics();

  } catch (err) {
    console.error("Fetch error:", err);
  }
}

function drawThreatMap() {
  const canvas = document.getElementById("threatMap");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const W = canvas.width, H = canvas.height;

  ctx.clearRect(0, 0, W, H);

  // Background
  ctx.fillStyle = "#0c0f1a";
  ctx.fillRect(0, 0, W, H);

  // Grid lines
  ctx.strokeStyle = "#1e2438";
  ctx.lineWidth = 0.5;
  for (let x = 0; x < W; x += 20) {
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke();
  }
  for (let y = 0; y < H; y += 20) {
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
  }

  // Threat origin dots
  const origins = [
    { x: 30,  y: 40,  color: "#ff2d2d", size: 5 },
    { x: 80,  y: 60,  color: "#ff2d2d", size: 4 },
    { x: 160, y: 30,  color: "#ffc542", size: 4 },
    { x: 190, y: 80,  color: "#ff2d2d", size: 6 },
    { x: 50,  y: 90,  color: "#ffc542", size: 3 },
    { x: 120, y: 70,  color: "#00e5b0", size: 3 },
    { x: 100, y: 100, color: "#ff2d2d", size: 5 },
  ];

  const target = { x: W / 2, y: H / 2 };

  // Draw lines to center
  origins.forEach(o => {
    const grad = ctx.createLinearGradient(o.x, o.y, target.x, target.y);
    grad.addColorStop(0, o.color + "99");
    grad.addColorStop(1, "transparent");
    ctx.beginPath();
    ctx.moveTo(o.x, o.y);
    ctx.lineTo(target.x, target.y);
    ctx.strokeStyle = grad;
    ctx.lineWidth = 1;
    ctx.stroke();
  });

  // Draw target
  ctx.beginPath();
  ctx.arc(target.x, target.y, 8, 0, Math.PI * 2);
  ctx.fillStyle = "rgba(0,229,176,0.15)";
  ctx.fill();
  ctx.beginPath();
  ctx.arc(target.x, target.y, 4, 0, Math.PI * 2);
  ctx.fillStyle = "#00e5b0";
  ctx.fill();
  ctx.shadowColor = "#00e5b0";
  ctx.shadowBlur = 10;
  ctx.fill();
  ctx.shadowBlur = 0;

  // Draw origin dots
  origins.forEach(o => {
    ctx.beginPath();
    ctx.arc(o.x, o.y, o.size, 0, Math.PI * 2);
    ctx.fillStyle = o.color;
    ctx.shadowColor = o.color;
    ctx.shadowBlur = 8;
    ctx.fill();
    ctx.shadowBlur = 0;
  });
}

// ── Animate Threat Map (Pulse) ────────────────────────────────

let mapPulse = 0;

function animateThreatMap() {
  const canvas = document.getElementById("threatMap");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const W = canvas.width, H = canvas.height;
  const target = { x: W / 2, y: H / 2 };

  drawThreatMap();

  // Pulse ring
  const r = 12 + (mapPulse % 30);
  const alpha = 1 - (mapPulse % 30) / 30;
  ctx.beginPath();
  ctx.arc(target.x, target.y, r, 0, Math.PI * 2);
  ctx.strokeStyle = `rgba(0,229,176,${alpha * 0.5})`;
  ctx.lineWidth = 1.5;
  ctx.stroke();

  mapPulse++;
  requestAnimationFrame(animateThreatMap);
}

// ── Helpers ───────────────────────────────────────────────────

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
function updateLastScan() {
  const el = document.getElementById("last-scan");
  if (!el) return;
  el.textContent = new Date().toLocaleTimeString("en-GB");
}
function killProcess(pid) {
  fetch("/kill", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ pid })
  });
}
const socket = io();

socket.on("new_alert", (alert) => {
  alerts.unshift(alert);
  metrics.active_threats = alerts.length;
  renderAlerts();
  renderMetrics();
});
// ── Init ──────────────────────────────────────────────────────
function init() {
  fetchData(); // first load

  setInterval(fetchData, 3000); // real-time updates
  setInterval(updateClock, 1000);
  setInterval(updateLastScan, 3000);

  animateThreatMap(); // optional visual
}

document.addEventListener("DOMContentLoaded", init);