/* ══════════════════════════════════════════════════════
   RANSOMSENTINEL — SOC DASHBOARD
   dashboard.js | Professional Threat Management System
══════════════════════════════════════════════════════ */

/* ── STATE ── */
const STATE = {
  alerts: [],
  resolvedAlerts: [],
  devices: {},
  currentTab: 'dashboard',
  currentSubTab: 'active',
  filters: { severity: '', device: '' },
  historyFilters: { severity: '', device: '' },
  metrics: { active_threats: 0, total_devices: 0, blocked_today: 0, resolved: 0 },
  startTime: Date.now(),
  connected: false
};

/* ── SOCKET.IO ── */
const socket = io("http://127.0.0.1:5000");

socket.on("connect", () => {
  STATE.connected = true;
  setConnectionStatus(true);
  console.log("✅ Socket connected");
});

socket.on("disconnect", () => {
  STATE.connected = false;
  setConnectionStatus(false);
});

socket.on("new_alert", () => {
  flashDanger();
  playAlertSound();

  // small delay avoids race condition
  setTimeout(fetchData, 500);
});

/* ── API CALLS ── */
async function fetchData() {
  try {
    const [activeRes, resolvedRes, devicesRes] = await Promise.all([
      fetch("/get_alerts"),
      fetch("/get_resolved_alerts").catch(() => ({ json: () => [] })),
      fetch("/status")
    ]);

    const activeAlerts = await activeRes.json();
    const resolvedAlerts = await resolvedRes.json().catch(() => []);
    const statusData = await devicesRes.json();

    // Normalize alerts
    STATE.alerts = (activeAlerts || []).map(a => normalizeAlert(a));
    STATE.resolvedAlerts = (resolvedAlerts || []).map(a => normalizeAlert(a, true));

    // Build device list
    const deviceObj = statusData.devices || {};
    STATE.devices = {};
    Object.entries(deviceObj).forEach(([name, info]) => {
      STATE.devices[name] = {
        name,
        status: (info.status || 'CLEAN').toUpperCase(),
        status_class: info.status_class || 'clean',
        ip: info.ip || 'N/A',
        last_seen: info.last_seen || '--',
        os: info.os || 'Unknown',
        online: info.online !== false
      };
    });

    // Compute metrics
    STATE.metrics = {
      active_threats: STATE.alerts.length,
      total_devices: Object.keys(STATE.devices).length,
      blocked_today: STATE.alerts.length + STATE.resolvedAlerts.length,
      resolved: STATE.resolvedAlerts.length
    };

    renderAll();
    updateDeviceFilter();
    updateHistoryDeviceFilter();

  } catch (err) {
    console.error("❌ Fetch error:", err);
  }
}

function normalizeAlert(a, resolved = false) {
  return {
    _id: a._id || a.id || String(Math.random()),
    device: a.device || 'unknown',
    alert: a.alert || 'Unknown Threat',
    file: a.file || '-',
    time: a.time || '--:--:--',
    created_at: a.created_at || a.time || '--:--:--',
    severity: a.severity || inferSeverity(a.alert || ''),
    status: resolved ? 'resolved' : (a.status || 'active')
  };
}

function inferSeverity(alertText) {
  const t = alertText.toLowerCase();
  if (t.includes('ransomware') || t.includes('malware') || t.includes('critical')) return 'high';
  if (t.includes('entropy') || t.includes('virus') || t.includes('suspicious')) return 'medium';
  return 'low';
}

/* ── RENDER ENGINE ── */
function renderAll() {
  renderMetrics();
  renderSeverityBreakdown();
  renderAlertsDash();
  renderDevicesDash();
  renderAlertsTab();
  renderDevicesFull();
  renderHistory();
  updateBadges();
}

/* Metrics */
function renderMetrics() {
  animateCount("m-threats", STATE.metrics.active_threats);
  animateCount("m-devices", STATE.metrics.total_devices);
  animateCount("m-blocked", STATE.metrics.blocked_today);
  animateCount("m-resolved", STATE.metrics.resolved);

  const badge = document.getElementById("top-threat-badge");
  const n = STATE.metrics.active_threats;
  badge.textContent = `${n} THREAT${n !== 1 ? 'S' : ''}`;
  badge.className = n ? "threat-badge has-threats" : "threat-badge calm";

  // Health/threat score
  const pct = Math.min(100, Math.round((STATE.metrics.active_threats / Math.max(1, STATE.metrics.blocked_today || 1)) * 100));
  const health = Math.max(0, 100 - pct);
  const healthEl = document.getElementById("health-fill");
  const healthPct = document.getElementById("health-pct");
  const threatFill = document.getElementById("threat-score-fill");
  const threatPct = document.getElementById("threat-score-pct");
  if (healthEl) { healthEl.style.width = health + '%'; healthPct.textContent = health + '%'; }
  if (threatFill) { threatFill.style.width = pct + '%'; threatPct.textContent = pct + '%'; }
}

/* Severity Breakdown */
function renderSeverityBreakdown() {
  const counts = { high: 0, medium: 0, low: 0 };
  STATE.alerts.forEach(a => { counts[a.severity] = (counts[a.severity] || 0) + 1; });
  const total = STATE.alerts.length || 1;

  ['high', 'medium', 'low'].forEach(sev => {
    const c = counts[sev] || 0;
    const el = document.getElementById(`sev-${sev}`);
    const bar = document.getElementById(`sev-bar-${sev}`);
    if (el) el.textContent = c;
    if (bar) bar.style.width = Math.round((c / total) * 100) + '%';
  });
}

/* Dashboard alerts */
function renderAlertsDash() {
  const list = document.getElementById("alerts-list-dash");
  const chip = document.getElementById("active-chip");
  if (!list) return;

  chip.textContent = STATE.alerts.length;
  chip.className = STATE.alerts.length ? 'count-chip' : 'count-chip calm';

  if (!STATE.alerts.length) {
    list.innerHTML = emptyState('🛡', 'ALL CLEAR — NO ACTIVE THREATS', 'System is monitoring all endpoints');
    return;
  }
  list.innerHTML = STATE.alerts.slice(0, 10).map(a => buildAlertCard(a, true)).join('');
}

/* Dashboard devices */
function renderDevicesDash() {
  const list = document.getElementById("devices-list-dash");
  const chip = document.getElementById("devices-chip-dash");
  if (!list) return;

  const all = Object.values(STATE.devices);
  chip.textContent = all.length;
  chip.className = all.some(d => d.status_class === 'danger') ? 'count-chip' : 'count-chip calm';

  if (!all.length) {
    list.innerHTML = emptyState('🖥', 'NO DEVICES REGISTERED', '');
    return;
  }
  list.innerHTML = all.slice(0, 8).map(d => buildDeviceMini(d)).join('');
}

/* Alerts Tab */
function renderAlertsTab() {
  const list = document.getElementById("alerts-full-list");
  if (!list) return;

  const sevF = document.getElementById("filter-severity")?.value || '';
  const devF = document.getElementById("filter-device")?.value || '';

  const source = STATE.currentSubTab === 'resolved' ? STATE.resolvedAlerts : STATE.alerts;
  let filtered = source.filter(a => {
    if (sevF && a.severity !== sevF) return false;
    if (devF && a.device !== devF) return false;
    return true;
  });

  const subActiveC = document.getElementById("sub-active-count");
  const subResolvedC = document.getElementById("sub-resolved-count");
  if (subActiveC) subActiveC.textContent = STATE.alerts.length;
  if (subResolvedC) subResolvedC.textContent = STATE.resolvedAlerts.length;

  if (!filtered.length) {
    list.innerHTML = emptyState('🔍', 'NO ALERTS MATCH FILTER', 'Try adjusting your filters');
    return;
  }
  list.innerHTML = filtered.map(a => buildAlertCard(a, STATE.currentSubTab === 'active')).join('');
}

/* Devices Full */
function renderDevicesFull() {
  const grid = document.getElementById("devices-full-grid");
  if (!grid) return;

  const searchQ = (document.getElementById("deviceSearchFull")?.value || '').toLowerCase();
  const statusF = (document.getElementById("filter-device-status")?.value || '').toLowerCase();

  let all = Object.values(STATE.devices).filter(d => {
    if (searchQ && !d.name.toLowerCase().includes(searchQ)) return false;
    if (statusF) {
      if (statusF === 'attack' && d.status_class !== 'danger') return false;
      if (statusF === 'online' && (!d.online || d.status_class === 'danger')) return false;
      if (statusF === 'offline' && d.online) return false;
    }
    return true;
  });

  if (!all.length) {
    grid.innerHTML = emptyState('◈', 'NO DEVICES MATCH FILTER', '');
    return;
  }
  grid.innerHTML = all.map(d => buildDeviceFull(d)).join('');
}

/* History */
function renderHistory() {
  const list = document.getElementById("history-list");
  if (!list) return;

  const sevF = document.getElementById("history-filter-sev")?.value || '';
  const devF = document.getElementById("history-filter-device")?.value || '';

  const all = [...STATE.alerts, ...STATE.resolvedAlerts]
    .filter(a => {
      if (sevF && a.severity !== sevF) return false;
      if (devF && a.device !== devF) return false;
      return true;
    })
    .sort((a, b) => b.created_at.localeCompare(a.created_at));

  if (!all.length) {
    list.innerHTML = emptyState('◷', 'NO ALERT HISTORY', 'Alerts will appear here as they are detected');
    return;
  }
  list.innerHTML = all.map(a => buildAlertCard(a, a.status === 'active')).join('');
}

/* ── CARD BUILDERS ── */
function buildAlertCard(a, showActions = true) {
  const sev = a.severity || 'low';
  const icons = { high: '🔴', medium: '🟡', low: '🟢' };
  const sevLabels = { high: 'HIGH', medium: 'MEDIUM', low: 'LOW' };
  const resolvedClass = a.status === 'resolved' ? 'resolved' : `sev-${sev}`;

  const actions = showActions && a.status !== 'resolved' ? `
    <div class="alert-actions">
      <button class="btn-resolve" onclick="resolveAlert('${escapeHtml(a._id)}')">✔ RESOLVE</button>
      <button class="btn-kill" onclick="killProcess('${escapeHtml(a.file)}')">⊗ KILL PROCESS</button>
    </div>` : (a.status === 'resolved' ? `<div class="alert-actions"><span style="font-family:var(--mono);font-size:9px;color:var(--teal);letter-spacing:.1em">✔ RESOLVED</span></div>` : '');

  return `
    <div class="alert-card ${resolvedClass}">
      <div class="alert-header">
        <div class="alert-sev-icon">${icons[sev] || '🔵'}</div>
        <div class="alert-info">
          <div class="alert-device-row">
            <span class="alert-device">${escapeHtml(a.device)}</span>
            <span class="alert-sev-tag">${sevLabels[sev] || 'LOW'}</span>
          </div>
          <div class="alert-type">${escapeHtml(a.alert)}</div>
        </div>
        <div class="alert-time">${a.time || '--:--:--'}</div>
      </div>
      <div class="alert-file">📄 ${escapeHtml(a.file)}</div>
      ${actions}
    </div>`;
}

function buildDeviceMini(d) {
  const cls = d.status_class === 'danger' ? 'attack' : (d.online ? 'online' : 'offline');
  const tagMap = { online: '🟢 ONLINE', offline: '🔴 OFFLINE', attack: '⚠ ATTACK' };
  return `
    <div class="device-mini ${cls}">
      <div class="device-status-dot ${cls}"></div>
      <div style="flex:1;overflow:hidden">
        <div class="device-mini-name">${escapeHtml(d.name)}</div>
        <div class="device-mini-ip">${d.ip}</div>
      </div>
      <span class="device-mini-tag ${cls}">${tagMap[cls] || '?'}</span>
    </div>`;
}

function buildDeviceFull(d) {
  const cls = d.status_class === 'danger' ? 'attack' : (d.online ? 'online' : 'offline');
  const statusLabels = { online: '🟢 ONLINE', offline: '🔴 OFFLINE', attack: '⚠ UNDER ATTACK' };
  const alertCount = STATE.alerts.filter(a => a.device === d.name).length;

  return `
    <div class="device-full-card ${cls}">
      <div class="dfc-header">
        <div class="dfc-icon">${cls === 'attack' ? '⚠' : '🖥'}</div>
        <div class="dfc-name">${escapeHtml(d.name)}</div>
        <span class="dfc-status ${cls}">${statusLabels[cls] || 'UNKNOWN'}</span>
      </div>
      <div class="dfc-fields">
        <div class="dfc-field">
          <span class="dfc-field-label">IP ADDRESS</span>
          <span class="dfc-field-val">${d.ip}</span>
        </div>
        <div class="dfc-field">
          <span class="dfc-field-label">LAST SEEN</span>
          <span class="dfc-field-val">${d.last_seen}</span>
        </div>
        <div class="dfc-field">
          <span class="dfc-field-label">ACTIVE ALERTS</span>
          <span class="dfc-field-val" style="color:${alertCount ? 'var(--red)' : 'var(--teal)'}">${alertCount}</span>
        </div>
        <div class="dfc-field">
          <span class="dfc-field-label">OS</span>
          <span class="dfc-field-val">${d.os}</span>
        </div>
      </div>
    </div>`;
}

/* ── ACTIONS ── */
async function resolveAlert(id) {
  if (!id) {
    console.error("❌ Invalid ID:", id);
    return;
  }

  try {
    console.log("🟡 Resolving:", id);

    const res = await fetch("/resolve_alert", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ id })
    });

    const data = await res.json();
    console.log("✅ Resolved:", data);

    // 🔥 refresh properly
    await fetchData();

  } catch (err) {
    console.error("❌ Resolve error:", err);
  }
}

async function killProcess(file) {
  if (!file) return;
  try {
    await fetch("/kill", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pid: file })
    });
  } catch (err) {
    console.error("Kill error:", err);
  }
}

function clearAlerts() {
  if (!confirm("Clear all active alerts? This cannot be undone.")) return;
  fetch("/clear_alerts", { method: "POST" })
    .then(() => { STATE.alerts = []; renderAll(); })
    .catch(console.error);
}

function applyFilters() {
  renderAlertsTab();
}

function clearFilters() {
  const sevEl = document.getElementById("filter-severity");
  const devEl = document.getElementById("filter-device");
  if (sevEl) sevEl.value = '';
  if (devEl) devEl.value = '';
  renderAlertsTab();
}

/* ── NAVIGATION ── */
function switchTab(tab) {
  STATE.currentTab = tab;

  document.querySelectorAll(".nav-btn").forEach(b => {
    b.classList.toggle("active", b.dataset.tab === tab);
  });
  document.querySelectorAll(".tab-pane").forEach(p => {
    p.classList.toggle("active", p.id === `tab-${tab}`);
  });

  if (tab === 'devices') renderDevicesFull();
  if (tab === 'history') renderHistory();
}

function switchSubTab(sub) {
  STATE.currentSubTab = sub;
  document.querySelectorAll(".sub-nav-btn").forEach(b => {
    b.classList.toggle("active", b.dataset.sub === sub);
  });
  renderAlertsTab();
}

/* ── FILTER UPDATES ── */
function updateDeviceFilter() {
  const sel = document.getElementById("filter-device");
  if (!sel) return;
  const current = sel.value;
  const devices = [...new Set(STATE.alerts.map(a => a.device))];
  sel.innerHTML = '<option value="">ALL DEVICES</option>' +
    devices.map(d => `<option value="${escapeHtml(d)}" ${current === d ? 'selected' : ''}>${escapeHtml(d)}</option>`).join('');
}

function updateHistoryDeviceFilter() {
  const sel = document.getElementById("history-filter-device");
  if (!sel) return;
  const current = sel.value;
  const all = [...STATE.alerts, ...STATE.resolvedAlerts];
  const devices = [...new Set(all.map(a => a.device))];
  sel.innerHTML = '<option value="">ALL DEVICES</option>' +
    devices.map(d => `<option value="${escapeHtml(d)}" ${current === d ? 'selected' : ''}>${escapeHtml(d)}</option>`).join('');
}

function updateBadges() {
  const n = STATE.alerts.length;
  const badge = document.getElementById("nav-alert-badge");
  if (badge) {
    badge.textContent = n;
    badge.classList.toggle("has-count", n > 0);
  }
}

/* ── THREAT MAP CANVAS ── */
const THREAT_ORIGINS = [
  { x: 32, y: 32, color: "#ff3547", size: 5 },
  { x: 78, y: 55, color: "#ff3547", size: 4 },
  { x: 158, y: 22, color: "#ffaa00", size: 4 },
  { x: 192, y: 78, color: "#ff3547", size: 6 },
  { x: 44, y: 95, color: "#ffaa00", size: 3 },
  { x: 118, y: 65, color: "#00ffe7", size: 3 },
  { x: 92, y: 105, color: "#ff3547", size: 5 },
  { x: 135, y: 40, color: "#ffaa00", size: 4 },
];

let mapPulse = 0;

function drawThreatMap() {
  const canvas = document.getElementById("threatMap");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const W = canvas.width, H = canvas.height;
  const tgt = { x: W / 2, y: H / 2 };

  ctx.clearRect(0, 0, W, H);

  // Background
  ctx.fillStyle = "#060a14";
  ctx.fillRect(0, 0, W, H);

  // Grid lines
  ctx.strokeStyle = "rgba(255,255,255,0.035)";
  ctx.lineWidth = 0.5;
  for (let x = 0; x < W; x += 20) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke(); }
  for (let y = 0; y < H; y += 20) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke(); }

  // Threat lines
  THREAT_ORIGINS.forEach((o, i) => {
    const progress = ((mapPulse * 0.4 + i * 20) % 60) / 60;
    const ix = o.x + (tgt.x - o.x) * progress;
    const iy = o.y + (tgt.y - o.y) * progress;

    const g = ctx.createLinearGradient(o.x, o.y, tgt.x, tgt.y);
    g.addColorStop(0, o.color + "80");
    g.addColorStop(1, "transparent");
    ctx.beginPath();
    ctx.moveTo(o.x, o.y);
    ctx.lineTo(tgt.x, tgt.y);
    ctx.strokeStyle = g;
    ctx.lineWidth = 0.8;
    ctx.stroke();

    // Moving particle
    ctx.beginPath();
    ctx.arc(ix, iy, 2, 0, Math.PI * 2);
    ctx.fillStyle = o.color;
    ctx.shadowColor = o.color;
    ctx.shadowBlur = 6;
    ctx.fill();
    ctx.shadowBlur = 0;
  });

  // Pulse rings at center
  for (let i = 0; i < 3; i++) {
    const r = 8 + ((mapPulse + i * 18) % 54);
    const alpha = 1 - ((mapPulse + i * 18) % 54) / 54;
    ctx.beginPath();
    ctx.arc(tgt.x, tgt.y, r, 0, Math.PI * 2);
    ctx.strokeStyle = `rgba(0,255,231,${alpha * 0.4})`;
    ctx.lineWidth = 1;
    ctx.stroke();
  }

  // Center dot
  ctx.beginPath();
  ctx.arc(tgt.x, tgt.y, 5, 0, Math.PI * 2);
  ctx.fillStyle = "#00ffe7";
  ctx.shadowColor = "#00ffe7";
  ctx.shadowBlur = 12;
  ctx.fill();
  ctx.shadowBlur = 0;

  // Origin dots
  THREAT_ORIGINS.forEach(o => {
    ctx.beginPath();
    ctx.arc(o.x, o.y, o.size, 0, Math.PI * 2);
    ctx.fillStyle = o.color;
    ctx.shadowColor = o.color;
    ctx.shadowBlur = 8;
    ctx.fill();
    ctx.shadowBlur = 0;
  });

  mapPulse++;
  requestAnimationFrame(drawThreatMap);
}

/* ── HELPERS ── */
function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function animateCount(id, to) {
  const el = document.getElementById(id);
  if (!el) return;
  const from = parseInt(el.textContent) || 0;
  if (from === to) return;
  let steps = 18, i = 0;
  const step = (to - from) / steps;
  let cur = from;
  const t = setInterval(() => {
    cur += step;
    el.textContent = Math.round(cur);
    if (++i >= steps) { el.textContent = to; clearInterval(t); }
  }, 22);
}

function flashDanger() {
  const el = document.getElementById("threat-flash");
  if (!el) return;
  el.classList.add("flash-on");
  setTimeout(() => el.classList.remove("flash-on"), 250);
}

function playAlertSound() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.type = 'square';
    osc.frequency.setValueAtTime(880, ctx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.15);
    gain.gain.setValueAtTime(0.1, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.2);
    osc.start(ctx.currentTime);
    osc.stop(ctx.currentTime + 0.2);
  } catch (e) {}
}

function setConnectionStatus(connected) {
  const dot = document.getElementById("conn-dot");
  const label = document.getElementById("conn-label");
  if (dot) dot.className = "status-dot " + (connected ? "connected" : "error");
  if (label) label.textContent = connected ? "CONNECTED" : "DISCONNECTED";
}

function updateClock() {
  const clock = document.getElementById("clock");
  const dateEl = document.getElementById("date-display");
  const now = new Date();
  if (clock) clock.textContent = now.toLocaleTimeString("en-GB", { hour12: false });
  if (dateEl) dateEl.textContent = now.toLocaleDateString("en-GB").replace(/\//g, '/');
}

function updateLastScan() {
  const el = document.getElementById("last-scan-time");
  const label = document.getElementById("last-scan-label");
  const t = new Date().toLocaleTimeString("en-GB");
  if (el) el.textContent = t;
  if (label) label.textContent = `LAST SCAN: ${t}`;
}

function updateUptime() {
  const el = document.getElementById("uptime-display");
  if (!el) return;
  const s = Math.floor((Date.now() - STATE.startTime) / 1000);
  const h = String(Math.floor(s / 3600)).padStart(2, '0');
  const m = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
  const sec = String(s % 60).padStart(2, '0');
  el.textContent = `${h}:${m}:${sec}`;
}

function updateAgentCount() {
  const el = document.getElementById("agent-count");
  if (el) el.textContent = Object.values(STATE.devices).filter(d => d.online).length;
}

function emptyState(icon, label, sub) {
  return `<div class="empty-state">
    <div class="empty-icon">${icon}</div>
    <div class="empty-label">${label}</div>
    ${sub ? `<div class="empty-sub">${sub}</div>` : ''}
  </div>`;
}

/* ── BOOT SEQUENCE ── */
function runBootSequence() {
  const overlay = document.getElementById("boot-overlay");
  const fill = document.getElementById("bootBarFill");
  const status = document.getElementById("bootStatus");

  const steps = [
    [10, "LOADING KERNEL MODULES..."],
    [25, "INITIALIZING WATCHDOG..."],
    [45, "CONNECTING TO MONGODB..."],
    [60, "MOUNTING FILE MONITORS..."],
    [75, "LOADING THREAT DATABASE..."],
    [90, "ESTABLISHING SOCKET CONNECTION..."],
    [100, "SYSTEM READY"]
  ];

  let i = 0;
  const tick = setInterval(() => {
    if (i >= steps.length) {
      clearInterval(tick);
      setTimeout(() => {
        overlay.classList.add("hidden");
        setTimeout(() => overlay.remove(), 700);
      }, 400);
      return;
    }
    const [pct, msg] = steps[i];
    if (fill) fill.style.width = pct + '%';
    if (status) status.textContent = msg;
    i++;
  }, 250);
}

/* ── EVENT LISTENERS ── */
function bindEvents() {
  document.getElementById("clear-alerts-btn")?.addEventListener("click", clearAlerts);
  document.getElementById("clear-all-btn2")?.addEventListener("click", clearAlerts);
}

/* ── INIT ── */
document.addEventListener("DOMContentLoaded", () => {
  runBootSequence();
  bindEvents();
  updateClock();
  fetchData(); // ✅ correct function

  drawThreatMap();

  setInterval(fetchData, 4000); // ✅ correct
  setInterval(updateClock, 1000);
  setInterval(updateLastScan, 4000);
  setInterval(updateUptime, 1000);
  setInterval(updateAgentCount, 4000);
});