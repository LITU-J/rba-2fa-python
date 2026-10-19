/* =========================================================
   dashboard.js — RBA-2FA Dashboard (Full File)
   ========================================================= */

// ── Inactivity timer ──────────────────────────────────────
const INACTIVE_LIMIT_MS = 5 * 60 * 1000;
const WARN_BEFORE_MS    = 1 * 60 * 1000;
let inactivityTimer = null;
let warnTimer       = null;
let warningShown    = false;

function resetInactivityTimer() {
  clearTimeout(inactivityTimer);
  clearTimeout(warnTimer);
  const warning = document.getElementById('inactivityWarning');
  if (warning) warning.style.display = 'none';
  warningShown = false;
  warnTimer       = setTimeout(showInactivityWarning, INACTIVE_LIMIT_MS - WARN_BEFORE_MS);
  inactivityTimer = setTimeout(autoLogout, INACTIVE_LIMIT_MS);
}

function showInactivityWarning() {
  warningShown = true;
  const warning = document.getElementById('inactivityWarning');
  if (warning) {
    warning.style.display = 'flex';
    let secs = Math.floor(WARN_BEFORE_MS / 1000);
    const countEl = document.getElementById('inactivity-countdown');
    const tick = setInterval(() => {
      secs--;
      if (countEl) {
        const m = Math.floor(secs / 60);
        const s = secs % 60;
        countEl.textContent = `${m}:${s.toString().padStart(2,'0')}`;
      }
      if (secs <= 0) clearInterval(tick);
    }, 1000);
  }
}

async function autoLogout() {
  try { await fetch('/api/auth/logout', { method: 'POST' }); } catch {}
  window.location.href = '/login?reason=inactivity';
}

['mousemove','keydown','click','scroll','touchstart'].forEach(evt =>
  document.addEventListener(evt, resetInactivityTimer, { passive: true })
);

// ── Helpers ───────────────────────────────────────────────
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function toLocalTime(utcStr) {
  if (!utcStr) return '—';
  try {
    const str = utcStr.includes('Z') ? utcStr : utcStr + 'Z';
    return new Date(str).toLocaleString('en-ZA', {
      timeZone: 'Africa/Windhoek',
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false
    });
  } catch { return utcStr; }
}

function tierBadge(tier) {
  const map = { LOW:'badge-low', MEDIUM:'badge-medium', HIGH:'badge-high', CRITICAL:'badge-critical' };
  return `<span class="badge ${map[tier]||''}">${tier||'—'}</span>`;
}

function outcomeBadge(outcome) {
  if (!outcome) return '—';
  const cls = outcome.startsWith('success') ? 'badge-success' : 'badge-fail';
  return `<span class="badge ${cls}">${outcome}</span>`;
}

function authMethod(method) {
  const map = {
    password:    '🔑 Password',
    otp:         '📱 OTP',
    totp:        '🔐 TOTP',
    totp_backup: '🗝️ Backup Code',
    none:        '—'
  };
  return map[method] || method || '—';
}

function formatLocation(city, country) {
  if (!city && !country) return '—';
  if (!city) return country;
  if (!country) return city;
  return `${city}, ${country}`;
}

function showToast(msg, type = 'info') {
  const t = document.createElement('div');
  t.className = `toast toast-${type}`;
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.classList.add('show'), 10);
  setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.remove(), 300); }, 3500);
}

function renderPagination(containerId, current, total, cb) {
  const el = document.getElementById(containerId);
  if (!el || total <= 1) { if (el) el.innerHTML = ''; return; }
  let html = '';
  for (let i = 1; i <= total; i++) {
    html += `<button class="page-btn${i === current ? ' active' : ''}" onclick="${cb.name}(${i})">${i}</button>`;
  }
  el.innerHTML = html;
}

// ── Section navigation ────────────────────────────────────
function showSection(name) {
  document.querySelectorAll('.dash-section').forEach(s => s.style.display = 'none');
  const target = document.getElementById('sec-' + name);
  if (target) target.style.display = 'block';
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const navEl = document.querySelector(`.nav-item[data-section="${name}"]`);
  if (navEl) navEl.classList.add('active');

  if (name === 'overview') {
    loadRecentActivity();
    loadRiskTrend();
    loadRiskGauge();
    loadLoginMap();
    loadTrustTimeline();
    // Fix Leaflet map size after section becomes visible
    setTimeout(() => { if (loginMap) loginMap.invalidateSize(); }, 150);
  }
  if (name === 'history')  loadHistory(1);
  if (name === 'devices')  loadDevices();
  if (name === 'sessions') loadSessions();
  if (name === 'totp')     loadTotpSection();
  if (name === 'admin')    loadAdmin();
}

function toggleGroup(id) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle('collapsed');
}

// ── Load user profile + overview stats ────────────────────
async function loadMe() {
  try {
    const r = await fetch('/api/dashboard/overview');
    if (r.status === 401) { window.location.href = '/login.html'; return; }
    if (!r.ok) return;
    const d = await r.json();
    const last = d.last_login || {};

    // Welcome name
    setText('welcomeName', d.username || '');

    // Sidebar username + avatar initial
    const nameEl = document.querySelector('.sidebar-user .info .name');
    if (nameEl) nameEl.textContent = d.username || 'User';
    const avatarEl = document.querySelector('.sidebar-user .avatar');
    if (avatarEl) avatarEl.textContent = (d.username || 'U')[0].toUpperCase();

    // Nav username (top bar)
    const navEl = document.querySelector('.nav-user');
    if (navEl) navEl.textContent = d.username || '';

    // Overview stat cards
    setText('statScore',   last.risk_score != null ? last.risk_score : '—');
    setText('statTier',    last.risk_tier  || '—');
    setText('statDevices', d.device_count  != null ? d.device_count  : '—');
    setText('statTotp',    d.totp_enabled  ? '✅ On' : '❌ Off');

    // Last login location card
    setText('locCity', last.city || '—');
    const sub = [last.country, last.isp].filter(Boolean).join(' · ');
    setText('locDetails', sub);

  } catch (e) { console.error('loadMe', e); }
}

// ── Init ──────────────────────────────────────────────────
async function init() {
  resetInactivityTimer();
  await loadMe();
  await loadCurrentSession();
  await loadRecentActivity();
  loadRiskTrend();
}

// ── Current Session Card ──────────────────────────────────
async function loadCurrentSession() {
  try {
    const r = await fetch('/api/auth/session-context');
    if (r.status === 401) { window.location.href = '/login.html'; return; }
    const d = await r.json();
    setText('sess-ip',      d.ip      || 'Unavailable');
    setText('sess-country', d.country || 'Unavailable');
    setText('sess-city',    d.city    || 'Unavailable');
    setText('sess-isp',     d.isp     || 'Unavailable');
  } catch (e) { console.error('loadCurrentSession', e); }
}

// ── Recent Activity (overview) ────────────────────────────
async function loadRecentActivity() {
  try {
    const r = await fetch('/api/dashboard/recent-activity');
    if (!r.ok) return;
    const { events } = await r.json();
    const tbody = document.querySelector('#tbl-recent tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    (events || []).slice(0, 5).forEach(e => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${toLocalTime(e.timestamp)}</td>
        <td>${outcomeBadge(e.outcome)}</td>
        <td>${authMethod(e.auth_method)}</td>
        <td>${formatLocation(e.city, e.country)}</td>
        <td>${tierBadge(e.risk_tier)}</td>`;
      tbody.appendChild(tr);
    });
  } catch (e) { console.error('loadRecentActivity', e); }
}

// ── Login History ─────────────────────────────────────────
async function loadHistory(page = 1) {
  try {
    const r = await fetch(`/api/dashboard/login-history?page=${page}&per_page=20`);
    if (!r.ok) return;
    const { history, pages, current_page } = await r.json();
    const tbody = document.querySelector('#tbl-history tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    (history || []).forEach(e => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${toLocalTime(e.timestamp)}</td>
        <td>${outcomeBadge(e.outcome)}</td>
        <td>${authMethod(e.auth_method)}</td>
        <td>${e.ip || '—'}</td>
        <td>${formatLocation(e.city, e.country)}</td>
        <td>${e.isp || '—'}</td>
        <td>${tierBadge(e.risk_tier)}</td>
        <td>${e.risk_score ?? '—'}</td>
        <td><button class="btn-details">🔍 Details</button></td>`;
      tr.querySelector('.btn-details').addEventListener('click', ev => {
        ev.stopPropagation();
        openRiskPanel(e);
      });
      tbody.appendChild(tr);
    });
    renderPagination('history-pagination', current_page, pages, loadHistory);
  } catch (e) { console.error('loadHistory', e); }
}

// ── CSV Export ────────────────────────────────────────────
async function exportCSV() {
  try {
    const r = await fetch('/api/dashboard/login-history?per_page=1000');
    if (!r.ok) return;
    const { history } = await r.json();
    const rows = [['Timestamp','Outcome','Auth Method','IP','City','Country','ISP','Risk Tier','Risk Score']];
    (history || []).forEach(e => rows.push([
      toLocalTime(e.timestamp), e.outcome, e.auth_method,
      e.ip||'', e.city||'', e.country||'', e.isp||'',
      e.risk_tier, e.risk_score ?? ''
    ]));
    const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(',')).join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    a.download = `login-history-${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
  } catch { showToast('Export failed', 'error'); }
}

// ── Known Devices ─────────────────────────────────────────
async function loadDevices() {
  try {
    const r = await fetch('/api/dashboard/known-devices');
    if (!r.ok) return;
    const { devices } = await r.json();
    const tbody = document.querySelector('#tbl-devices tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    (devices || []).forEach(d => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${d.device_label || 'Unknown Device'}</td>
        <td>${toLocalTime(d.first_seen)}</td>
        <td>${toLocalTime(d.last_seen)}</td>
        <td>${d.login_count ?? 0}</td>
        <td>
          <button class="btn-revoke" onclick="revokeDevice('${d.device_hash_prefix}')">
            Revoke
          </button>
        </td>`;
      tbody.appendChild(tr);
    });
    if (!devices || devices.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No trusted devices found.</td></tr>';
    }
  } catch (e) { console.error('loadDevices', e); }
}

async function revokeDevice(prefix) {
  if (!confirm('Remove this trusted device? You will need to verify again on next login.')) return;
  try {
    const r = await fetch('/api/dashboard/devices/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_hash_prefix: prefix })
    });
    const d = await r.json();
    if (r.ok) { showToast('Device removed', 'success'); loadDevices(); }
    else showToast(d.error || 'Failed', 'error');
  } catch { showToast('Network error', 'error'); }
}

// ── Active Sessions ───────────────────────────────────────
async function loadSessions() {
  const container = document.getElementById('sessions-list');
  try {
    const r = await fetch('/api/dashboard/sessions');
    if (!r.ok) {
      if (container) container.innerHTML = '<p class="empty-state">No active sessions found.</p>';
      return;
    }
    const { sessions } = await r.json();
    if (!container) return;
    container.innerHTML = '';
    if (!sessions || sessions.length === 0) {
      container.innerHTML = '<p class="empty-state">No active sessions found.</p>';
      return;
    }
    sessions.forEach(s => {
      const card = document.createElement('div');
      card.className = 'session-card' + (s.is_current ? ' current' : '');
      card.innerHTML = `
        <div class="session-info">
          <div class="session-device">${(s.user_agent || 'Unknown Device').slice(0, 80)}</div>
          <div class="session-meta">
            <span>${s.ip || '—'}</span> ·
            <span>${formatLocation(s.city, s.country)}</span> ·
            <span>Last active: ${toLocalTime(s.last_active)}</span>
          </div>
        </div>
        <div class="session-actions">
          ${s.is_current
            ? '<span class="badge-current">Current Session</span>'
            : `<button class="btn-revoke" onclick="revokeSession('${s.session_uuid}')">Revoke</button>`
          }
        </div>`;
      container.appendChild(card);
    });
  } catch (e) { console.error('loadSessions', e); }
}

async function revokeSession(uuid) {
  if (!confirm('Revoke this session? That device will be logged out immediately.')) return;
  try {
    const r = await fetch('/api/dashboard/sessions/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_uuid: uuid })
    });
    const d = await r.json();
    if (r.ok) { showToast('Session revoked', 'success'); loadSessions(); }
    else showToast(d.error || 'Failed', 'error');
  } catch { showToast('Network error', 'error'); }
}

// ── Risk Trend Chart ──────────────────────────────────────
let riskChart = null;

async function loadRiskTrend() {
  try {
    const r = await fetch('/api/dashboard/risk-trend');
    if (!r.ok) return;
    const { trend } = await r.json();
    const canvas = document.getElementById('risk-trend-chart');
    if (!canvas || typeof Chart === 'undefined') return;
    const labels = (trend || []).map(t => toLocalTime(t.timestamp).slice(0, 10));
    const scores = (trend || []).map(t => t.risk_score);
    const colors = (trend || []).map(t => {
      const tier = t.risk_tier;
      return tier === 'CRITICAL' ? '#ef4444'
           : tier === 'HIGH'     ? '#f97316'
           : tier === 'MEDIUM'   ? '#eab308'
           :                       '#22c55e';
    });
    if (riskChart) riskChart.destroy();
    riskChart = new Chart(canvas, {
      type: 'line',
      data: {
        labels,
        datasets: [{
          label: 'Risk Score',
          data: scores,
          borderColor: '#8b5cf6',
          backgroundColor: 'rgba(139,92,246,0.1)',
          pointBackgroundColor: colors,
          pointBorderColor: colors,
          pointRadius: 5,
          tension: 0.3,
          fill: true
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: { labels: { color: '#374151' } },          // FIXED: light theme
          tooltip: {
            callbacks: {
              afterLabel: ctx => `Tier: ${(trend[ctx.dataIndex] || {}).risk_tier || ''}`
            }
          }
        },
        scales: {
          x: { ticks: { color: '#64748b' }, grid: { color: 'rgba(148,163,184,0.2)' } }, // FIXED
          y: { min: 0, max: 100, ticks: { color: '#64748b' }, grid: { color: 'rgba(148,163,184,0.2)' } }
        }
      }
    });
  } catch (e) { console.error('loadRiskTrend', e); }
}

// ── Feature #2: Live Risk Gauge ───────────────────────────
function drawGaugeSVG(score, tier) {
  const W = 200, H = 120, R = 80, cx = 100, cy = 108;
  const tierColors = { LOW:'#16a34a', MEDIUM:'#d97706', HIGH:'#ea580c', CRITICAL:'#dc2626' };
  const col = tierColors[tier] || '#94a3b8';

  // Convert angle to x/y coordinates on the arc
  const toXY = deg => ({
    x: cx + R * Math.cos(deg * Math.PI / 180),
    y: cy + R * Math.sin(deg * Math.PI / 180)
  });

  const arcStart = toXY(-180); // leftmost point
  const arcEnd   = toXY(0);    // rightmost point

  // Background semicircle path
  const bgPath = `M ${arcStart.x.toFixed(1)} ${arcStart.y.toFixed(1)} A ${R} ${R} 0 0 1 ${arcEnd.x.toFixed(1)} ${arcEnd.y.toFixed(1)}`;

  // Fill arc — proportional to score
  const fillDeg = Math.min(180, Math.max(0, (score / 100) * 180));
  const fillEnd = toXY(-180 + fillDeg);
  const largeArc = fillDeg > 180 ? 1 : 0;
  const fillPath = `M ${arcStart.x.toFixed(1)} ${arcStart.y.toFixed(1)} A ${R} ${R} 0 ${largeArc} 1 ${fillEnd.x.toFixed(1)} ${fillEnd.y.toFixed(1)}`;

  return `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
    <path d="${bgPath}" fill="none" stroke="#e2e8f0" stroke-width="14" stroke-linecap="round"/>
    ${fillDeg > 0 ? `<path d="${fillPath}" fill="none" stroke="${col}" stroke-width="14" stroke-linecap="round"/>` : ''}
    <text x="${cx}" y="${cy - 24}" text-anchor="middle" fill="${col}"
          font-size="32" font-weight="900" font-family="system-ui,sans-serif">${score}</text>
    <text x="${cx}" y="${cy - 6}" text-anchor="middle" fill="#94a3b8"
          font-size="10" font-weight="600" font-family="system-ui,sans-serif">/ 100</text>
    <text x="${cx}" y="${cy + 10}" text-anchor="middle" fill="${col}"
          font-size="11" font-weight="800" font-family="system-ui,sans-serif" letter-spacing="1">${tier}</text>
    <text x="${(arcStart.x - 2).toFixed(0)}" y="${(arcStart.y + 16).toFixed(0)}"
          text-anchor="end" fill="#cbd5e1" font-size="9" font-family="system-ui,sans-serif">0</text>
    <text x="${(arcEnd.x + 2).toFixed(0)}" y="${(arcEnd.y + 16).toFixed(0)}"
          text-anchor="start" fill="#cbd5e1" font-size="9" font-family="system-ui,sans-serif">100</text>
  </svg>`;
}

async function loadRiskGauge() {
  try {
    const r = await fetch('/api/dashboard/recent-activity');
    if (!r.ok) return;
    const { events } = await r.json();
    if (!events || !events.length) return;

    const latest = events[0];
    const score  = latest.risk_score ?? 0;
    const tier   = (latest.risk_tier || 'LOW').toUpperCase();

    const svgBox = document.getElementById('gaugeSvgBox');
    if (svgBox) svgBox.innerHTML = drawGaugeSVG(score, tier);

    const tsEl = document.getElementById('gaugeTimestamp');
    if (tsEl) tsEl.textContent = toLocalTime(latest.timestamp);

    const detailsEl = document.getElementById('gaugeDetails');
    if (detailsEl) detailsEl.innerHTML = `
      <div class="gauge-info-grid">
        <div class="gauge-info-item">
          <div class="gauge-info-label">Outcome</div>
          <div class="gauge-info-value">${latest.outcome || '—'}</div>
        </div>
        <div class="gauge-info-item">
          <div class="gauge-info-label">Auth Method</div>
          <div class="gauge-info-value">${authMethod(latest.auth_method)}</div>
        </div>
        <div class="gauge-info-item">
          <div class="gauge-info-label">Location</div>
          <div class="gauge-info-value" style="font-size:0.79rem;">${formatLocation(latest.city, latest.country)}</div>
        </div>
        <div class="gauge-info-item">
          <div class="gauge-info-label">IP Address</div>
          <div class="gauge-info-value" style="color:#7c3aed;font-size:0.79rem;">${latest.ip || '—'}</div>
        </div>
      </div>`;
  } catch(e) { console.error('loadRiskGauge', e); }
}

// ── Feature #3: Login Location Map ───────────────────────
let loginMap = null;
let loginMapMarkers = [];

async function loadLoginMap() {
  const mapEl = document.getElementById('loginMapContainer');
  if (!mapEl || typeof L === 'undefined') return;

  try {
    const r = await fetch('/api/dashboard/login-locations');
    if (!r.ok) return;
    const { locations } = await r.json();

    // Initialize map only once
    if (!loginMap) {
      loginMap = L.map('loginMapContainer', {
        scrollWheelZoom: false,
        zoomControl: true
      }).setView([-22.5597, 17.0832], 3);

      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© <a href="https://www.openstreetmap.org/copyright" target="_blank">OpenStreetMap</a>',
        maxZoom: 18
      }).addTo(loginMap);
    } else {
      // Remove old markers
      loginMapMarkers.forEach(m => m.remove());
      loginMapMarkers = [];
    }

    const emptyNote = document.getElementById('mapEmptyNote');

    if (!locations || !locations.length) {
      if (emptyNote) emptyNote.style.display = 'inline';
      setTimeout(() => loginMap && loginMap.invalidateSize(), 200);
      return;
    }
    if (emptyNote) emptyNote.style.display = 'none';

    const tierColors = { LOW:'#16a34a', MEDIUM:'#d97706', HIGH:'#ea580c', CRITICAL:'#dc2626' };
    const bounds = [];

    locations.forEach(loc => {
      const lat = parseFloat(loc.lat);
      const lon = parseFloat(loc.lon);
      if (isNaN(lat) || isNaN(lon)) return;

      const tier = (loc.risk_tier || 'LOW').toUpperCase();
      const col  = tierColors[tier] || '#64748b';

      const marker = L.circleMarker([lat, lon], {
        radius: 8, fillColor: col, color: '#ffffff',
        weight: 2, opacity: 1, fillOpacity: 0.85
      }).bindPopup(`
        <div style="font-size:0.82rem;min-width:150px;line-height:1.6;">
          <div style="font-weight:700;color:#1e293b;margin-bottom:2px;">
            ${loc.city || 'Unknown'}, ${loc.country || ''}
          </div>
          <div style="color:#64748b;font-size:0.74rem;margin-bottom:6px;">
            ${toLocalTime(loc.timestamp)}
          </div>
          <span style="background:${col}18;color:${col};border:1px solid ${col}40;
                border-radius:999px;padding:2px 9px;font-size:0.73rem;font-weight:700;">${tier}</span>
          <span style="color:#64748b;font-size:0.74rem;margin-left:6px;">
            Score: ${loc.risk_score ?? '—'}
          </span>
        </div>`).addTo(loginMap);

      loginMapMarkers.push(marker);
      bounds.push([lat, lon]);
    });

    if (bounds.length > 0) {
      loginMap.fitBounds(bounds, { padding: [30, 30], maxZoom: 10 });
    }

    setTimeout(() => loginMap && loginMap.invalidateSize(), 200);
  } catch(e) { console.error('loadLoginMap', e); }
}

// ── Feature #4: Print Security Report ────────────────────
async function printReport() {
  try {
    showToast('Preparing report…', 'info');
    const r = await fetch('/api/dashboard/login-history?per_page=50');
    if (!r.ok) { showToast('Failed to load data', 'error'); return; }
    const { history, total } = await r.json();

    const userName   = (document.querySelector('.sidebar-user .info .name') || {}).textContent || 'User';
    const now        = new Date().toLocaleString('en-ZA', { timeZone: 'Africa/Windhoek' });
    const tierColors = { LOW:'#16a34a', MEDIUM:'#d97706', HIGH:'#ea580c', CRITICAL:'#dc2626' };

    const successCount = (history||[]).filter(e => e.outcome === 'success').length;
    const failCount    = (history||[]).length - successCount;
    const scoreAvg     = (history||[]).length
      ? Math.round((history||[]).reduce((a,e) => a + (e.risk_score||0), 0) / history.length)
      : 0;
    const critCount    = (history||[]).filter(e => e.risk_tier === 'CRITICAL').length;

    const rows = (history||[]).map(e => {
      const tier = e.risk_tier || 'LOW';
      const col  = tierColors[tier] || '#64748b';
      return `<tr>
        <td>${toLocalTime(e.timestamp)}</td>
        <td>${e.outcome || '—'}</td>
        <td>${authMethod(e.auth_method)}</td>
        <td>${e.ip || '—'}</td>
        <td>${formatLocation(e.city, e.country)}</td>
        <td style="color:${col};font-weight:700;">${tier}</td>
        <td style="color:${col};font-weight:700;">${e.risk_score ?? '—'}</td>
      </tr>`;
    }).join('');

    const frame = document.getElementById('printFrame');
    if (!frame) return;

    frame.innerHTML = `
      <div class="pr-header">
        <h1>🔐 RBA-2FA Security Report</h1>
        <div class="pr-meta">
          <span><strong>User:</strong> ${userName}</span>
          <span><strong>Generated:</strong> ${now}</span>
          <span><strong>Showing:</strong> Last ${(history||[]).length} of ${total ?? '?'} total logins</span>
        </div>
      </div>
      <div class="pr-section">Login Summary</div>
      <div class="pr-stats">
        <div class="pr-stat">
          <span class="pr-stat-val">${successCount}</span>
          <div class="pr-stat-lbl">Successful</div>
        </div>
        <div class="pr-stat">
          <span class="pr-stat-val">${failCount}</span>
          <div class="pr-stat-lbl">Failed / Blocked</div>
        </div>
        <div class="pr-stat">
          <span class="pr-stat-val">${scoreAvg}</span>
          <div class="pr-stat-lbl">Avg Risk Score</div>
        </div>
        <div class="pr-stat">
          <span class="pr-stat-val">${critCount}</span>
          <div class="pr-stat-lbl">Critical Events</div>
        </div>
      </div>
      <div class="pr-section">Login Details</div>
      <table class="pr-table">
        <thead>
          <tr>
            <th>Timestamp</th><th>Outcome</th><th>Auth Method</th>
            <th>IP Address</th><th>Location</th><th>Risk Tier</th><th>Score</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>`;

    window.print();
  } catch(e) { console.error('printReport', e); showToast('Could not generate report', 'error'); }
}

// ── Feature #5: Trust Timeline ────────────────────────────
async function loadTrustTimeline() {
  try {
    const r = await fetch('/api/dashboard/recent-activity');
    if (!r.ok) return;
    const { events } = await r.json();

    const container = document.getElementById('trustTimeline');
    if (!container) return;

    if (!events || !events.length) {
      container.innerHTML = '<div style="color:#94a3b8;font-size:0.85rem;padding:12px 0;">No activity recorded yet.</div>';
      return;
    }

    container.innerHTML = events.slice(0, 5).map(e => {
      const tier = (e.risk_tier || 'LOW').toUpperCase();
      return `
        <div class="tl-item">
          <div class="tl-dot ${tier}"></div>
          <div class="tl-content">
            <div class="tl-time">${toLocalTime(e.timestamp)}</div>
            <div class="tl-main">
              ${outcomeBadge(e.outcome)}
              <span style="color:#374151;font-size:0.82rem;">${authMethod(e.auth_method)}</span>
              ${tierBadge(e.risk_tier)}
            </div>
            <div class="tl-loc">📍 ${formatLocation(e.city, e.country)}</div>
          </div>
        </div>`;
    }).join('');
  } catch(e) { console.error('loadTrustTimeline', e); }
}

// ── Feature #1: Risk Breakdown Panel ─────────────────────
// (Defined at global scope so onclick="closeRiskPanel()" in HTML works)
function openRiskPanel(entry) {
  const tier  = (entry.risk_tier  || 'LOW').toUpperCase();
  const score = entry.risk_score ?? 0;

  let reasons = [];
  try {
    reasons = typeof entry.risk_reasons === 'string'
      ? JSON.parse(entry.risk_reasons)
      : (entry.risk_reasons || []);
  } catch {}

  let factors = [];
  try {
    factors = typeof entry.required_factors === 'string'
      ? JSON.parse(entry.required_factors)
      : (entry.required_factors || []);
  } catch {}

  const reasonsHtml = reasons.length
    ? reasons.map(r => `<div class="rp-reason">${r}</div>`).join('')
    : `<div class="rp-reason clean">✅ No risk factors detected — login matched normal pattern</div>`;

  const factorsHtml = factors.length
    ? factors.map(f => `<span class="rp-chip">✅ ${f.replace(/_/g,' ')}</span>`).join('')
    : `<span class="rp-chip">✅ password</span>`;

  document.getElementById('riskPanelBody').innerHTML = `
    <div class="rp-score-box">
      <div class="rp-score-num ${tier}">${score}</div>
      <div style="font-size:0.72rem;color:#64748b;margin-top:4px;font-weight:600;text-transform:uppercase;letter-spacing:0.1em;">Risk Score / 100</div>
      <div class="rp-bar-track">
        <div class="rp-bar-fill ${tier}" style="width:${score}%"></div>
      </div>
      <span class="badge badge-${tier.toLowerCase()}">${tier}</span>
    </div>

    <div class="rp-label">Login Details</div>
    <div class="rp-grid">
      <div class="rp-cell">
        <div class="rp-cl">Date &amp; Time</div>
        <div class="rp-cv" style="font-size:0.76rem;">${toLocalTime(entry.timestamp)}</div>
      </div>
      <div class="rp-cell">
        <div class="rp-cl">Outcome</div>
        <div class="rp-cv">${entry.outcome || '—'}</div>
      </div>
      <div class="rp-cell">
        <div class="rp-cl">IP Address</div>
        <div class="rp-cv" style="color:#7c3aed;font-size:0.78rem;">${entry.ip || '—'}</div>
      </div>
      <div class="rp-cell">
        <div class="rp-cl">Location</div>
        <div class="rp-cv" style="font-size:0.78rem;">${formatLocation(entry.city, entry.country)}</div>
      </div>
      <div class="rp-cell">
        <div class="rp-cl">ISP / Network</div>
        <div class="rp-cv" style="font-size:0.78rem;">${entry.isp || '—'}</div>
      </div>
      <div class="rp-cell">
        <div class="rp-cl">Auth Method</div>
        <div class="rp-cv" style="font-size:0.78rem;">${authMethod(entry.auth_method)}</div>
      </div>
    </div>

    <div class="rp-label">⚠️ Risk Factors That Triggered</div>
    ${reasonsHtml}

    <div class="rp-label">🔐 Authentication Factors Used</div>
    <div style="padding-bottom:24px;">${factorsHtml}</div>
  `;

  document.getElementById('riskPanel').classList.add('open');
  document.getElementById('riskPanelOverlay').classList.add('open');
}

function closeRiskPanel() {
  document.getElementById('riskPanel').classList.remove('open');
  document.getElementById('riskPanelOverlay').classList.remove('open');
}

// ── TOTP Section (status + backup codes) ─────────────────
async function loadTotpSection() {
  try {
    const r = await fetch('/api/dashboard/overview');
    if (!r.ok) return;
    const d = await r.json();
    const statusBox = document.getElementById('totpStatusBox');
    const setupBtn  = document.getElementById('btn-setup-totp');
    if (statusBox) {
      if (d.totp_enabled) {
        statusBox.className = 'alert alert-success';
        statusBox.textContent = '✅ Authenticator app is enabled on your account.';
        if (setupBtn) setupBtn.textContent = '🔄 Re-setup authenticator app';
      } else {
        statusBox.className = 'alert alert-warning';
        statusBox.textContent = '⚠️ Authenticator app is not set up yet.';
        if (setupBtn) setupBtn.textContent = '📱 Set up authenticator app';
      }
    }
  } catch (e) { console.error('loadTotpSection', e); }
  loadBackupCodes();
}

// ── TOTP Backup Codes ─────────────────────────────────────
async function loadBackupCodes() {
  try {
    const r = await fetch('/api/auth/totp/backup-codes/count');
    if (!r.ok) return;
    const { remaining } = await r.json();
    setText('backup-codes-count', `${remaining} backup code${remaining !== 1 ? 's' : ''} remaining`);
  } catch (e) { console.error('loadBackupCodes', e); }
}

async function generateBackupCodes() {
  if (!confirm('This will invalidate all existing backup codes. Continue?')) return;
  try {
    const r = await fetch('/api/auth/totp/backup-codes/generate', { method: 'POST' });
    const d = await r.json();
    if (!r.ok) { showToast(d.error || 'Failed', 'error'); return; }
    const codes = d.codes || d.backup_codes || [];
    const container = document.getElementById('backup-codes-display');
    if (container) {
      container.innerHTML = `
        <div class="backup-codes-grid">
          ${codes.map(c => `<code class="backup-code">${c}</code>`).join('')}
        </div>
        <p class="backup-codes-note">⚠️ Save these codes now — they will not be shown again.</p>`;
      container.style.display = 'block';
    }
    loadBackupCodes();
    showToast('New backup codes generated', 'success');
  } catch { showToast('Network error', 'error'); }
}

// ── Admin Panel ───────────────────────────────────────────
async function loadAdmin() {
  await Promise.all([loadAdminStats(), loadAdminUsers()]);
}

async function loadAdminStats() {
  try {
    const r = await fetch('/api/dashboard/admin/stats');
    if (r.status === 403) {
      const sec = document.getElementById('sec-admin');
      if (sec) sec.innerHTML = '<p class="error-state">⛔ Access denied — admin only.</p>';
      return;
    }
    const d = await r.json();
    setText('admin-total-users',  d.total_users  ?? '—');
    setText('admin-total-logins', d.total_logins ?? '—');
    setText('admin-totp-users',   d.totp_users   ?? '—');
    setText('admin-locked-users', d.locked_users ?? '—');
    const tiers = d.tier_breakdown || {};
    ['LOW','MEDIUM','HIGH','CRITICAL'].forEach(t => {
      setText(`admin-tier-${t.toLowerCase()}`, tiers[t] ?? 0);
    });
  } catch (e) { console.error('loadAdminStats', e); }
}

async function loadAdminUsers() {
  try {
    const r = await fetch('/api/dashboard/admin/users');
    if (!r.ok) return;
    const { users } = await r.json();
    const tbody = document.querySelector('#tbl-admin-users tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    (users || []).forEach(u => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${u.id}</td>
        <td>${u.username}</td>
        <td>${u.email || '—'}</td>
        <td>${u.totp_enabled ? '✅' : '❌'}</td>
        <td>${u.failed_attempts ?? 0}${u.locked_until ? ` <span class="badge-fail">(locked)</span>` : ''}</td>
        <td>${toLocalTime(u.created_at)}</td>
        <td>${u.login_count ?? 0}</td>`;
      tbody.appendChild(tr);
    });
    if (!users || users.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No users found.</td></tr>';
    }
  } catch (e) { console.error('loadAdminUsers', e); }
}

// ── TOTP Setup ────────────────────────────────────────
async function setupTotp() {
  try {
    const r = await fetch('/api/auth/totp/setup', { method: 'POST' });
    const d = await r.json();
    if (!r.ok) { showToast(d.error || 'Setup failed', 'error'); return; }
    const qrImg        = document.getElementById('totp-qr');
    const secretEl     = document.getElementById('totp-secret');
    const setupSection = document.getElementById('totp-setup-section');
    if (qrImg)        qrImg.src = d.qrDataUrl;
    if (secretEl)     secretEl.textContent = d.secretBase32;
    if (setupSection) setupSection.style.display = 'block';
  } catch { showToast('Network error', 'error'); }
}

async function confirmTotp() {
  const codeEl = document.getElementById('totp-confirm-code');
  const code = codeEl ? codeEl.value.trim() : '';
  if (!code || code.length < 6) { showToast('Enter the 6-digit code', 'error'); return; }
  try {
    const r = await fetch('/api/auth/totp/confirm', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: code })
    });
    const d = await r.json();
    if (!r.ok) { showToast(d.error || 'Invalid code', 'error'); return; }
    showToast('2FA enabled successfully!', 'success');
    const setupSection = document.getElementById('totp-setup-section');
    if (setupSection) setupSection.style.display = 'none';
    const backupCodes = d.backupCodes || d.backup_codes || [];
    if (backupCodes.length) {
      const container = document.getElementById('backup-codes-display');
      if (container) {
        container.innerHTML = `
          <p><strong style="color:#7c3aed;">Your backup codes — save these now:</strong></p>
          <div class="backup-codes-grid">
            ${backupCodes.map(c => `<code class="backup-code">${c}</code>`).join('')}
          </div>
          <p class="backup-codes-note">⚠️ These will not be shown again.</p>`;
        container.style.display = 'block';
      }
    }
    loadBackupCodes();
    setTimeout(() => location.reload(), 2000);
  } catch { showToast('Network error', 'error'); }
}

async function doLogout() {
  try { await fetch('/api/auth/logout', { method: 'POST' }); } catch {}
  window.location.href = '/';
}

// ── Boot ───────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  init();

  document.querySelectorAll('.nav-item[data-section]').forEach(el => {
    el.addEventListener('click', () => showSection(el.dataset.section));
  });

  const btn = (id, fn) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('click', fn);
  };

  btn('btn-export-csv',            exportCSV);
  btn('btn-logout',                doLogout);
  btn('btn-setup-totp',            setupTotp);
  btn('btn-confirm-totp',          confirmTotp);
  btn('btn-generate-backup-codes', generateBackupCodes);
  btn('btn-print-report',          printReport);   // ← Feature #4

  const stayBtn = document.getElementById('btn-stay-logged-in');
  if (stayBtn) stayBtn.addEventListener('click', resetInactivityTimer);

  setInterval(loadRiskGauge, 30000);  // ← Feature #2: auto-refresh gauge every 30s

  showSection('overview');
});