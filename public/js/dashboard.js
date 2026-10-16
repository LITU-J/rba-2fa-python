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
  const map = {
    LOW:      'badge-low',
    MEDIUM:   'badge-medium',
    HIGH:     'badge-high',
    CRITICAL: 'badge-critical'
  };
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

  if (name === 'overview') { loadRecentActivity(); loadRiskTrend(); }
  if (name === 'history')  loadHistory(1);
  if (name === 'devices')  loadDevices();
  if (name === 'sessions') loadSessions();
  if (name === 'totp')     loadBackupCodes();
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
    if (!r.ok) return;
    const d = await r.json();
    const last = d.last_login || {};

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
    if (r.status === 401) { window.location.href = '/login'; return; }
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
        <td>${e.risk_score ?? '—'}</td>`;
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
          backgroundColor: 'rgba(139,92,246,0.15)',
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
          legend: { labels: { color: '#c4b5fd' } },
          tooltip: {
            callbacks: {
              afterLabel: ctx => `Tier: ${(trend[ctx.dataIndex] || {}).risk_tier || ''}`
            }
          }
        },
        scales: {
          x: { ticks: { color: '#a78bfa' }, grid: { color: 'rgba(167,139,250,0.1)' } },
          y: { min: 0, max: 100, ticks: { color: '#a78bfa' }, grid: { color: 'rgba(167,139,250,0.1)' } }
        }
      }
    });
  } catch (e) { console.error('loadRiskTrend', e); }
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
    const codes = d.backup_codes || [];
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

// ── TOTP Setup ────────────────────────────────────────────
async function setupTotp() {
  try {
    const r = await fetch('/api/auth/totp/setup', { method: 'POST' });
    const d = await r.json();
    if (!r.ok) { showToast(d.error || 'Setup failed', 'error'); return; }
    const qrImg = document.getElementById('totp-qr');
    const secretEl = document.getElementById('totp-secret');
    const setupSection = document.getElementById('totp-setup-section');
    if (qrImg) qrImg.src = d.qr_code;
    if (secretEl) secretEl.textContent = d.secret;
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
      body: JSON.stringify({ code })
    });
    const d = await r.json();
    if (!r.ok) { showToast(d.error || 'Invalid code', 'error'); return; }
    showToast('2FA enabled successfully!', 'success');
    const setupSection = document.getElementById('totp-setup-section');
    if (setupSection) setupSection.style.display = 'none';
    if (d.backup_codes && d.backup_codes.length) {
      const container = document.getElementById('backup-codes-display');
      if (container) {
        container.innerHTML = `
          <p><strong style="color:#c4b5fd;">Your backup codes — save these now:</strong></p>
          <div class="backup-codes-grid">
            ${d.backup_codes.map(c => `<code class="backup-code">${c}</code>`).join('')}
          </div>
          <p class="backup-codes-note">⚠️ These will not be shown again.</p>`;
        container.style.display = 'block';
      }
    }
    loadBackupCodes();
    setTimeout(() => location.reload(), 2000);
  } catch { showToast('Network error', 'error'); }
}

// ── Logout ────────────────────────────────────────────────
async function doLogout() {
  try { await fetch('/api/auth/logout', { method: 'POST' }); } catch {}
  window.location.href = '/';
}

// ── DOMContentLoaded ──────────────────────────────────────
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

  const stayBtn = document.getElementById('btn-stay-logged-in');
  if (stayBtn) stayBtn.addEventListener('click', resetInactivityTimer);

  showSection('overview');
});