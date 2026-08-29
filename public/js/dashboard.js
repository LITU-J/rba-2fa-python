// ============================================================
//  RBA-2FA Dashboard
// ============================================================

function showSection(name) {
  ["overview", "history", "devices", "totp"].forEach(s => {
    document.getElementById(`sec-${s}`).style.display = s === name ? "block" : "none";
  });
  document.querySelectorAll("button.sidebar-item").forEach((btn, i) => {
    btn.classList.toggle("active", ["overview","history","devices","totp"][i] === name);
  });
  if (name === "history") loadHistory();
  if (name === "devices") loadDevices();
}

function tierBadge(tier) {
  const t = tier || "LOW";
  return `<span class="badge badge-${t}">${t}</span>`;
}

function outcomeBadge(outcome) {
  if (!outcome)             return "—";
  if (outcome === "success") return `<span class="badge badge-success">✅ Success</span>`;
  if (outcome === "blocked") return `<span class="badge badge-CRITICAL">🔴 Blocked</span>`;
  return `<span class="badge badge-failed">❌ Failed</span>`;
}

function authMethod(factors) {
  if (!factors || !factors.length)                                   return "—";
  if (factors.includes("blocked"))                                   return `<span style="color:var(--danger);font-weight:700;">🚫 Blocked</span>`;
  if (factors.includes("sms_otp"))                                   return `<span style="color:#7c3aed;font-weight:600;">🔐 Password + TOTP + SMS</span>`;
  if (factors.includes("totp"))                                      return `<span style="color:#2563eb;font-weight:600;">🔐 Password + TOTP</span>`;
  if (factors.includes("email_otp") || factors.includes("otp_any")) return `<span style="color:#0891b2;font-weight:600;">📧 Password + Email OTP</span>`;
  return `<span style="color:var(--muted);">🔑 Password only</span>`;
}

function formatLocation(city, country) {
  if (!city && !country)                             return `<span style="color:var(--muted);font-size:0.82rem;">🏠 Local Network</span>`;
  if (city === "Local Network" || city === "Unknown") return `<span style="color:var(--muted);font-size:0.82rem;">🏠 ${city}</span>`;
  return [city, country].filter(Boolean).join(", ");
}

function showToast(message, type = "info", duration = 3500) {
  let container = document.getElementById("toastContainer");
  if (!container) {
    container = document.createElement("div");
    container.id = "toastContainer";
    container.style.cssText = "position:fixed;top:80px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:10px;";
    document.body.appendChild(container);
  }
  const icons  = { success:"✅", error:"❌", info:"ℹ️", warning:"⚠️" };
  const colors = {
    success: "background:#f0fdf4;color:#166534;border:1px solid #86efac;",
    error:   "background:#fef2f2;color:#991b1b;border:1px solid #fca5a5;",
    info:    "background:#eff6ff;color:#1d4ed8;border:1px solid #93c5fd;",
    warning: "background:#fffbeb;color:#92400e;border:1px solid #fcd34d;",
  };
  const toast = document.createElement("div");
  toast.style.cssText = `padding:12px 18px;border-radius:12px;font-size:0.88rem;font-weight:600;
    box-shadow:0 8px 32px rgba(0,0,0,0.12);display:flex;align-items:center;gap:10px;
    min-width:260px;max-width:360px;animation:slideInToast 0.3s ease;${colors[type] || colors.info}`;
  toast.innerHTML = `<span>${icons[type] || "ℹ️"}</span><span>${message}</span>`;

  const style = document.createElement("style");
  style.textContent = `@keyframes slideInToast{from{transform:translateX(120%);opacity:0}to{transform:translateX(0);opacity:1}}`;
  if (!document.getElementById("toastStyle")) { style.id="toastStyle"; document.head.appendChild(style); }

  container.appendChild(toast);
  setTimeout(() => { toast.style.opacity="0"; toast.style.transition="opacity 0.3s"; setTimeout(()=>toast.remove(),300); }, duration);
}

// ============================================================
//  INIT
// ============================================================
async function init() {
  const meRes = await fetch("/api/auth/me");
  if (!meRes.ok) { location.href = "/login.html"; return; }
  const { user, lastLogin } = await meRes.json();

  document.getElementById("navUser").textContent     = `👤 ${user.username}`;
  document.getElementById("welcomeName").textContent  = user.username;

  if (lastLogin) {
    document.getElementById("statScore").textContent = lastLogin.risk_score ?? "0";
    document.getElementById("statTier").innerHTML    = tierBadge(lastLogin.risk_tier);
  } else {
    document.getElementById("statScore").textContent = "N/A";
    document.getElementById("statTier").textContent  = "N/A";
  }

  document.getElementById("statTotp").innerHTML = user.totp_enabled
    ? `<span style="color:var(--success);font-size:1.1rem;">✅ On</span>`
    : `<span style="color:var(--danger); font-size:1.1rem;">❌ Off</span>`;

  const dr = await fetch("/api/dashboard/known-devices");
  const dd = await dr.json();
  document.getElementById("statDevices").textContent = dd.devices.length;

  // Location card
  const locCityEl    = document.getElementById("locCity");
  const locDetailsEl = document.getElementById("locDetails");
  if (lastLogin && lastLogin.city && lastLogin.city !== "Local Network" && lastLogin.city !== "Unknown") {
    locCityEl.textContent = `${lastLogin.city}, ${lastLogin.country}`;
    const parts = [];
    if (lastLogin.isp)      parts.push(`ISP: ${lastLogin.isp}`);
    if (lastLogin.timezone) parts.push(`Timezone: ${lastLogin.timezone}`);
    if (lastLogin.ip)       parts.push(`IP: ${lastLogin.ip}`);
    locDetailsEl.textContent = parts.join("   ·   ");
  } else if (lastLogin && lastLogin.city === "Local Network") {
    locCityEl.textContent    = "🏠 Local Network";
    locDetailsEl.textContent = `IP: ${lastLogin.ip || "unknown"} — Private network. Use Simulate IP on login page to test geolocation.`;
  } else {
    locCityEl.textContent    = "No location data yet";
    locDetailsEl.textContent = "Log in using Simulate IP to test geolocation.";
  }

  // TOTP section
  const totpBox = document.getElementById("totpStatusBox");
  if (user.totp_enabled) {
    totpBox.className   = "alert alert-success";
    totpBox.textContent = "✅ Authenticator app is enabled on your account.";
    document.getElementById("setupTotpBtn").textContent = "🔄 Re-enrol authenticator app";
  } else {
    totpBox.className   = "alert alert-warning";
    totpBox.textContent = "⚠️ No authenticator app set up. Email OTP will be used for Medium-risk logins.";
  }

  loadRecentActivity();

  // Session timeout warning — 2 min before 4-hour session expires
  setTimeout(() => {
    const banner = document.createElement("div");
    banner.style.cssText = `position:fixed;bottom:20px;left:50%;transform:translateX(-50%);
      background:#1a3c8f;color:#fff;padding:14px 24px;border-radius:12px;font-size:0.9rem;
      font-weight:600;z-index:9999;box-shadow:0 8px 32px rgba(0,0,0,0.25);
      display:flex;align-items:center;gap:14px;`;
    banner.innerHTML = `
      <span>⏱ Your session expires in 2 minutes.</span>
      <button onclick="location.reload()" style="background:rgba(255,255,255,0.2);border:none;
        color:#fff;padding:6px 14px;border-radius:8px;cursor:pointer;font-weight:700;">
        Stay signed in
      </button>
      <button onclick="this.parentElement.remove()" style="background:none;border:none;
        color:rgba(255,255,255,0.6);cursor:pointer;font-size:1.1rem;">✕</button>`;
    document.body.appendChild(banner);
  }, (4 * 60 - 2) * 60 * 1000);
}

// ============================================================
//  RECENT ACTIVITY (overview tab — 5 rows)
// ============================================================
async function loadRecentActivity() {
  const res   = await fetch("/api/dashboard/history");
  const data  = await res.json();
  const tbody = document.getElementById("recentBody");
  const rows  = data.history.slice(0, 5);

  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:24px;">No login history yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = rows.map(h => `
    <tr>
      <td style="white-space:nowrap;font-size:0.84rem;">${h.timestamp}</td>
      <td>${formatLocation(h.city, h.country)}</td>
      <td>${tierBadge(h.risk_tier)}</td>
      <td>${authMethod(h.required_factors)}</td>
      <td>${outcomeBadge(h.outcome)}</td>
    </tr>
  `).join("");
}

// ============================================================
//  FULL LOGIN HISTORY (history tab — 50 rows + export)
// ============================================================
async function loadHistory() {
  const res   = await fetch("/api/dashboard/history");
  const data  = await res.json();
  const tbody = document.getElementById("historyBody");

  if (!data.history.length) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;color:var(--muted);padding:24px;">No history yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = data.history.map(h => {
    const tl = (h.risk_tier || "low").toLowerCase();
    return `
      <tr>
        <td style="white-space:nowrap;font-size:0.82rem;">${h.timestamp}</td>
        <td style="font-family:monospace;font-size:0.82rem;">${h.ip || "—"}</td>
        <td style="font-size:0.84rem;">${formatLocation(h.city, h.country)}</td>
        <td style="font-size:0.82rem;">${h.isp === "Private Network" ? "🏠 Local" : (h.isp || "—")}</td>
        <td>
          <div style="display:flex;align-items:center;gap:8px;">
            <div class="risk-bar" style="width:64px;">
              <div class="risk-bar-fill ${tl}" style="width:${h.risk_score || 0}%;"></div>
            </div>
            <span style="font-size:0.82rem;font-weight:700;">${h.risk_score ?? "—"}</span>
          </div>
        </td>
        <td>${tierBadge(h.risk_tier)}</td>
        <td>${authMethod(h.required_factors)}</td>
        <td>${outcomeBadge(h.outcome)}</td>
      </tr>`;
  }).join("");

  showToast("Login history loaded", "success");
}

async function exportCSV() {
  const res  = await fetch("/api/dashboard/history");
  const data = await res.json();

  const headers = ["Timestamp","IP Address","City","Country","ISP","Risk Score","Risk Tier","Auth Method","Outcome"];
  const rows    = data.history.map(h => [
    h.timestamp,
    h.ip || "",
    h.city || "",
    h.country || "",
    h.isp || "",
    h.risk_score ?? "",
    h.risk_tier || "",
    (h.required_factors || []).join(" + ") || "password",
    h.outcome || "",
  ]);

  const csvContent = [headers, ...rows]
    .map(row => row.map(v => `"${String(v).replace(/"/g, '""')}"`).join(","))
    .join("\n");

  const blob = new Blob([csvContent], { type: "text/csv" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = `rba2fa_login_history_${new Date().toISOString().split("T")[0]}.csv`;
  a.click();
  URL.revokeObjectURL(url);

  showToast("Login history exported as CSV ✅", "success");
}

// ============================================================
//  KNOWN DEVICES
// ============================================================
async function loadDevices() {
  const res   = await fetch("/api/dashboard/known-devices");
  const data  = await res.json();
  const tbody = document.getElementById("devicesBody");

  if (!data.devices.length) {
    tbody.innerHTML = `<tr><td colspan="3" style="text-align:center;color:var(--muted);padding:24px;">No known devices yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = data.devices.map(d => `
    <tr>
      <td style="font-family:monospace;font-size:0.85rem;">🖥️ ${d.device_hash}</td>
      <td style="font-size:0.85rem;">${d.first_seen}</td>
      <td style="font-size:0.85rem;">${d.last_seen}</td>
    </tr>
  `).join("");

  showToast("Known devices loaded", "info");
}

// ============================================================
//  TOTP SETUP
// ============================================================
async function setupTotp() {
  const res  = await fetch("/api/auth/totp/setup", { method: "POST" });
  const data = await res.json();
  document.getElementById("qrImg").src                  = data.qrDataUrl;
  document.getElementById("qrArea").style.display        = "block";
  document.getElementById("setupTotpBtn").style.display  = "none";
  showToast("QR code generated — scan with your authenticator app", "info");
}

async function confirmTotp() {
  const code = document.getElementById("totpConfirmCode").value.trim();
  const msg  = document.getElementById("totpMsg");

  const res = await fetch("/api/auth/totp/confirm", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ token: code }),
  });

  if (res.ok) {
    msg.innerHTML = `<div class="alert alert-success" style="margin-top:14px;">✅ Authenticator app enabled successfully!</div>`;
    document.getElementById("qrArea").style.display        = "none";
    document.getElementById("setupTotpBtn").style.display  = "block";
    document.getElementById("totpStatusBox").className     = "alert alert-success";
    document.getElementById("totpStatusBox").textContent   = "✅ Authenticator app is enabled on your account.";
    document.getElementById("statTotp").innerHTML =
      `<span style="color:var(--success);font-size:1.1rem;">✅ On</span>`;
    showToast("Authenticator app enabled! 🎉", "success");
  } else {
    const err = await res.json();
    msg.innerHTML = `<div class="alert alert-error" style="margin-top:14px;">❌ ${err.error} — check the code and try again.</div>`;
    showToast("Invalid code — try again", "error");
  }
}

// ============================================================
//  LOGOUT
// ============================================================
async function doLogout() {
  await fetch("/api/auth/logout", { method: "POST" });
  location.href = "/login.html";
}

// ============================================================
//  START
// ============================================================
init();