async function doLogin() {
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  const debugIpEl = document.getElementById("debugIp");
  const debugIp   = debugIpEl ? debugIpEl.value.trim() : "";
  const btn       = document.getElementById("loginBtn");
  const msg       = document.getElementById("msg");
  msg.innerHTML   = "";

  if (!username || !password) {
    showMsg("error", "Please enter your username and password.");
    return;
  }

  btn.innerHTML = '<span class="spinner"></span> Signing in…';
  btn.disabled  = true;

  try {
    const url = "/api/auth/login" + (debugIp ? `?debug_ip=${encodeURIComponent(debugIp)}` : "");
    const res  = await fetch(url, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ username, password }),
    });
    const data = await res.json();

    if (res.status === 403) {
      const reasons = (data.reasons || []).map(r => `<li style="margin-bottom:4px;">${r}</li>`).join("");
      msg.innerHTML = `
        <div class="alert alert-error" style="margin-top:14px;flex-direction:column;align-items:flex-start;gap:8px;">
          <strong>🔴 Login Blocked — Critical Risk (Score: ${data.riskScore}/100)</strong>
          <ul style="padding-left:18px;margin:0;line-height:1.8;">${reasons}</ul>
        </div>`;
      return;
    }

    if (!res.ok) {
      showMsg("error", "❌ " + (data.error || "Login failed"));
      return;
    }

    if (data.status === "authenticated") {
      showMsg("success", `✅ Signed in! Risk: ${data.riskScore}/100 (${data.riskTier}). Redirecting…`);
      setTimeout(() => location.href = "/dashboard.html", 900);
      return;
    }

    if (data.status === "challenge_required") {
      sessionStorage.setItem("pendingChallenge", JSON.stringify(data));
      location.href = "/verify.html";
    }

  } catch (e) {
    showMsg("error", "Network error. Is the server running?");
  } finally {
    btn.innerHTML = "Sign In →";
    btn.disabled  = false;
  }
}

function showMsg(type, text) {
  document.getElementById("msg").innerHTML =
    `<div class="alert alert-${type}" style="margin-top:14px;">${text}</div>`;
}

document.addEventListener("keydown", e => {
  if (e.key === "Enter") doLogin();
});