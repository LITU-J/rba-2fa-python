const pending = JSON.parse(
  sessionStorage.getItem("pendingChallenge") || "null"
);
if (!pending) location.href = "/login.html";

// Populate risk card
const tierMap = {
  LOW: "low", MEDIUM: "medium", HIGH: "high", CRITICAL: "critical"
};
document.getElementById("tierBadge").className =
  `badge badge-${pending.riskTier}`;
document.getElementById("tierBadge").textContent = pending.riskTier;
document.getElementById("scoreVal").textContent  = pending.riskScore;

const fill = document.getElementById("riskBarFill");
fill.style.width = pending.riskScore + "%";
fill.className   =
  `risk-bar-fill ${tierMap[pending.riskTier] || "medium"}`;

(pending.reasons || []).forEach(r => {
  const li       = document.createElement("li");
  li.textContent = r;
  document.getElementById("reasonsList").appendChild(li);
});

// Show detected location
if (pending.location && pending.location !== "Unknown location") {
  document.getElementById("locationText").textContent =
    pending.location;
  document.getElementById("locationPill").style.display = "block";
}

// Show correct OTP input fields
const required = pending.requiredFactors || [];

if ((required.includes("totp") || required.includes("otp_any"))
    && pending.totpAvailable) {
  document.getElementById("totpField").style.display = "block";
}
if (required.includes("otp_any") || required.includes("email_otp")) {
  document.getElementById("emailField").style.display = "block";
}
if (required.includes("sms_otp")) {
  document.getElementById("smsField").style.display = "block";
}

// OTP codes are NEVER shown on this page
// They are delivered exclusively to the user's registered
// email address or phone number

async function doVerify() {
  const body = { pendingToken: pending.pendingToken };
  const tc   = document.getElementById("totpCode");
  const ec   = document.getElementById("emailOtp");
  const sc   = document.getElementById("smsOtp");

  if (tc && tc.value.trim()) body.totpCode = tc.value.trim();
  if (ec && ec.value.trim()) body.emailOtp = ec.value.trim();
  if (sc && sc.value.trim()) body.smsOtp   = sc.value.trim();

  const btn = document.querySelector("button.btn-primary");
  btn.innerHTML = '<span class="spinner"></span> Verifying…';
  btn.disabled  = true;

  try {
    const res  = await fetch("/api/auth/verify", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(body),
    });
    const data = await res.json();
    const msg  = document.getElementById("msg");

    if (!res.ok) {
      msg.innerHTML = `
        <div class="alert alert-error" style="margin-top:14px;">
          ❌ ${data.error}
          ${data.missing
            ? `<br/><small>Missing: ${data.missing.join(", ")}</small>`
            : ""}
        </div>`;
      return;
    }

    msg.innerHTML = `
      <div class="alert alert-success" style="margin-top:14px;">
        ✅ Identity verified! Signing you in…
      </div>`;
    sessionStorage.removeItem("pendingChallenge");
    setTimeout(() => location.href = "/dashboard.html", 700);

  } catch (e) {
    document.getElementById("msg").innerHTML = `
      <div class="alert alert-error" style="margin-top:14px;">
        ❌ Network error. Please try again.
      </div>`;
  } finally {
    btn.innerHTML = "Verify & Sign In →";
    btn.disabled  = false;
  }
}

document.addEventListener("keydown", e => {
  if (e.key === "Enter") doVerify();
});