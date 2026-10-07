async function doLogin() {
  const username  = document.getElementById("username").value.trim();
  const password  = document.getElementById("password").value;
  const debugIpEl = document.getElementById("debugIp");
  const debugIp   = debugIpEl ? debugIpEl.value.trim() : "";
  const btn       = document.getElementById("loginBtn");
  const msg       = document.getElementById("msg");
  msg.innerHTML   = "";

  if (!username || !password) {
    showMsg("error", "Please enter your username and password.");
    return;
  }

  btn.innerHTML = '<span class="spinner"></span> Signing in...';
  btn.disabled  = true;

  try {
    const url = "/api/auth/login" +
      (debugIp ? "?debug_ip=" + encodeURIComponent(debugIp) : "");

    const res  = await fetch(url, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ username: username, password: password }),
    });
    const data = await res.json();

    // Lockout with countdown timer
    if (res.status === 403 &&
        data.locked &&
        data.minutes_remaining !== undefined) {

      let totalSeconds = (data.minutes_remaining * 60) +
                          data.seconds_remaining;

      const timerBox = document.createElement("div");
      timerBox.className            = "alert alert-error";
      timerBox.style.marginTop      = "14px";
      timerBox.style.flexDirection  = "column";
      timerBox.style.alignItems     = "flex-start";
      timerBox.style.gap            = "10px";

      timerBox.innerHTML =
        "<strong>Account Temporarily Locked</strong>" +
        "<p style='margin:0;color:inherit;'>" +
          "Too many failed login attempts. " +
          "Your account will automatically unlock in:" +
        "</p>" +
        "<div id='lockoutTimer'" +
             " style='font-size:2rem;font-weight:900;" +
                      "color:#991b1b;text-align:center;" +
                      "width:100%;padding:8px 0;" +
                      "background:rgba(153,27,27,0.08);" +
                      "border-radius:8px;'>" +
          data.minutes_remaining + "m " +
          String(data.seconds_remaining).padStart(2, "0") + "s" +
        "</div>" +
        "<p style='margin:0;color:inherit;font-size:0.85rem;'>" +
          "This lockout protects your account against " +
          "brute-force attacks. Please wait for the timer " +
          "to expire before trying again." +
        "</p>";

      msg.innerHTML = "";
      msg.appendChild(timerBox);

      var interval = setInterval(function() {
        totalSeconds--;
        var el = document.getElementById("lockoutTimer");
        if (!el) { clearInterval(interval); return; }

        if (totalSeconds <= 0) {
          clearInterval(interval);
          el.textContent      = "Account unlocked. You may try again.";
          el.style.color      = "#16a34a";
          el.style.fontSize   = "1rem";
          el.style.fontWeight = "600";
          return;
        }

        var m = Math.floor(totalSeconds / 60);
        var s = totalSeconds % 60;
        el.textContent = m + "m " + (s < 10 ? "0" + s : s) + "s";
      }, 1000);

      return;
    }

    // Other critical block — impossible travel etc
    if (res.status === 403) {
      var reasons = "";
      if (data.reasons && data.reasons.length > 0) {
        for (var i = 0; i < data.reasons.length; i++) {
          reasons += "<li style='margin-bottom:4px;'>" +
                     data.reasons[i] + "</li>";
        }
      }
      msg.innerHTML =
        "<div class='alert alert-error'" +
             " style='margin-top:14px;flex-direction:column;" +
                      "align-items:flex-start;gap:8px;'>" +
          "<strong>Login Blocked — Critical Risk " +
          "(Score: " + data.riskScore + "/100)</strong>" +
          "<p style='margin:0;color:inherit;'>" +
            "This login was blocked due to the following " +
            "risk indicators:" +
          "</p>" +
          "<ul style='padding-left:18px;margin:0;line-height:1.8;'>" +
            reasons +
          "</ul>" +
        "</div>";
      return;
    }

    // Other errors
    if (!res.ok) {
      showMsg("error", data.error || "Login failed");
      return;
    }

    // Successful low risk login
    if (data.status === "authenticated") {
      showMsg("success",
        "Signed in successfully! " +
        "Risk: " + data.riskScore + "/100 (" + data.riskTier + "). " +
        "Redirecting...");
      setTimeout(function() {
        location.href = "/dashboard.html";
      }, 900);
      return;
    }

    // OTP challenge required
    if (data.status === "challenge_required") {
      sessionStorage.setItem("pendingChallenge", JSON.stringify(data));
      location.href = "/verify.html";
    }

  } catch (e) {
    showMsg("error", "Network error. Please check your connection.");
  } finally {
    btn.innerHTML = "Sign In";
    btn.disabled  = false;
  }
}

function showMsg(type, text) {
  document.getElementById("msg").innerHTML =
    "<div class='alert alert-" + type + "' " +
         "style='margin-top:14px;'>" +
      text +
    "</div>";
}

document.addEventListener("keydown", function(e) {
  if (e.key === "Enter") doLogin();
});