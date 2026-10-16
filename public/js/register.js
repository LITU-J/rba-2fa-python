async function doRegister() {
  const username   = document.getElementById("username").value.trim();
  const email      = document.getElementById("email").value.trim();
  const password   = document.getElementById("password").value;
  const confirmPwd = document.getElementById("confirmPwd").value;
  const phone      = document.getElementById("phone").value.trim();
  const msg        = document.getElementById("msg");
  msg.innerHTML    = "";

  const SPECIAL = "!@#$%^&*()_+-=[]{}|;':\",./<>?";

  if (!username || !email || !password) {
    showMsg("error", "Please fill in username, email and password.");
    return;
  }
  if (!/\S+@\S+\.\S+/.test(email)) {
    showMsg("error", "Please enter a valid email address.");
    return;
  }
  if (password.length < 8) {
    showMsg("error", "Password must be at least 8 characters.");
    return;
  }
  if (!/[A-Z]/.test(password)) {
    showMsg("error", "Password must contain at least one uppercase letter.");
    return;
  }
  if (!/[0-9]/.test(password)) {
    showMsg("error", "Password must contain at least one number.");
    return;
  }
  if (!password.split("").some(c => SPECIAL.includes(c))) {
    showMsg("error", "Password must contain at least one special character e.g. !@#$%^&*");
    return;
  }
  if (password !== confirmPwd) {
    showMsg("error", "Passwords do not match. Please try again.");
    return;
  }

  const btn = document.getElementById("registerBtn");
  btn.innerHTML = '<span class="spinner"></span> Creating account…';
  btn.disabled  = true;

  try {
    const res  = await fetch("/api/auth/register", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ username, email, password, phone }),
    });
    const data = await res.json();

    if (!res.ok) {
      showMsg("error", data.error || "Registration failed");
      return;
    }

    showMsg("success", "Account created successfully! Redirecting…");
    setTimeout(() => location.href = "/dashboard.html", 1000);

  } catch (e) {
    showMsg("error", "Network error. Please try again.");
  } finally {
    btn.innerHTML = "Create Account →";
    btn.disabled  = false;
  }
}

function showMsg(type, text) {
  document.getElementById("msg").innerHTML =
    `<div class="alert alert-${type}" style="margin-top:14px;">${text}</div>`;
}

// Wire up button click AND prevent any form submit
document.addEventListener("DOMContentLoaded", function() {
  var btn = document.querySelector("button.btn-primary");
  if (btn) {
    btn.addEventListener("click", function(e) {
      e.preventDefault();
      doRegister();
    });
  }
  var form = document.querySelector("form");
  if (form) {
    form.addEventListener("submit", function(e) {
      e.preventDefault();
      doRegister();
    });
  }
});

document.addEventListener("keydown", e => {
  if (e.key === "Enter") doRegister();
});