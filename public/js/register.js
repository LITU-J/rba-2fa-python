async function doRegister() {
  const username   = document.getElementById("username").value.trim();
  const email      = document.getElementById("email").value.trim();
  const password   = document.getElementById("password").value;
  const confirmPwd = document.getElementById("confirmPwd").value;
  const phone      = document.getElementById("phone").value.trim();
  const msg        = document.getElementById("msg");
  msg.innerHTML    = "";

  if (!username || !email || !password) {
    showMsg("error", "Please fill in username, email and password."); return;
  }
  if (password.length < 8) {
    showMsg("error", "Password must be at least 8 characters."); return;
  }
  if (password !== confirmPwd) {
    showMsg("error", "Passwords do not match. Please try again."); return;
  }
  if (!/\S+@\S+\.\S+/.test(email)) {
    showMsg("error", "Please enter a valid email address."); return;
  }

  const btn = document.querySelector("button.btn-primary");
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
      showMsg("error", data.error || "Registration failed"); return;
    }

    showMsg("success", "✅ Account created! Redirecting to your dashboard…");
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

document.addEventListener("keydown", e => {
  if (e.key === "Enter") doRegister();
});