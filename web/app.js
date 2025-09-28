const els = {
  authSection: document.getElementById("auth-section"),
  meSection: document.getElementById("me-section"),
  meJson: document.getElementById("me-json"),
  adminPanel: document.getElementById("admin-panel"),
  usersTableBody: document.querySelector("#users-table tbody"),
  registerForm: document.getElementById("register-form"),
  loginForm: document.getElementById("login-form"),
  logoutBtn: document.getElementById("logout-btn"),
  loadUsersBtn: document.getElementById("load-users-btn"),
  toast: document.getElementById("toast-container"),
};

const LIMITS = {
  usernameMin: 3,
  usernameMax: 32,
  passwordMin: 8,
  passwordMax: 32,
};

function getToken() { return localStorage.getItem("token") || ""; }
function setToken(t) { t ? localStorage.setItem("token", t) : localStorage.removeItem("token"); }
function authHeader() { const t = getToken(); return t ? { Authorization: `Bearer ${t}` } : {}; }

function showToast({ title = "", msg = "", ok = false, err = false, timeout = 3000 } = {}) {
  const el = document.createElement("div");
  el.className = `toast${ok ? " ok" : ""}${err ? " err" : ""}`;
  el.innerHTML = `<div class="toast-title">${title}</div><div class="toast-msg">${msg}</div>`;
  els.toast.appendChild(el);
  const t = setTimeout(() => {
    el.remove();
  }, timeout);
  el.addEventListener("click", () => { clearTimeout(t); el.remove(); });
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}), ...authHeader() }
  });
  let data = {};
  try { data = await res.json(); } catch { data = {}; }
  if (!res.ok) {
    const msg = data.error || res.statusText || "Request failed";
    throw new Error(msg);
  }
  return data;
}

/* ---------- Field errors helpers ----------- */
function setFieldError(inputId, message) {
  const small = document.querySelector(`[data-error-for="${inputId}"]`);
  if (small) small.textContent = message || "";
}
function clearFieldErrors(formEl) {
  if (!formEl) return;
  formEl.querySelectorAll(".error").forEach(s => s.textContent = "");
  const formError = formEl.querySelector('[data-form-error]');
  if (formError) formError.textContent = "";
}
function setFormError(formName, message) {
  const el = document.querySelector(`[data-form-error="${formName}"]`);
  if (el) el.textContent = message || "";
}

/* ---------- UI state ----------- */
function setUILoggedIn(me) {
  els.authSection.classList.add("hidden");
  els.meSection.classList.remove("hidden");
  els.meJson.textContent = JSON.stringify(me, null, 2);
  if (me.role === "admin") els.adminPanel.classList.remove("hidden");
  else els.adminPanel.classList.add("hidden");
}

function setUILoggedOut() {
  els.authSection.classList.remove("hidden");
  els.meSection.classList.add("hidden");
  els.adminPanel.classList.add("hidden");
  els.meJson.textContent = "";
  // почистимо таблицю адміна
  if (els.usersTableBody) els.usersTableBody.innerHTML = "";
  // почистимо помилки форм
  clearFieldErrors(els.registerForm);
  clearFieldErrors(els.loginForm);
}

/* ---------- Validators ----------- */
function validateUsername(u) {
  if (!u) return `Введіть username`;
  if (u.length < LIMITS.usernameMin || u.length > LIMITS.usernameMax) {
    return `Довжина ${LIMITS.usernameMin}–${LIMITS.usernameMax} символів`;
  }
  return "";
}
function validatePassword(p) {
  if (!p) return `Введіть пароль`;
  if (p.length < LIMITS.passwordMin || p.length > LIMITS.passwordMax) {
    return `Довжина ${LIMITS.passwordMin}–${LIMITS.passwordMax} символів`;
  }
  return "";
}

/* ---------- Actions ----------- */
async function fetchMe() {
  try {
    const { me } = await api("/me");
    setUILoggedIn(me);
  } catch {
    setUILoggedOut();
  }
}

/* Registration */
els.registerForm?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.currentTarget;
  clearFieldErrors(form);

  const username = document.getElementById("reg-username")?.value.trim();
  const password = document.getElementById("reg-password")?.value;

  let hasError = false;
  const uErr = validateUsername(username);
  if (uErr) { setFieldError("reg-username", uErr); hasError = true; }
  const pErr = validatePassword(password);
  if (pErr) { setFieldError("reg-password", pErr); hasError = true; }
  if (hasError) return;

  try {
    await api("/users/register", {
      method: "POST",
      body: JSON.stringify({ username, password })
    });

    // Успіх: покажемо тост і логічно очистимо/заповнимо форми
    showToast({ title: "Реєстрація успішна", msg: "Можете увійти під своїм логіном.", ok: true });
    // безпечно очистимо форму
    form?.reset();
    clearFieldErrors(form);

    // автозаповнення логін-форми
    const loginUserEl = document.getElementById("login-username");
    if (loginUserEl) {
      loginUserEl.value = username;
      const loginPassEl = document.getElementById("login-password");
      if (loginPassEl) {
        loginPassEl.value = "";
        loginPassEl.focus();
      }
    }
  } catch (err) {
    // помилка від бекенду: наприклад Username already taken
    setFormError("register", err.message || "Не вдалося зареєструватися");
    showToast({ title: "Помилка реєстрації", msg: err.message, err: true });
  }
});

/* Login */
els.loginForm?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.currentTarget;
  clearFieldErrors(form);

  const username = document.getElementById("login-username")?.value.trim();
  const password = document.getElementById("login-password")?.value;

  let hasError = false;
  const uErr = validateUsername(username);
  if (uErr) { setFieldError("login-username", uErr); hasError = true; }
  const pErr = validatePassword(password);
  if (pErr) { setFieldError("login-password", pErr); hasError = true; }
  if (hasError) return;

  try {
    const { token } = await api("/users/login", {
      method: "POST",
      body: JSON.stringify({ username, password })
    });
    setToken(token);
    // очищення полів логіну після успіху
    form?.reset();
    clearFieldErrors(form);

    await fetchMe();
    showToast({ title: "Вхід виконано", msg: `Ласкаво просимо, ${username}!`, ok: true });
  } catch (err) {
    setFormError("login", err.message || "Помилка входу");
    showToast({ title: "Помилка входу", msg: err.message, err: true });
  }
});

/* Logout */
els.logoutBtn?.addEventListener("click", () => {
  setToken("");
  setUILoggedOut();
  showToast({ title: "Вихід виконано", msg: "Сесію завершено.", ok: true });
});

/* Admin load users */
els.loadUsersBtn?.addEventListener("click", async () => {
  try {
    const { users } = await api("/admin/users");
    els.usersTableBody.innerHTML = users
      .map((u, i) =>
        `<tr><td>${i + 1}</td><td>${u.username}</td><td>${u.role}</td><td>${new Date(u.created_at).toLocaleString()}</td></tr>`
      )
      .join("");
    showToast({ title: "Готово", msg: `Завантажено користувачів: ${users.length}`, ok: true });
  } catch (err) {
    showToast({ title: "Помилка завантаження", msg: err.message, err: true });
  }
});

/* Live validation UX (необов'язково, але приємно) */
["reg-username","login-username"].forEach(id => {
  const el = document.getElementById(id);
  el?.addEventListener("input", () => {
    const v = el.value.trim();
    const msg = validateUsername(v);
    setFieldError(id, msg);
  });
});
["reg-password","login-password"].forEach(id => {
  const el = document.getElementById(id);
  el?.addEventListener("input", () => {
    const v = el.value;
    const msg = validatePassword(v);
    setFieldError(id, msg);
  });
});

document.addEventListener("DOMContentLoaded", fetchMe);