// =========================
// CONFIG
// =========================
const API_BASE = "http://127.0.0.1:8000";

// =========================
// Referencias HTML
// =========================
const landing = document.getElementById("landing");
const dashboardApp = document.getElementById("dashboardApp");

const btnEnter = document.getElementById("btnEnter");
const btnSignup = document.getElementById("btnSignup");
const btnAbout = document.getElementById("btnAbout");
const aboutBox = document.getElementById("aboutBox");

/* ===== Modal Crear Cuenta ===== */

const signupBackdrop = document.getElementById("signupBackdrop");
const btnCloseSignup = document.getElementById("btnCloseSignup");
const btnCreateAccount = document.getElementById("btnCreateAccount");
const signupTitle = document.getElementById("signupTitle");
const signupHint = document.getElementById("suHint");

const stepForm = document.getElementById("signupStepForm");
const stepOtp = document.getElementById("signupStepOtp");

const suFirstName = document.getElementById("suFirstName");
const suLastName = document.getElementById("suLastName");
const suEmail = document.getElementById("suEmail");
const suPassword = document.getElementById("suPassword");
const suPassword2 = document.getElementById("suPassword2");
const suTerms = document.getElementById("suTerms");

const suOtp = document.getElementById("suOtp");
const btnVerifyOtp = document.getElementById("btnVerifyOtp");
const otpHint = document.getElementById("otpHint");

/* ===== Modal Acceder (Login) ===== */
const loginBackdrop = document.getElementById("loginBackdrop");
const btnCloseLogin = document.getElementById("btnCloseLogin");
const loginForm = document.getElementById("loginForm");
const liEmail = document.getElementById("liEmail");
const liPassword = document.getElementById("liPassword");
const liRemember = document.getElementById("liRemember");
const btnTogglePwd = document.getElementById("btnTogglePwd");
const btnGoSignup = document.getElementById("btnGoSignup");
const loginOtpBackdrop = document.getElementById("loginOtpBackdrop");
const btnCloseLoginOtp = document.getElementById("btnCloseLoginOtp");
const loginOtpForm = document.getElementById("loginOtpForm");
const liOtp = document.getElementById("liOtp");

/* ===== Dashboard ===== */
const listEl = document.getElementById("list");
const detailEl = document.getElementById("detail");
const searchEl = document.getElementById("search");
const btnRefresh = document.getElementById("btnRefresh");

const modalBackdrop = document.getElementById("modalBackdrop");
const btnCompose = document.getElementById("btnCompose");
const btnCloseModal = document.getElementById("btnCloseModal");
const btnSendAction = document.getElementById("btnSendAction");

const actionTypeEl = document.getElementById("actionType");
const actionDescEl = document.getElementById("actionDesc");

const navItems = document.querySelectorAll(".nav-item");

// =========================
// Estado
// =========================
const STORAGE_KEY = "cryptolock_items_v1";

const state = {
  view: "inbox",
  query: "",
  selectedId: null,
  items: []
};

let pendingEmail = "";
let pendingLoginIdentifier = "";

// =========================
// Helpers UI
// =========================
function show(el) {
  if (el) el.classList.remove("hidden");
}
function hide(el) {
  if (el) el.classList.add("hidden");
}

function open_signup() {
  show(signupBackdrop);
  reset_signup_modal();
}

function open_login() {
  show(loginBackdrop);
  setTimeout(() => liEmail?.focus(), 0);
}

function close_login() {
  hide(loginBackdrop);
}

function open_login_otp(identifier) {
  pendingLoginIdentifier = identifier;
  if (liOtp) liOtp.value = "";
  hide(loginBackdrop);
  show(loginOtpBackdrop);
  setTimeout(() => liOtp?.focus(), 0);
}

function close_login_otp() {
  hide(loginOtpBackdrop);
}

function close_signup() {
  hide(signupBackdrop);
}

function set_signup_hint(message, isError = false) {
  if (!signupHint) return;
  signupHint.textContent = message;
  signupHint.classList.toggle("is-error", Boolean(isError));
}

function show_signup_error(message) {
  set_signup_hint(message, true);
  toast(message);
}
 
function reset_signup_modal() {
  pendingEmail = "";
  signupTitle.textContent = "Crear una cuenta";
  set_signup_hint("El correo debe terminar en @gmail.com.");
  otpHint.textContent = "";

  show(stepForm);
  hide(stepOtp);
  show(btnCreateAccount);
  hide(btnVerifyOtp);

  suOtp.value = "";
}

function show_otp_step(email) {
  pendingEmail = email;
  signupTitle.textContent = "Verificar correo";
  hide(stepForm);
  show(stepOtp);
  hide(btnCreateAccount);
  show(btnVerifyOtp);
  otpHint.textContent = "Revisa tu correo y pega aquí el código OTP.";
}

function is_gmail(email) {
  return String(email || "").toLowerCase().endsWith("@gmail.com");
}

function looks_like_gamil_typo(email) {
  return String(email || "").toLowerCase().endsWith("@gamil.com");
}

// =========================
// Toast
// =========================
let toastTimer = null;
function toast(msg) {
  const el = document.getElementById("toast");
  if (!el) return;

  el.textContent = msg;
  el.classList.add("show");

  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.classList.remove("show");
  }, 1800);
}


  async function api_json(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.detail || `Error HTTP ${res.status}`);
  return data;
}

function short_hash(value = "") {
  return String(value).slice(0, 12) + "...";
}

function fmt_ts(value = "") {
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}


// =========================
// Crear cuenta (Paso 1)
// =========================
async function handle_create_account() {
  try {
    set_signup_hint("Validando datos...");

    const first = suFirstName.value.trim();
    const last = suLastName.value.trim();
    const email = suEmail.value.trim().toLowerCase();
    const p1 = suPassword.value;
    const p2 = suPassword2.value;
    const okTerms = suTerms.checked;

    if (!first || !last) return show_signup_error("Completa nombres y apellidos");
    if (!email) return show_signup_error("Ingresa tu correo");
    if (looks_like_gamil_typo(email)) return show_signup_error("Parece que escribiste @gamil.com. Debe ser @gmail.com");
    if (!is_gmail(email)) return show_signup_error("El correo debe terminar en @gmail.com");
    if (p1.length < 8) return show_signup_error("Contraseña mínima: 8 caracteres");
    if (p1 !== p2) return show_signup_error("Las contraseñas no coinciden");
    if (!okTerms) return show_signup_error("Acepta los términos");

    btnCreateAccount.disabled = true;
    btnCreateAccount.textContent = "Creando...";

    const res = await fetch(`${API_BASE}/users/human`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email,
        nombre: `${first} ${last}`,
        telefono: "",
        mfaHabilitado: false,
        password: p1
      }),
    });

    const data = await res.json();

    if (!res.ok) return show_signup_error(data?.detail || "Error creando usuario");

// ✅ OTP real: no viene en la respuesta. Solo pasamos a paso 2.
    show_otp_step(email);
        if (data?.emailSent === false) {
          otpHint.textContent = data?.otpDebug
            ? `No se pudo enviar correo. OTP de prueba: ${data.otpDebug}`
            : "No se pudo enviar correo. Solicita soporte para configurar SMTP.";
        }

        toast(data?.message || "Te enviamos un OTP a tu correo 📩");


  } catch (err) {
    console.error(err);
    const msg = err instanceof TypeError
      ? `No se pudo conectar con el backend (${API_BASE}). Verifica que esté encendido y con CORS habilitado.`
      : "Error de red o servidor";
    show_signup_error(msg);
  } finally {
    btnCreateAccount.disabled = false;
    btnCreateAccount.textContent = "Crear cuenta";
  }
}

// =========================
// Verificar OTP (Paso 2)
// =========================
async function handle_verify_otp() {
  try {
    const otp = suOtp.value.trim();
    if (!pendingEmail) return toast("No hay correo pendiente");
    if (!otp) return toast("Ingresa el OTP");

    btnVerifyOtp.disabled = true;
    btnVerifyOtp.textContent = "Verificando...";

    const res = await fetch(`${API_BASE}/users/verify-email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: pendingEmail, otp }),
    });

    const data = await res.json();

    if (!res.ok) return toast(data?.detail || "OTP inválido");

    toast("Cuenta activada ✅");
    close_signup();

  } catch (err) {
    console.error(err);
    toast("Error de red");
  } finally {
    btnVerifyOtp.disabled = false;
    btnVerifyOtp.textContent = "Verificar";
  }
}

// Dashboard
// =========================
function default_items() {
  const now = new Date().toISOString();
  return [
    {
      id: "INB-1",
      view: "inbox",
      title: "Login verificado",
      subtitle: "OTP",
      status: "OK",
      createdAt: now,
      body: "Acceso verificado."
    }
  ];
}

function normalize_block_to_item(block) {
  const datos = block?.datos || {};
  return {
    id: `BLK-${block.indice}`,
    view: "ledger",
    title: `${datos.accion || "GENESIS"} #${block.indice}`,
    subtitle: datos.usuarioId || datos.mensaje || "Sistema",
    status: "OK",
    createdAt: block.timestamp,
    body: JSON.stringify(block, null, 2),
    raw: block,
  };
}
function load_items() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : default_items();
  } catch {
    return default_items();
  }
}

function save_items(items) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(items));
}


function current_items() {
  const q = state.query.trim().toLowerCase();
  const byView = state.items.filter(i => i.view === state.view);
  if (!q) return byView;
  return byView.filter(i => `${i.title} ${i.subtitle} ${i.body}`.toLowerCase().includes(q));
}

function render_detail(item) {
  if (!detailEl) return;
  if (!item) {
    detailEl.innerHTML = `
      <div class="detail-empty">
        <div class="big">📩</div>
        <h2>Selecciona un evento</h2>
        <p>Haz click en un elemento de la lista para ver el detalle.</p>
      </div>
    `;
    return;
  }

  if (item.view === "ledger" && item.raw) {
    detailEl.innerHTML = `
      <div class="detail-card">
        <h2>Bloque #${item.raw.indice}</h2>
        <p><b>Hash:</b> <code>${item.raw.hash}</code></p>
        <p><b>Hash anterior:</b> <code>${item.raw.hash_anterior}</code></p>
        <p><b>Nonce:</b> ${item.raw.nonce} | <b>Dificultad:</b> ${item.raw.dificultad}</p>
        <p><b>Fecha:</b> ${fmt_ts(item.raw.timestamp)}</p>
        <pre>${JSON.stringify(item.raw.datos, null, 2)}</pre>
      </div>
    `;
    return;
  }

  detailEl.innerHTML = `
    <div class="detail-card">
      <h2>${item.title}</h2>
      <p><b>Estado:</b> ${item.status}</p>
      <p><b>Fecha:</b> ${fmt_ts(item.createdAt)}</p>
      <pre>${item.body}</pre>
    </div>
  `;
}

function render() {
  if (!listEl) return;
  const rows = current_items();
  listEl.innerHTML = rows.map(i => `
    <button class="list-item" data-id="${i.id}">
      <b>${i.title}</b><br />
      <small>${i.subtitle || ""}</small>
      <small>${fmt_ts(i.createdAt)}</small>
    </button>
  `).join("");

  const selected = rows.find(i => i.id === state.selectedId) || rows[0] || null;
  state.selectedId = selected?.id || null;
  render_detail(selected);
}

async function refresh_blockchain_panel() {
  try {
    const [status, chain] = await Promise.all([
      api_json('/audit/status'),
      api_json('/audit/chain')
    ]);

    const ledgerBlocks = (chain?.cadena || []).map(normalize_block_to_item);
    state.items = [
      ...state.items.filter(i => i.view !== 'ledger'),
      ...ledgerBlocks,
    ];
    save_items(state.items);

    if (detailEl && state.view === 'ledger') {
      detailEl.innerHTML = `
        <div class="detail-card">
          <h2>Estado blockchain</h2>
          <p><b>Válida:</b> ${status.valida ? 'Sí ✅' : 'No ❌'}</p>
          <p><b>Longitud:</b> ${status.longitud}</p>
          <p><b>Dificultad:</b> ${status.dificultad}</p>
          <p><b>Último hash:</b> <code>${ledgerBlocks.length ? short_hash(ledgerBlocks[ledgerBlocks.length - 1].raw.hash) : '-'}</code></p>
        </div>
      `;
    }

    return status;
  } catch (err) {
    console.error(err);
    toast(`No se pudo cargar auditoría blockchain: ${err.message}`);
    throw err;
  }
}

async function go_to_dashboard() {
  hide(landing);
  show(dashboardApp);
  state.view = 'ledger';
  navItems.forEach(n => n.classList.toggle('active', n.dataset.view === state.view));
  await refresh_blockchain_panel().catch(() => {});
  render();
}

function go_to_landing() {
  show(landing);
  hide(dashboardApp);
}

function preload_login_identifier() {
  const saved = localStorage.getItem("cryptolock_last_login");
  if (saved && liEmail) {
    liEmail.value = saved;
    if (liRemember) liRemember.checked = true;
  }
}

// =========================
// Listeners
// =========================
btnSignup?.addEventListener("click", open_signup);
btnCloseSignup?.addEventListener("click", close_signup);
signupBackdrop?.addEventListener("click", e => e.target === signupBackdrop && close_signup());

btnCreateAccount?.addEventListener("click", handle_create_account);
btnVerifyOtp?.addEventListener("click", handle_verify_otp);

btnEnter?.addEventListener("click", open_login);


btnAbout?.addEventListener("click", () => {
  if (aboutBox) aboutBox.classList.toggle("hidden");
});
btnCloseLogin?.addEventListener("click", close_login);
btnCloseLoginOtp?.addEventListener("click", close_login_otp);
loginBackdrop?.addEventListener("click", e => e.target === loginBackdrop && close_login());
loginOtpBackdrop?.addEventListener("click", e => e.target === loginOtpBackdrop && close_login_otp());

btnTogglePwd?.addEventListener("click", () => {
  const isPwd = liPassword.type === "password";
  liPassword.type = isPwd ? "text" : "password";
  btnTogglePwd.textContent = isPwd ? "Ocultar" : "Mostrar";
});

function valid_login_identifier(value) {
  const v = String(value || "").trim();
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const phoneRegex = /^\+?\d{7,15}$/;
  return emailRegex.test(v) || phoneRegex.test(v.replace(/[\s()-]/g, ""));
}

// Submit (paso 1): validar y pedir OTP
loginForm?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const identifier = liEmail?.value?.trim() || "";
  const pwd = liPassword?.value || "";

  if (!identifier) return toast("Ingresa tu correo o teléfono");
  if (!valid_login_identifier(identifier)) return toast("Formato inválido: usa correo o teléfono");
  if (!pwd) return toast("Ingresa tu contraseña");

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(identifier)) {
    return toast("Por ahora el login OTP solo admite correo electrónico");
  }

  if (liRemember?.checked) {
    localStorage.setItem("cryptolock_last_login", identifier);
  } else {
    localStorage.removeItem("cryptolock_last_login");
  }

  const submitBtn = loginForm.querySelector('button[type="submit"]');
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = "Enviando OTP...";
  }

  try {
    const res = await fetch(`${API_BASE}/auth/login/request-otp`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: identifier.toLowerCase(), password: pwd }),
    });

    const data = await res.json();
    if (!res.ok) {
      return toast(data?.detail || "No se pudo enviar el OTP");
    }

    if (data?.emailSent === false) {
      const debugOtp = data?.otpDebug ? ` OTP de prueba: ${data.otpDebug}` : "";
      toast(`${data?.message || "No se pudo enviar el correo OTP."}${debugOtp}`);
    } else {
      toast(data?.message || "OTP enviado. Revisa tu correo 📩");
    }

    open_login_otp(identifier.toLowerCase());
  } catch (err) {
    console.error(err);
    toast(`No se pudo conectar con el backend (${API_BASE})`);
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = "Ingresar";
    }
  }
});

// Submit OTP (paso 2)
loginOtpForm?.addEventListener("submit", async (e) => {
  e.preventDefault();

  const otp = String(liOtp?.value || "").trim();
  if (!pendingLoginIdentifier) return toast("No hay inicio de sesión pendiente");
  if (!/^\d{6}$/.test(otp)) return toast("Ingresa un OTP de 6 dígitos");


  const submitBtn = loginOtpForm.querySelector('button[type="submit"]');
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.textContent = "Verificando...";
  }

  try {
    const res = await fetch(`${API_BASE}/auth/login/verify-otp`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: pendingLoginIdentifier, otp }),
    });

    const data = await res.json();
    if (!res.ok) {
      return toast(data?.detail || "OTP inválido");
    }

    toast(data?.message || "Acceso verificado ✅");
    close_login_otp();
    pendingLoginIdentifier = "";
    go_to_dashboard();
  } catch (err) {
    console.error(err);
    toast(`No se pudo conectar con el backend (${API_BASE})`);
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = "Verificar OTP";
    }
  }
});

navItems.forEach((btn) => {
  btn.addEventListener('click', () => {
    state.view = btn.dataset.view || 'inbox';
    state.selectedId = null;
    navItems.forEach(n => n.classList.toggle('active', n === btn));
    if (state.view === 'ledger') {
      refresh_blockchain_panel().finally(render);
      return;
    }
    render();
  });
});

listEl?.addEventListener('click', (e) => {
  const row = e.target.closest('[data-id]');
  if (!row) return;
  state.selectedId = row.dataset.id;
  render();
});

searchEl?.addEventListener('input', () => {
  state.query = searchEl.value || '';
  render();
});

btnRefresh?.addEventListener('click', () => {
  if (state.view === 'ledger') {
    refresh_blockchain_panel().finally(render);
    return;
  }
  render();
});

// Ir a crear cuenta desde login
btnGoSignup?.addEventListener("click", () => {
  close_login();
  open_signup();
});

// Cerrar con ESC
document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  close_login();
  close_login_otp();
});

// =========================
// Init
// =========================
state.items = load_items();
preload_login_identifier();
go_to_landing();
