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

function close_signup() {
  hide(signupBackdrop);
}

function reset_signup_modal() {
  pendingEmail = "";
  signupTitle.textContent = "Crear una cuenta";
  if (signupHint) {
    signupHint.innerHTML = "El correo debe terminar en <b>@uni.pe</b>.";
  }
  otpHint.textContent = "";

  show(stepForm);
  hide(stepOtp);
  show(btnCreateAccount);
  hide(btnVerifyOtp);

  suOtp.value = "";
}

function show_otp_step(email, otpSimulado) {
  pendingEmail = email;
  signupTitle.textContent = "Verificar correo";
  hide(stepForm);
  show(stepOtp);
  hide(btnCreateAccount);
  show(btnVerifyOtp);
  otpHint.textContent = `OTP simulado: ${otpSimulado}`;
}

function is_uni_email(email) {
  return String(email || "").toLowerCase().endsWith("@uni.pe");
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

// =========================
// Crear cuenta (Paso 1)
// =========================
async function handle_create_account() {
  try {
    if (signupHint) signupHint.textContent = "";

    const first = suFirstName.value.trim();
    const last = suLastName.value.trim();
    const email = suEmail.value.trim().toLowerCase();
    const p1 = suPassword.value;
    const p2 = suPassword2.value;
    const okTerms = suTerms.checked;

    if (!first || !last) return toast("Completa nombres y apellidos");
    if (!email) return toast("Ingresa tu correo");
    if (!is_uni_email(email)) return toast("El correo debe terminar en @uni.pe");
    if (p1.length < 8) return toast("Contraseña mínima: 8 caracteres");
    if (p1 !== p2) return toast("Las contraseñas no coinciden");
    if (!okTerms) return toast("Acepta los términos");

    btnCreateAccount.disabled = true;
    btnCreateAccount.textContent = "Creando...";

    const res = await fetch(`${API_BASE}/users/human`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email,
        nombre: `${first} ${last}`,
        telefono: "",
        mfaHabilitado: false
      }),
    });

    const data = await res.json();

    if (!res.ok) return toast(data?.detail || "Error creando usuario");
    if (!data.otp_simulado) return toast("No llegó OTP");

    show_otp_step(email, data.otp_simulado);

  } catch (err) {
    console.error(err);
    toast("Error de red o servidor");
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

// =========================
// Dashboard (demo)
// =========================
function default_items() {
  const now = new Date().toISOString();
  return [
    { id: "INB-1", view: "inbox", title: "Login verificado", subtitle: "OTP", status: "OK", createdAt: now, body: "Acceso verificado." }
  ];
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

function render() {
  if (!listEl) return;
  listEl.innerHTML = state.items.map(i => `<button class="list-item">${i.title}</button>`).join("");
}

function go_to_dashboard() {
  hide(landing);
  show(dashboardApp);
  render();
}

function go_to_landing() {
  show(landing);
  hide(dashboardApp);
}

// =========================
// Listeners
// =========================
btnSignup?.addEventListener("click", open_signup);
btnCloseSignup?.addEventListener("click", close_signup);
signupBackdrop?.addEventListener("click", e => e.target === signupBackdrop && close_signup());

btnCreateAccount?.addEventListener("click", handle_create_account);
btnVerifyOtp?.addEventListener("click", handle_verify_otp);

btnEnter?.addEventListener("click", go_to_dashboard);

btnAbout?.addEventListener("click", () => {
  if (aboutBox) aboutBox.classList.toggle("hidden");
});

// =========================
// Init
// =========================
state.items = load_items();
go_to_landing();
