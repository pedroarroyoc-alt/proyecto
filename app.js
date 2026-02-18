// =========================
// CONFIG
// =========================
function resolveApiBase() {
  const params = new URLSearchParams(window.location.search);
  const explicitApiBase = params.get("api") || window.localStorage.getItem("api_base_override");

  if (explicitApiBase) return explicitApiBase.replace(/\/$/, "");

  const isHttp = window.location.protocol === "http:" || window.location.protocol === "https:";
  const host = isHttp ? window.location.hostname : "127.0.0.1";
  const protocol = window.location.protocol === "https:" ? "https:" : "http:";

  return `${protocol}//${host}:8000`;
}

const API_BASE = resolveApiBase();
const JSON_HEADERS = { "Content-Type": "application/json" };

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
const btnResendSignupOtp = document.getElementById("btnResendSignupOtp");
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
const loginOtpHint = document.getElementById("loginOtpHint");
const loginOtpLabel = document.getElementById("loginOtpLabel");
const loginTotpGuide = document.getElementById("loginTotpGuide");
const loginTotpQr = document.getElementById("loginTotpQr");
const loginTotpSecret = document.getElementById("loginTotpSecret");

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
let currentUserEmail = "";
let signupVerificationLocked = false;
let signupSubmitting = false;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_REGEX = /^\+?\d{7,15}$/;
const DEFAULT_SIGNUP_HINT = "El correo debe terminar en @gmail.com.";

// =========================
// Helpers UI
// =========================
function show(el) {
  if (!el) return;
  el.classList.remove("hidden");
  el.removeAttribute("aria-hidden");
}

function hide(el) {
  if (!el) return;
  el.classList.add("hidden");
  el.setAttribute("aria-hidden", "true");
}

function set_text(el, value) {
  if (!el) return;
  el.textContent = value;
}

function normalize_email(value) {
  return String(value || "").trim().toLowerCase();
}

function is_email_identifier(value) {
  return EMAIL_REGEX.test(String(value || "").trim());
}

function backend_connection_hint() {
  return `No se pudo conectar con el backend (${API_BASE}). Verifica que el servidor esté encendido y con CORS habilitado.`;
}

function get_signup_email_input() {
  return normalize_email(suEmail?.value);
}

function clear_totp_guide() {
  loginTotpGuide?.classList.add("hidden");
  loginTotpQr?.removeAttribute("src");
  set_text(loginTotpSecret, "-");
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

function open_login_totp(identifier, enrollment = null) {
  pendingLoginIdentifier = identifier;
  if (liOtp) liOtp.value = "";

  set_text(loginOtpLabel, "Código TOTP");
  set_text(
    loginOtpHint,
    "Ingresa el código de 6 dígitos de tu app autenticadora (Google Authenticator, Microsoft Authenticator, etc.)."
  );

  if (loginTotpGuide) {
    if (enrollment?.qrUrl || enrollment?.secret) {
      loginTotpGuide.classList.remove("hidden");
      if (loginTotpQr) loginTotpQr.src = enrollment.qrUrl || "";
      set_text(loginTotpSecret, enrollment.secret || "-");
    } else {
      clear_totp_guide();
    }
  }

  hide(loginBackdrop);
  show(loginOtpBackdrop);
  if (loginOtpBackdrop) loginOtpBackdrop.style.display = "grid";
  setTimeout(() => liOtp?.focus(), 0);
}

function close_login_otp() {
  pendingLoginIdentifier = "";
  if (loginOtpBackdrop) loginOtpBackdrop.style.display = "";
  hide(loginOtpBackdrop);
  clear_totp_guide();
}

function is_signup_otp_step_active() {
  return Boolean(signupVerificationLocked);
}

function close_signup(force = false) {
  const isForced = typeof force === "boolean" ? force : false;

  if (!isForced && is_signup_otp_step_active()) {
    toast("Primero verifica el código OTP enviado a tu correo.");
    setTimeout(() => suOtp?.focus(), 0);
    return;
  }

  if (signupBackdrop) signupBackdrop.style.display = "";
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
 
function set_button_loading(button, loadingText, idleText, isLoading) {
  if (!button) return;
  button.disabled = isLoading;
  button.textContent = isLoading ? loadingText : idleText;
}

function set_otp_delivery_hint(targetEl, data, fallback) {
  if (!targetEl) return;

  targetEl.textContent = data?.emailSent === false
    ? (data?.otpDebug
        ? `No se pudo enviar correo. OTP de prueba: ${data.otpDebug}`
        : "No se pudo enviar correo. Solicita soporte para configurar SMTP.")
    : fallback;
}

function reset_signup_modal() {
  pendingEmail = "";
  signupVerificationLocked = false;

  set_text(signupTitle, "Crear una cuenta");
  set_signup_hint(DEFAULT_SIGNUP_HINT);
  set_text(otpHint, "");

  show(stepForm);
  hide(stepOtp);
  show(btnCreateAccount);
  hide(btnVerifyOtp);
  hide(btnResendSignupOtp);

  if (stepForm) stepForm.style.display = "block";
  if (stepOtp) stepOtp.style.display = "";
  if (btnCreateAccount) btnCreateAccount.style.display = "";
  if (btnVerifyOtp) btnVerifyOtp.style.display = "";
  if (btnResendSignupOtp) btnResendSignupOtp.style.display = "";
  if (suOtp) suOtp.value = "";
  if (suPassword) suPassword.value = "";
  if (suPassword2) suPassword2.value = "";
  if (suTerms) suTerms.checked = true;
}

function show_otp_step(email) {
  console.log("[signup] open modal OTP", { email });
  pendingEmail = email;
  signupVerificationLocked = true;

  set_text(signupTitle, "Verificar correo");
  show(signupBackdrop);
  if (signupBackdrop) signupBackdrop.style.display = "grid";
  hide(stepForm);
  if (stepForm) stepForm.style.display = "none";
  show(stepOtp);
  if (stepOtp) stepOtp.style.display = "block";
  hide(btnCreateAccount);
  if (btnCreateAccount) btnCreateAccount.style.display = "none";
  show(btnVerifyOtp);
  if (btnVerifyOtp) btnVerifyOtp.style.display = "";
  show(btnResendSignupOtp);
  if (btnResendSignupOtp) btnResendSignupOtp.style.display = "";
  set_text(otpHint, "Revisa tu correo y pega aquí el código OTP.");

  setTimeout(() => suOtp?.focus(), 0);
}

function show_signup_form_step(clearPending = false) {
  signupVerificationLocked = false;
  if (clearPending) {
    pendingEmail = "";
  }

  set_text(signupTitle, "Crear una cuenta");
  set_text(otpHint, "");
  show(stepForm);
  if (stepForm) stepForm.style.display = "block";
  hide(stepOtp);
  show(btnCreateAccount);
  if (btnCreateAccount) btnCreateAccount.style.display = "";
  hide(btnVerifyOtp);
  if (btnVerifyOtp) btnVerifyOtp.style.display = "";
  hide(btnResendSignupOtp);
  if (btnResendSignupOtp) btnResendSignupOtp.style.display = "";
  if (stepOtp) stepOtp.style.display = "";
}

async function post_json(path, body = {}) {
  return api_json(path, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(body),
  });
}

async function resend_verification_otp(email) {
  return post_json("/users/resend-verification-otp", { email: normalize_email(email) });
}

async function open_signup_otp_flow(email, payload = null, options = {}) {
  const normalizedEmail = normalize_email(email);
  if (!normalizedEmail) return null;
  const {
    hintMessage = "Cuenta pendiente de verificación. Revisa tu correo e ingresa el OTP.",
    resendHint = "Te reenviamos el OTP. Revisa tu correo.",
    resendErrorHint = "Cuenta pendiente de verificación. Usa 'Reenviar OTP' para solicitar un nuevo código.",
  } = options;

  close_login();
  const signupModalAlreadyOpen = Boolean(signupBackdrop && !signupBackdrop.classList.contains("hidden"));
  if (signupModalAlreadyOpen) {
    show(signupBackdrop);
  } else {
    open_signup();
  }
  if (signupBackdrop) signupBackdrop.style.display = "grid";
  if (suEmail) suEmail.value = normalizedEmail;
  show_otp_step(normalizedEmail);

  if (payload) {
    set_otp_delivery_hint(otpHint, payload, hintMessage);
    return payload;
  }

  try {
    const resendData = await resend_verification_otp(normalizedEmail);
    set_otp_delivery_hint(otpHint, resendData, resendHint);
    return resendData;
  } catch (err) {
    console.warn("No se pudo reenviar OTP automáticamente", err);
    set_otp_delivery_hint(otpHint, null, resendErrorHint);
    return null;
  }
}

function is_pending_verification_response(payload = {}) {
  const detail = payload?.detail;
  const detailText = typeof detail === "string"
    ? detail.toLowerCase()
    : String(detail || "").toLowerCase();
  const messageText = String(payload?.message || "").toLowerCase();
  const combinedText = `${detailText} ${messageText}`;
  const mentionsOtpPending = combinedText.includes("otp") && (
    combinedText.includes("enviado")
    || combinedText.includes("pendiente")
    || combinedText.includes("verifica")
  );

  return Boolean(
    payload?.requiresEmailVerification
    ?? payload?.requires_email_verification
    ?? payload?.otpSent
    ?? payload?.otp_sent
  ) || (
    detailText.includes("verific") && detailText.includes("correo")
  ) || (
    messageText.includes("verific") && messageText.includes("correo")
  ) || mentionsOtpPending;
}

function is_gmail(email) {
  return normalize_email(email).endsWith("@gmail.com");
}

function looks_like_gmail_typo(email) {
  return normalize_email(email).endsWith("@gamil.com");
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

  if (!res.ok) {
    const rawDetail = data?.detail;
    const detail = Array.isArray(rawDetail)
      ? rawDetail.map(item => item?.msg || item).join(" | ")
      : rawDetail;
    const error = new Error(detail || `Error HTTP ${res.status}`);
    error.status = res.status;
    error.payload = data;
    throw error;
  }

  return data;
}

function humanize_error(err, fallback) {
  const message = String(err?.message || "").trim();
  if (!message) return fallback;

  const normalized = message.toLowerCase();
  if (normalized.includes("failed to fetch") || normalized.includes("networkerror")) {
    return backend_connection_hint();
  }

  return message;
}

function short_hash(value = "") {
  return `${String(value).slice(0, 12)}...`;
}

function fmt_ts(value = "") {
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}

// =========================
// Crear cuenta (Paso 1)
// =========================
async function handle_create_account() {
  if (signupSubmitting) return;
  signupSubmitting = true;

  try {
    console.log("[signup] submit");
    set_signup_hint("Validando datos...");

    const first = suFirstName.value.trim();
    const last = suLastName.value.trim();
    const email = get_signup_email_input();
    const p1 = suPassword.value;
    const p2 = suPassword2.value;
    const okTerms = suTerms.checked;

    if (!first || !last) return show_signup_error("Completa nombres y apellidos");
    if (!email) return show_signup_error("Ingresa tu correo");
    if (looks_like_gmail_typo(email)) return show_signup_error("Parece que escribiste @gamil.com. Debe ser @gmail.com");
    if (!is_gmail(email)) return show_signup_error("El correo debe terminar en @gmail.com");
    if (p1.length < 8) return show_signup_error("Contraseña mínima: 8 caracteres");
    if (p1 !== p2) return show_signup_error("Las contraseñas no coinciden");
    if (!okTerms) return show_signup_error("Acepta los términos");

    set_signup_hint("Creando cuenta y enviando código OTP...");
    set_button_loading(btnCreateAccount, "Creando...", "Crear cuenta", true);

    const data = await post_json("/users/human", {
      email,
      nombre: `${first} ${last}`,
      telefono: "",
      mfaHabilitado: false,
      password: p1,
    });

    console.log("[signup] response", data);

    await open_signup_otp_flow(
      email,
      { ...data, otpSent: data?.emailSent !== false },
      { hintMessage: "Revisa tu correo y pega aquí el código OTP." }
    );
    toast(data?.message || "Te enviamos un OTP a tu correo 📩");
  } catch (err) {
    console.error(err);
    console.log("[signup] error response", err?.payload || err?.message || err);

    const signupEmail = get_signup_email_input();
    
    if (is_pending_verification_response(err?.payload || {}) && signupEmail) {
      await open_signup_otp_flow(
        signupEmail,
        err?.payload || {},
        { hintMessage: "Cuenta pendiente de verificación. Revisa tu correo e ingresa el OTP." }
      );
      toast(err?.payload?.message || err?.payload?.detail || "Te enviamos un OTP de verificación 📩");
      return;
    }

    if (err?.status === 409) {
      try {
        set_signup_hint("La cuenta ya existe. Reenviando OTP...");
        const resendData = await resend_verification_otp(signupEmail);
        await open_signup_otp_flow(
          signupEmail,
          resendData,
          { hintMessage: "Cuenta existente pendiente de verificación. Revisa tu correo e ingresa el OTP." }
        );
        toast(resendData?.message || "Te reenviamos el OTP de verificación 📩");
        return;
      } catch (resendErr) {
        console.error(resendErr);
      }
    }

    if (signupEmail && Number(err?.status) >= 500) {
      await open_signup_otp_flow(
        signupEmail,
        err?.payload || null,
        { hintMessage: "Si ya recibiste el OTP en tu correo, ingrésalo aquí para activar tu cuenta." }
      );
      toast("Pudimos abrir la verificación OTP para que completes la activación.");
      return;
    }

    show_signup_form_step(true);
    show_signup_error(
      humanize_error(
        err,
        backend_connection_hint()
      )
    );
  } finally {
    signupSubmitting = false;
    set_button_loading(btnCreateAccount, "Creando...", "Crear cuenta", false);
  }
}

// =========================
// Verificar OTP (Paso 2)
// =========================
async function handle_resend_signup_otp() {
  try {
    const email = normalize_email(pendingEmail || suEmail?.value);
    if (!email) return toast("No hay correo para reenviar OTP");

    set_button_loading(btnResendSignupOtp, "Reenviando...", "Reenviar OTP", true);

    const data = await resend_verification_otp(email);

    pendingEmail = email;
    set_otp_delivery_hint(otpHint, data, "Te reenviamos el OTP. Revisa tu correo.");
    toast(data?.message || "Te reenviamos el OTP 📩");
  } catch (err) {
    console.error(err);
    toast(humanize_error(err, "No se pudo reenviar el OTP"));
  } finally {
    set_button_loading(btnResendSignupOtp, "Reenviando...", "Reenviar OTP", false);
  }
}

async function handle_verify_otp() {
  try {
    console.log("[signup] verify submit", { email: pendingEmail });
    const otp = suOtp.value.trim();
    if (!pendingEmail) return toast("No hay correo pendiente");
    if (!otp) return toast("Ingresa el OTP");

    set_button_loading(btnVerifyOtp, "Verificando...", "Verificar", true);

    const verifyData = await post_json("/users/verify-email", { email: pendingEmail, otp });
    console.log("[signup] verify success", verifyData);

    pendingEmail = "";
    signupVerificationLocked = false;
    toast("Cuenta activada ✅");
    close_signup(true);
  } catch (err) {
    console.error(err);
    toast(humanize_error(err, "Error de red"));
  } finally {
    set_button_loading(btnVerifyOtp, "Verificando...", "Verificar", false);
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
  
  if (state.view === "security") {
    const totpEnabled = Boolean(state?.security?.mfaHabilitado) && state?.security?.mfaMetodo === "totp";
    const statusText = totpEnabled ? "Activo ✅" : "No configurado";
    const setupHtml = totpEnabled
      ? `<p><b>Estado TOTP:</b> ${statusText}</p>
         <p class="muted">Ya puedes usar códigos TOTP desde tu celular durante el login.</p>`
      : `
        <p><b>Estado TOTP:</b> ${statusText}</p>
        <p class="muted">Configura TOTP para generar códigos en tu celular.</p>
        <button class="btn" id="btnStartTotpSetup">Configurar TOTP en mi celular</button>
      `;

    const enrollment = state?.security?.enrollment || null;
    const enrollmentHtml = enrollment ? `
      <hr />
      <h3>Activación pendiente</h3>
      <p>1) Escanea este QR en tu app autenticadora.</p>
      <img class="totp-qr" alt="QR TOTP" src="${enrollment.qrUrl}" />
      <p class="muted">Si no puedes escanear, copia la clave manual: <code>${enrollment.secret}</code></p>
      <p>2) Ingresa el código de 6 dígitos para activar:</p>
      <div class="totp-confirm-row">
        <input id="totpCodeInput" type="text" inputmode="numeric" maxlength="6" placeholder="123456" />
        <button class="btn" id="btnConfirmTotp">Activar TOTP</button>
      </div>
    ` : "";

    detailEl.innerHTML = `
      <div class="detail-card">
        <h2>Seguridad de la cuenta (MFA)</h2>
        <p><b>Usuario:</b> ${currentUserEmail || "(sin sesión)"}</p>
        ${setupHtml}
        ${enrollmentHtml}
      </div>
    `;

    detailEl.querySelector("#btnStartTotpSetup")?.addEventListener("click", start_totp_setup);
    detailEl.querySelector("#btnConfirmTotp")?.addEventListener("click", () => {
      const code = String(detailEl.querySelector("#totpCodeInput")?.value || "").trim();
      confirm_totp_setup(code);
    });
    return;
  }

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

function get_otpauth_qr_url(otpauthUri) {
  return `https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=${encodeURIComponent(otpauthUri)}`;
}

async function fetch_current_user_profile() {
  if (!currentUserEmail) return null;
  try {
    return await api_json(`/users/by-email?email=${encodeURIComponent(currentUserEmail)}`);
  } catch (err) {
    console.warn("No se pudo obtener perfil por email", err);
    return null;
  }
}

async function ensure_security_context() {
  if (!state.security) state.security = {};
  const user = await fetch_current_user_profile();
  if (!user?.id) return null;

  state.security.userId = user.id;
  state.security.mfaHabilitado = Boolean(user.mfaHabilitado);
  state.security.mfaMetodo = user.mfaMetodo || "none";
  return user;
}

async function start_totp_setup() {
  if (!currentUserEmail) return toast("Debes iniciar sesión primero");
  const user = await ensure_security_context();
  if (!user?.id) return toast("No se pudo cargar tu perfil de usuario");

  try {
    const data = await post_json(`/users/${user.id}/mfa/totp/enroll`, {});
    state.security.enrollment = {
      secret: data?.secret || "",
      otpauthUri: data?.otpauthUri || "",
      qrUrl: get_otpauth_qr_url(data?.otpauthUri || ""),
    };
    toast("Escanea el QR en tu celular y confirma con tu código TOTP");
    render();
  } catch (err) {
    console.error(err);
    toast(err?.message || "No se pudo iniciar la configuración TOTP");
  }
}

async function confirm_totp_setup(code) {
  if (!/^\d{6}$/.test(code)) return toast("Ingresa un código TOTP de 6 dígitos");
  const user = await ensure_security_context();
  if (!user?.id) return toast("No se pudo cargar tu perfil de usuario");

  try {
    const data = await post_json(`/users/${user.id}/mfa/totp/confirm`, { codigo: code });
    state.security.enrollment = null;
    state.security.mfaHabilitado = Boolean(data?.user?.mfaHabilitado);
    state.security.mfaMetodo = data?.user?.mfaMetodo || "none";
    toast(data?.message || "TOTP activado correctamente");
    render();
  } catch (err) {
    console.error(err);
    toast(err?.message || "Código TOTP inválido");
  }
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
      api_json("/audit/status"),
      api_json("/audit/chain")
    ]);

    const ledgerBlocks = (chain?.cadena || []).map(normalize_block_to_item);
    state.items = [
      ...state.items.filter(i => i.view !== "ledger"),
      ...ledgerBlocks,
    ];

    save_items(state.items);

    if (detailEl && state.view === "ledger") {
      const lastHash = ledgerBlocks.length ? short_hash(ledgerBlocks[ledgerBlocks.length - 1].raw.hash) : "-";
      detailEl.innerHTML = `
        <div class="detail-card">
          <h2>Estado blockchain</h2>
          <p><b>Válida:</b> ${status.valida ? "Sí ✅" : "No ❌"}</p>
          <p><b>Longitud:</b> ${status.longitud}</p>
          <p><b>Dificultad:</b> ${status.dificultad}</p>
          <p><b>Último hash:</b> <code>${lastHash}</code></p>
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

  state.view = "ledger";
  navItems.forEach(n => n.classList.toggle("active", n.dataset.view === state.view));

  await ensure_security_context().catch(() => null);
  await refresh_blockchain_panel().catch(() => {});
  render();
}

function go_to_landing() {
  show(landing);
  hide(dashboardApp);
}

function preload_login_identifier() {
  const saved = localStorage.getItem("cryptolock_last_login");
  if (!saved || !liEmail) return;

  liEmail.value = saved;
  if (liRemember) liRemember.checked = true;
}

function valid_login_identifier(value) {
  const v = String(value || "").trim();
  return is_email_identifier(v) || PHONE_REGEX.test(v.replace(/[\s()-]/g, ""));
}

function persist_login_identifier(loginIdentifier) {
  if (liRemember?.checked) {
    localStorage.setItem("cryptolock_last_login", loginIdentifier);
  } else {
    localStorage.removeItem("cryptolock_last_login");
  }
}

function set_active_nav(button) {
  navItems.forEach(n => n.classList.toggle("active", n === button));
}

// =========================
// Listeners
// =========================
btnSignup?.addEventListener("click", open_signup);
btnCloseSignup?.addEventListener("click", close_signup);
signupBackdrop?.addEventListener("click", (e) => e.target === signupBackdrop && close_signup());

btnCreateAccount?.addEventListener("click", (e) => {
  e.preventDefault();
  handle_create_account();
});
btnVerifyOtp?.addEventListener("click", handle_verify_otp);
btnResendSignupOtp?.addEventListener("click", handle_resend_signup_otp);

[suFirstName, suLastName, suEmail, suPassword, suPassword2].forEach((field) => {
  field?.addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    if (signupVerificationLocked) return;
    e.preventDefault();
    handle_create_account();
  });
});

suOtp?.addEventListener("keydown", (e) => {
  if (e.key !== "Enter") return;
  e.preventDefault();
  handle_verify_otp();
});

btnEnter?.addEventListener("click", open_login);

btnAbout?.addEventListener("click", () => {
  if (aboutBox) aboutBox.classList.toggle("hidden");
});

btnCloseLogin?.addEventListener("click", close_login);
btnCloseLoginOtp?.addEventListener("click", close_login_otp);
loginBackdrop?.addEventListener("click", (e) => e.target === loginBackdrop && close_login());
loginOtpBackdrop?.addEventListener("click", (e) => e.target === loginOtpBackdrop && close_login_otp());

btnTogglePwd?.addEventListener("click", () => {
  const isPwd = liPassword.type === "password";
  liPassword.type = isPwd ? "text" : "password";
  btnTogglePwd.textContent = isPwd ? "Ocultar" : "Mostrar";
});

loginForm?.addEventListener("submit", async (e) => {
  e.preventDefault();

  const loginIdentifier = liEmail?.value?.trim() || "";
  const normalizedLoginIdentifier = normalize_email(loginIdentifier);
  const pwd = liPassword?.value || "";

  if (!loginIdentifier) return toast("Ingresa tu correo o teléfono");
  if (!valid_login_identifier(loginIdentifier)) return toast("Formato inválido: usa correo o teléfono");
  if (!pwd) return toast("Ingresa tu contraseña");

  if (!is_email_identifier(loginIdentifier)) {
    return toast("Por ahora el login TOTP solo admite correo electrónico");
  }

  persist_login_identifier(loginIdentifier);

  const submitBtn = loginForm.querySelector('button[type="submit"]');
  set_button_loading(submitBtn, "Verificando...", "Ingresar", true);

  try {
    const data = await post_json("/auth/login/request-otp", {
      email: normalizedLoginIdentifier,
      password: pwd,
    });

    const requiresEmailVerification = Boolean(
      data?.requiresEmailVerification ?? data?.requires_email_verification
    );
    const mfaRequired = Boolean(data?.mfaRequired ?? data?.mfa_required);
    const mfaMethod = String(data?.mfaMethod ?? data?.mfa_method ?? "").toLowerCase();

    if (requiresEmailVerification) {
      toast(data?.message || "Tu cuenta aún no está verificada. Te enviamos OTP de verificación.");
      await open_signup_otp_flow(
        normalizedLoginIdentifier,
        data,
        { hintMessage: "Tu cuenta está pendiente de verificación. Revisa tu correo e ingresa el OTP." }
      );
      return;
    }

    if (mfaMethod === "totp" && (mfaRequired || data?.totpEnrollment)) {
      toast("Ingresa el código TOTP de tu app autenticadora");
      open_login_totp(normalizedLoginIdentifier, data?.totpEnrollment || null);
      return;
    }

    toast("Esta cuenta no tiene TOTP configurado. Configúralo en Seguridad (MFA).");
  } catch (err) {
    console.error(err);

    const loginPayload = err?.payload || {};
    const loginDetail = String(loginPayload?.detail || err?.message || "").toLowerCase();
    const shouldOpenVerification = Boolean(
      is_pending_verification_response(loginPayload)
      || loginDetail.includes("no está verificada")
      || (loginDetail.includes("verific") && loginDetail.includes("correo"))
    );

    if (shouldOpenVerification && normalizedLoginIdentifier) {
      await open_signup_otp_flow(
        normalizedLoginIdentifier,
        loginPayload,
        { hintMessage: "Tu cuenta está pendiente de verificación. Revisa tu correo e ingresa el OTP." }
      );
      toast(loginPayload?.message || "Tu cuenta está pendiente de verificación. Ingresa el OTP.");
      return;
    }
   
    toast(humanize_error(err, `No se pudo conectar con el backend (${API_BASE})`));
  } finally {
    set_button_loading(submitBtn, "Verificando...", "Ingresar", false);
  }
});

loginOtpForm?.addEventListener("submit", async (e) => {
  e.preventDefault();

  const otp = String(liOtp?.value || "").trim();
  if (!pendingLoginIdentifier) return toast("No hay inicio de sesión pendiente");
  if (!/^\d{6}$/.test(otp)) return toast("Ingresa un código TOTP de 6 dígitos");

  const submitBtn = loginOtpForm.querySelector('button[type="submit"]');
  set_button_loading(submitBtn, "Verificando...", "Verificar TOTP", true);

  try {
    const data = await post_json("/auth/login/verify-otp", {
      email: pendingLoginIdentifier,
      otp,
    });

    toast(data?.message || "Acceso verificado ✅");
    currentUserEmail = data?.user?.email || pendingLoginIdentifier;
    close_login_otp();
    go_to_dashboard();
  } catch (err) {
    console.error(err);
    toast(humanize_error(err, `No se pudo conectar con el backend (${API_BASE})`));
  } finally {
    set_button_loading(submitBtn, "Verificando...", "Verificar TOTP", false);
  }
});

navItems.forEach((btn) => {
  btn.addEventListener("click", () => {
    state.view = btn.dataset.view || "inbox";
    state.selectedId = null;
    set_active_nav(btn);

    if (state.view === "ledger") {
      refresh_blockchain_panel().finally(render);
      return;
    }

    if (state.view === "security") {
      ensure_security_context().finally(render);
      return;
    }

    render();
  });
});

listEl?.addEventListener("click", (e) => {
  const row = e.target.closest("[data-id]");
  if (!row) return;
  state.selectedId = row.dataset.id;
  render();
});

searchEl?.addEventListener("input", () => {
  state.query = searchEl.value || "";
  render();
});

btnRefresh?.addEventListener("click", () => {
  if (state.view === "ledger") {
    refresh_blockchain_panel().finally(render);
    return;
  }

  render();
});

btnGoSignup?.addEventListener("click", (e) => {
  e.preventDefault();
  close_login();
  open_signup();
});

document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  close_signup();
  close_login();
  close_login_otp();
});

// =========================
// Init
// =========================
state.items = load_items();
preload_login_identifier();
go_to_landing();

void modalBackdrop;
void btnCompose;
void btnCloseModal;
void btnSendAction;
void actionTypeEl;
void actionDescEl;
