// =========================
// CONFIG
// =========================
function resolveApiBase() {
  const params = new URLSearchParams(window.location.search);
  const queryApiBase = String(params.get("api") || "").trim();

  if (queryApiBase) {
    try {
      const parsed = new URL(queryApiBase);
      if (parsed.protocol === "http:" || parsed.protocol === "https:") {
        return parsed.toString().replace(/\/$/, "");
      }
      console.warn("[cryptolock-ui] Ignorando ?api por protocolo no soportado", queryApiBase);
    } catch {
      console.warn("[cryptolock-ui] Ignorando ?api inválido", queryApiBase);
    }
  }

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
const signupOtpBackdrop = document.getElementById("signupOtpBackdrop");
const btnCloseSignupOtp = document.getElementById("btnCloseSignupOtp");

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
const btnCryptoLogin = document.getElementById("btnCryptoLogin");
const cryptoLoginBackdrop = document.getElementById("cryptoLoginBackdrop");
const btnCloseCryptoLogin = document.getElementById("btnCloseCryptoLogin");
const cryptoChallengeQr = document.getElementById("cryptoChallengeQr");
const cryptoChallengeId = document.getElementById("cryptoChallengeId");
const cryptoChallengeText = document.getElementById("cryptoChallengeText");
const btnRefreshCryptoChallenge = document.getElementById("btnRefreshCryptoChallenge");
const btnSignCryptoHere = document.getElementById("btnSignCryptoHere");
const cryptoChallengeStatus = document.getElementById("cryptoChallengeStatus");
const mobileSignerApp = document.getElementById("mobileSignerApp");
const mobileSignerEmail = document.getElementById("mobileSignerEmail");
const mobileSignerChallengeId = document.getElementById("mobileSignerChallengeId");
const mobileSignerChallengeText = document.getElementById("mobileSignerChallengeText");
const btnApproveMobileChallenge = document.getElementById("btnApproveMobileChallenge");
const mobileSignerStatus = document.getElementById("mobileSignerStatus");

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
  items: [],
  security: {},
  methods: {}
};

let pendingEmail = "";
let pendingLoginIdentifier = "";
let currentUserEmail = "";
let signupVerificationLocked = false;
let signupSubmitting = false;
let cryptoLoginSession = null;
let cryptoPollTimer = null;
let mobileSignerContext = null;
let mobileSetupContext = null;
let mobileSignerMode = "challenge";
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PHONE_REGEX = /^\+?\d{7,15}$/;
const DEFAULT_SIGNUP_HINT = "El correo debe terminar en @gmail.com.";
const CRYPTO_DEVICE_KEY_PREFIX = "cryptolock_crypto_device_key_v1:";
const CRYPTO_CHALLENGE_POLL_MS = 2000;
const APP_BUILD = "otpfix11";
console.info(`[cryptolock-ui] build ${APP_BUILD}`);

if (btnSignCryptoHere) {
  btnSignCryptoHere.classList.add("hidden");
}

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

function mobile_qr_host_hint() {
  const protocol = String(window.location.protocol || "");
  const host = String(window.location.hostname || "").toLowerCase();

  if (protocol === "file:") {
    return "Estas abriendo el frontend como archivo local. Para usar celular, sirvelo por HTTP en una IP de tu red local.";
  }

  if (host === "localhost" || host === "127.0.0.1") {
    return "Estas usando localhost/127.0.0.1. En el celular abre el frontend con la IP local de tu laptop (ej: http://192.168.1.25:5500).";
  }

  return "";
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
  close_signup_otp(true);
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

  if (!isForced && signupSubmitting) {
    toast("Espera un momento, estamos creando tu cuenta...");
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

// Reajuste del flujo de registro: OTP en modal dedicado.
function close_signup_otp(force = false) {
  void force;

  signupVerificationLocked = false;
  pendingEmail = "";

  if (signupOtpBackdrop) signupOtpBackdrop.style.display = "";
  hide(signupOtpBackdrop);
}

function reset_signup_modal() {
  pendingEmail = "";
  signupVerificationLocked = false;

  set_text(signupTitle, "Crear una cuenta");
  set_signup_hint(DEFAULT_SIGNUP_HINT);
  set_text(otpHint, "Revisa tu correo y pega aqui el codigo OTP.");

  if (suFirstName) suFirstName.value = "";
  if (suLastName) suLastName.value = "";
  if (suEmail) suEmail.value = "";
  if (suOtp) suOtp.value = "";
  if (suPassword) suPassword.value = "";
  if (suPassword2) suPassword2.value = "";
  if (suTerms) suTerms.checked = true;

  show_signup_form_step(false, { force: true });
}

function show_otp_step(email, options = {}) {
  const { preserveInput = false } = options;
  console.log("[signup] open modal OTP", { email });
  pendingEmail = email;
  signupVerificationLocked = true;

  const activeEl = document.activeElement;
  if (signupBackdrop && activeEl instanceof HTMLElement && signupBackdrop.contains(activeEl)) {
    activeEl.blur();
  }

  hide(signupBackdrop);
  show(signupOtpBackdrop);
  if (signupOtpBackdrop) signupOtpBackdrop.style.display = "grid";
  if (suOtp && !preserveInput) suOtp.value = "";
  show(btnVerifyOtp);
  show(btnResendSignupOtp);
  set_text(otpHint, "Revisa tu correo y pega aqui el codigo OTP.");

  setTimeout(() => suOtp?.focus(), 0);
}

function show_signup_form_step(clearPending = false, options = {}) {
  const { force = false } = options;
  if (signupVerificationLocked && !force) {
    return;
  }

  signupVerificationLocked = false;
  if (clearPending) {
    pendingEmail = "";
  }

  set_text(signupTitle, "Crear una cuenta");
  set_signup_hint(DEFAULT_SIGNUP_HINT);
  show(stepForm);
  show(btnCreateAccount);

  if (signupBackdrop) signupBackdrop.style.display = "grid";
  show(signupBackdrop);

  if (signupOtpBackdrop) signupOtpBackdrop.style.display = "";
  hide(signupOtpBackdrop);
}

async function post_json(path, body = {}) {
  return api_json(path, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(body),
  });
}

async function patch_json(path, body = {}) {
  return api_json(path, {
    method: "PATCH",
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
  if (suEmail) suEmail.value = normalizedEmail;
  show_otp_step(normalizedEmail, { preserveInput: true });

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

function response_mentions_email_verification(payload = {}) {
  const detailText = String(payload?.detail || "").toLowerCase();
  const messageText = String(payload?.message || "").toLowerCase();
  const combinedText = `${detailText} ${messageText}`;

  return (
    is_pending_verification_response(payload)
    || combinedText.includes("cuenta") && combinedText.includes("verific")
    || combinedText.includes("usuario no activo")
  );
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
  const controller = new AbortController();
  const timeoutMs = 15000;
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  let res;
  try {
    res = await fetch(`${API_BASE}${path}`, { ...options, signal: controller.signal });
  } catch (error) {
    if (error?.name === "AbortError") {
      throw new Error(`Tiempo de espera agotado al conectar con ${API_BASE}`);
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }

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

function set_status_text(el, message, isError = false) {
  if (!el) return;
  el.textContent = message;
  el.style.color = isError ? "#b42318" : "";
}

function set_crypto_status(message, isError = false) {
  set_status_text(cryptoChallengeStatus, message, isError);
}

function set_mobile_signer_status(message, isError = false) {
  set_status_text(mobileSignerStatus, message, isError);
}

function get_crypto_storage_key(email) {
  return `${CRYPTO_DEVICE_KEY_PREFIX}${normalize_email(email)}`;
}

function get_device_key_record(email) {
  const key = get_crypto_storage_key(email);
  const raw = localStorage.getItem(key);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (!parsed?.privateKeyPkcs8B64 || !parsed?.publicKeyPem) return null;
    return parsed;
  } catch {
    return null;
  }
}

function set_device_key_record(email, record) {
  localStorage.setItem(get_crypto_storage_key(email), JSON.stringify(record));
}

function clear_device_key_record(email) {
  localStorage.removeItem(get_crypto_storage_key(email));
}

function array_buffer_to_base64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function base64_to_array_buffer(base64) {
  const clean = String(base64 || "").replace(/\s+/g, "");
  const binary = atob(clean);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function base64_to_pem(base64, label) {
  const chunks = String(base64 || "").match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${chunks.join("\n")}\n-----END ${label}-----`;
}

function ensure_webcrypto_available() {
  if (!window.crypto?.subtle) {
    throw new Error("Este navegador/dispositivo no soporta WebCrypto");
  }
}

async function generate_rsa_pss_key_pair() {
  ensure_webcrypto_available();
  return window.crypto.subtle.generateKey(
    {
      name: "RSA-PSS",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"]
  );
}

async function export_public_key_pem(publicKey) {
  const spki = await window.crypto.subtle.exportKey("spki", publicKey);
  const b64 = array_buffer_to_base64(spki);
  return base64_to_pem(b64, "PUBLIC KEY");
}

async function export_private_key_pkcs8_base64(privateKey) {
  const pkcs8 = await window.crypto.subtle.exportKey("pkcs8", privateKey);
  return array_buffer_to_base64(pkcs8);
}

async function import_private_key_from_record(record) {
  return window.crypto.subtle.importKey(
    "pkcs8",
    base64_to_array_buffer(record.privateKeyPkcs8B64),
    { name: "RSA-PSS", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

async function ensure_device_keypair(email, options = {}) {
  const normalizedEmail = normalize_email(email);
  const forceRotate = Boolean(options.forceRotate);
  if (!normalizedEmail) throw new Error("Correo requerido para gestionar llaves");

  if (!forceRotate) {
    const existing = get_device_key_record(normalizedEmail);
    if (existing?.privateKeyPkcs8B64 && existing?.publicKeyPem) {
      return existing;
    }
  }

  const keyPair = await generate_rsa_pss_key_pair();
  const [publicKeyPem, privateKeyPkcs8B64] = await Promise.all([
    export_public_key_pem(keyPair.publicKey),
    export_private_key_pkcs8_base64(keyPair.privateKey),
  ]);

  const record = {
    algorithm: "RSA-PSS-SHA256",
    publicKeyPem,
    privateKeyPkcs8B64,
    createdAt: new Date().toISOString(),
  };

  set_device_key_record(normalizedEmail, record);
  return record;
}

async function sign_challenge_with_local_key(email, challenge) {
  const normalizedEmail = normalize_email(email);
  const record = get_device_key_record(normalizedEmail);
  if (!record) {
    throw new Error("No existe llave privada local para este correo. Activa el metodo en este dispositivo.");
  }
  if (!challenge) {
    throw new Error("Challenge vacio");
  }

  const privateKey = await import_private_key_from_record(record);
  const payload = new TextEncoder().encode(challenge);
  const signature = await window.crypto.subtle.sign(
    { name: "RSA-PSS", saltLength: 32 },
    privateKey,
    payload
  );
  return array_buffer_to_base64(signature);
}

function get_qr_code_url(value, size = 240) {
  return `https://api.qrserver.com/v1/create-qr-code/?size=${size}x${size}&data=${encodeURIComponent(String(value || ""))}`;
}

function build_mobile_signer_link({ email, challengeId, challenge }) {
  const url = new URL(window.location.href);
  url.searchParams.delete("mobile_signer_setup");
  url.searchParams.delete("userId");
  url.searchParams.set("mobile_signer", "1");
  url.searchParams.set("email", normalize_email(email));
  url.searchParams.set("challengeId", challengeId);
  url.searchParams.set("challenge", challenge);
  url.searchParams.set("api", API_BASE);
  return url.toString();
}

function build_mobile_setup_link({ email, userId }) {
  const url = new URL(window.location.href);
  url.searchParams.delete("mobile_signer");
  url.searchParams.delete("challengeId");
  url.searchParams.delete("challenge");
  url.searchParams.set("mobile_signer_setup", "1");
  url.searchParams.set("email", normalize_email(email));
  url.searchParams.set("userId", String(userId || "").trim());
  url.searchParams.set("api", API_BASE);
  return url.toString();
}

function stop_crypto_polling() {
  if (cryptoPollTimer) {
    clearInterval(cryptoPollTimer);
    cryptoPollTimer = null;
  }
}

function reset_crypto_login_modal() {
  stop_crypto_polling();
  if (cryptoChallengeQr) cryptoChallengeQr.removeAttribute("src");
  if (cryptoChallengeId) cryptoChallengeId.value = "";
  if (cryptoChallengeText) cryptoChallengeText.value = "";
  set_crypto_status("Esperando challenge...");
}

function open_crypto_login() {
  hide(loginBackdrop);
  show(cryptoLoginBackdrop);
  if (cryptoLoginBackdrop) cryptoLoginBackdrop.style.display = "grid";
  if (btnSignCryptoHere) {
    btnSignCryptoHere.disabled = true;
    btnSignCryptoHere.textContent = "Solo celular";
    btnSignCryptoHere.title = "Por seguridad, esta cuenta se aprueba solo desde el celular.";
  }
}

function close_crypto_login() {
  stop_crypto_polling();
  cryptoLoginSession = null;
  if (cryptoLoginBackdrop) cryptoLoginBackdrop.style.display = "";
  hide(cryptoLoginBackdrop);
  reset_crypto_login_modal();
}

async function exchange_crypto_grant(challengeId, loginGrant) {
  if (!challengeId || !loginGrant) throw new Error("Grant de login invalido");

  const data = await post_json("/auth/crypto/exchange", {
    challengeId,
    loginGrant,
  });
  currentUserEmail = data?.user?.email || cryptoLoginSession?.email || "";
  close_crypto_login();
  close_login();
  close_login_otp();
  toast(data?.message || "Acceso verificado por firma criptografica");
  await go_to_dashboard();
}

async function poll_crypto_challenge_once() {
  const challengeId = cryptoLoginSession?.challengeId;
  if (!challengeId) return;

  try {
    const data = await api_json(`/auth/crypto/challenge-status?challengeId=${encodeURIComponent(challengeId)}`);
    const status = String(data?.status || "").toLowerCase();

    if (status === "pending") {
      const expiresIn = Number(data?.expiresIn || 0);
      set_crypto_status(`Esperando aprobacion del celular/dispositivo... expira en ${Math.max(0, expiresIn)}s.`);
      return;
    }

    if (status === "verified" && data?.loginGrant) {
      set_crypto_status("Firma aprobada. Completando acceso...");
      stop_crypto_polling();
      await exchange_crypto_grant(challengeId, data.loginGrant);
      return;
    }

    if (status === "expired" || status === "failed") {
      stop_crypto_polling();
      set_crypto_status(`Challenge ${status}. Genera uno nuevo para continuar.`, true);
      return;
    }
  } catch (err) {
    set_crypto_status(humanize_error(err, "No se pudo consultar estado del challenge"), true);
  }
}

function start_crypto_challenge_polling() {
  stop_crypto_polling();
  let inFlight = false;
  cryptoPollTimer = setInterval(async () => {
    if (inFlight) return;
    inFlight = true;
    try {
      await poll_crypto_challenge_once();
    } finally {
      inFlight = false;
    }
  }, CRYPTO_CHALLENGE_POLL_MS);
}

async function request_crypto_challenge_for_email(email) {
  const normalizedEmail = normalize_email(email);
  if (!normalizedEmail) throw new Error("Ingresa un correo valido");

  stop_crypto_polling();
  set_crypto_status("Generando challenge criptografico...");
  const data = await post_json("/auth/crypto/challenge", { email: normalizedEmail });
  const challengeId = String(data?.challengeId || "").trim();
  const challenge = String(data?.challenge || "").trim();
  if (!challengeId || !challenge) {
    throw new Error("Respuesta invalida del backend al generar challenge");
  }

  const signerLink = build_mobile_signer_link({ email: normalizedEmail, challengeId, challenge });
  cryptoLoginSession = {
    email: normalizedEmail,
    challengeId,
    challenge,
    signerLink,
  };

  if (cryptoChallengeId) cryptoChallengeId.value = challengeId;
  if (cryptoChallengeText) cryptoChallengeText.value = challenge;
  if (cryptoChallengeQr) cryptoChallengeQr.src = get_qr_code_url(signerLink, 240);

  set_crypto_status("Challenge activo. Escanea el QR y aprueba desde tu celular/dispositivo.");
  start_crypto_challenge_polling();
}

async function start_crypto_login() {
  const loginIdentifier = liEmail?.value?.trim() || "";
  const normalizedEmail = normalize_email(loginIdentifier);
  if (!is_email_identifier(normalizedEmail)) {
    toast("Para firma criptografica debes ingresar un correo en el campo de login");
    return;
  }

  persist_login_identifier(loginIdentifier);
  open_crypto_login();
  cryptoLoginSession = { email: normalizedEmail, challengeId: "", challenge: "" };
  reset_crypto_login_modal();

  try {
    await request_crypto_challenge_for_email(normalizedEmail);
  } catch (err) {
    const msg = humanize_error(err, "No se pudo iniciar login por firma");
    set_crypto_status(msg, true);
    toast(msg);
  }
}

async function sign_current_challenge_here() {
  toast("Por seguridad, este login se aprueba solo desde tu celular.");
}

function parse_mobile_setup_context() {
  const params = new URLSearchParams(window.location.search);
  if (params.get("mobile_signer_setup") !== "1") return null;

  const email = normalize_email(params.get("email"));
  const userId = String(params.get("userId") || "").trim();
  return { email, userId };
}

function parse_mobile_signer_context() {
  const params = new URLSearchParams(window.location.search);
  if (params.get("mobile_signer") !== "1") return null;

  const email = normalize_email(params.get("email"));
  const challengeId = String(params.get("challengeId") || "").trim();
  const challenge = String(params.get("challenge") || "").trim();
  return { email, challengeId, challenge };
}

function open_mobile_signer_base() {
  hide(landing);
  hide(dashboardApp);
  hide(loginBackdrop);
  hide(loginOtpBackdrop);
  hide(signupBackdrop);
  hide(signupOtpBackdrop);
  hide(cryptoLoginBackdrop);
  show(mobileSignerApp);
}

function open_mobile_signer_mode(context) {
  mobileSignerMode = "challenge";
  mobileSignerContext = context || null;
  mobileSetupContext = null;
  open_mobile_signer_base();
  if (mobileSignerEmail) mobileSignerEmail.value = context?.email || "";
  if (mobileSignerChallengeId) mobileSignerChallengeId.value = context?.challengeId || "";
  if (mobileSignerChallengeText) mobileSignerChallengeText.value = context?.challenge || "";
  if (btnApproveMobileChallenge) {
    btnApproveMobileChallenge.textContent = "Firmar y aprobar acceso";
  }

  const titleEl = mobileSignerApp?.querySelector("h2");
  const subtitleEl = mobileSignerApp?.querySelector("p.muted");
  set_text(titleEl, "Aprobar acceso con firma");
  set_text(
    subtitleEl,
    "Este dispositivo firma el challenge con su llave privada y el backend verifica con la llave publica."
  );

  if (!context?.email || !context?.challengeId || !context?.challenge) {
    set_mobile_signer_status("Faltan datos del challenge en la URL.", true);
    if (btnApproveMobileChallenge) btnApproveMobileChallenge.disabled = true;
    return;
  }

  if (btnApproveMobileChallenge) btnApproveMobileChallenge.disabled = false;
  set_mobile_signer_status("Listo para firmar y aprobar el acceso.");
}

function open_mobile_setup_mode(context) {
  mobileSignerMode = "setup";
  mobileSetupContext = context || null;
  mobileSignerContext = null;
  open_mobile_signer_base();

  if (mobileSignerEmail) mobileSignerEmail.value = context?.email || "";
  if (mobileSignerChallengeId) mobileSignerChallengeId.value = context?.userId || "";
  if (mobileSignerChallengeText) {
    mobileSignerChallengeText.value = "Este celular generara la llave privada localmente y registrara la llave publica en el backend.";
  }
  if (btnApproveMobileChallenge) {
    btnApproveMobileChallenge.textContent = "Generar llave y activar firma criptografica";
  }

  const titleEl = mobileSignerApp?.querySelector("h2");
  const subtitleEl = mobileSignerApp?.querySelector("p.muted");
  set_text(titleEl, "Configurar firma en este celular");
  set_text(
    subtitleEl,
    "La llave privada quedara en este dispositivo. Solo se enviara la llave publica al backend."
  );

  if (!context?.email || !context?.userId) {
    set_mobile_signer_status("Faltan datos para configurar firma en celular.", true);
    if (btnApproveMobileChallenge) btnApproveMobileChallenge.disabled = true;
    return;
  }

  if (btnApproveMobileChallenge) btnApproveMobileChallenge.disabled = false;
  set_mobile_signer_status("Listo para generar llave y activar el metodo.");
}

async function approve_mobile_challenge() {
  const context = mobileSignerContext;
  if (!context?.email || !context?.challengeId || !context?.challenge) {
    set_mobile_signer_status("Challenge invalido.", true);
    return;
  }

  set_button_loading(
    btnApproveMobileChallenge,
    "Firmando...",
    "Firmar y aprobar acceso",
    true
  );
  try {
    const signature = await sign_challenge_with_local_key(context.email, context.challenge);
    await post_json("/auth/crypto/verify", {
      email: context.email,
      challengeId: context.challengeId,
      signature,
    });
    set_mobile_signer_status("Acceso aprobado. Regresa a tu laptop para completar el login.");
    toast("Firma enviada correctamente");
  } catch (err) {
    const msg = humanize_error(err, "No se pudo firmar/aprobar");
    set_mobile_signer_status(msg, true);
    toast(msg);
  } finally {
    set_button_loading(
      btnApproveMobileChallenge,
      "Firmando...",
      "Firmar y aprobar acceso",
      false
    );
  }
}

async function configure_mobile_key_on_this_device() {
  const context = mobileSetupContext;
  if (!context?.email || !context?.userId) {
    set_mobile_signer_status("No hay datos de configuracion en la URL.", true);
    return;
  }

  const idleLabel = "Generar llave y activar firma criptografica";
  set_button_loading(
    btnApproveMobileChallenge,
    "Configurando...",
    idleLabel,
    true
  );

  try {
    const keyRecord = await ensure_device_keypair(context.email, { forceRotate: true });
    const data = await patch_json(`/users/${context.userId}/methods/crypto-signature`, {
      habilitado: true,
      publicKeyPem: keyRecord.publicKeyPem,
    });
    set_mobile_signer_status("Firma activada en este celular. Regresa a tu laptop y actualiza el estado.");
    toast(data?.message || "Firma criptografica activada");
  } catch (err) {
    const msg = humanize_error(err, "No se pudo configurar firma en este celular");
    set_mobile_signer_status(msg, true);
    toast(msg);
  } finally {
    set_button_loading(
      btnApproveMobileChallenge,
      "Configurando...",
      idleLabel,
      false
    );
  }
}

async function handle_mobile_signer_action() {
  if (mobileSignerMode === "setup") {
    await configure_mobile_key_on_this_device();
    return;
  }
  await approve_mobile_challenge();
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
    show_otp_step(email);
    set_otp_delivery_hint(otpHint, null, "Creando cuenta y enviando codigo OTP...");
    set_button_loading(btnCreateAccount, "Creando...", "Crear cuenta", true);
    console.info("[signup] creando cuenta", { endpoint: `${API_BASE}/users/human`, email });
    
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

    const fallbackMessage = humanize_error(err, backend_connection_hint());
    if (signupEmail) {
      if (!is_signup_otp_step_active()) {
        show_otp_step(signupEmail);
      }

      set_otp_delivery_hint(
        otpHint,
        null,
        `${fallbackMessage} Usa 'Reenviar OTP' cuando el backend este disponible.`
      );
      toast(fallbackMessage);
      return;
    }

    show_signup_error(fallbackMessage);
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
    close_signup_otp(true);
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

  if (state.view === "methods") {
    const cryptoEnabled = Boolean(state?.methods?.cryptoAuthEnabled);
    const backendPublicKey = Boolean(state?.methods?.cryptoPublicKeyConfigured);
    const localPrivateKey = Boolean(state?.methods?.localPrivateKeyAvailable);
    const setupLink = String(state?.methods?.setupLink || "");
    const setupQrUrl = String(state?.methods?.setupQrUrl || "");
    const qrHostHint = mobile_qr_host_hint();
    const hostHintHtml = qrHostHint ? `<p class="muted small">${qrHostHint}</p>` : "";
    const hasSession = Boolean(currentUserEmail);
    const stateText = cryptoEnabled ? "Activo" : "Inactivo";
    const backendText = backendPublicKey ? "Configurada" : "No configurada";
    const localKeyText = localPrivateKey
      ? "Disponible en este dispositivo (recomendado eliminarla en laptop)"
      : "No encontrada en este dispositivo";
    const setupPanelHtml = setupLink ? `
      <hr />
      <h3>Configurar en celular</h3>
      <p>1) Escanea este QR con tu celular.</p>
      <img class="totp-qr" alt="QR configuracion firma en celular" src="${setupQrUrl}" />
      <p class="muted small">2) En el celular pulsa <b>Generar llave y activar firma criptografica</b>.</p>
      <p class="muted small">3) Vuelve aqui y presiona <b>Actualizar estado</b>.</p>
      ${hostHintHtml}
    ` : "";
    const localKeyActionHtml = localPrivateKey
      ? `<button class="ghost" id="btnClearLocalCryptoKey">Eliminar llave local de este dispositivo</button>`
      : "";

    detailEl.innerHTML = `
      <div class="detail-card">
        <h2>Metodo: Firma criptografica (celular + QR/challenge)</h2>
        <p>Este metodo usa <b>llave privada en tu celular/dispositivo</b> para firmar un challenge, y el backend valida con tu <b>llave publica</b>.</p>
        <ul>
          <li><b>Estado:</b> ${stateText}</li>
          <li><b>Llave publica en backend:</b> ${backendText}</li>
          <li><b>Llave privada local:</b> ${localKeyText}</li>
        </ul>
        <p class="muted">Este metodo debe configurarse desde celular. La laptop no debe conservar llave privada.</p>
        <div class="row">
          <button class="btn" id="btnEnableCryptoMethod" ${hasSession ? "" : "disabled"}>${cryptoEnabled ? "Reconfigurar en celular" : "Configurar en celular"}</button>
          <button class="ghost" id="btnRefreshMethodsState" ${hasSession ? "" : "disabled"}>Actualizar estado</button>
          <button class="ghost" id="btnDisableCryptoMethod" ${hasSession && cryptoEnabled ? "" : "disabled"}>Desactivar</button>
        </div>
        <div class="row">
          ${localKeyActionHtml}
        </div>
        <p class="muted small" id="methodsCryptoHint">${hasSession ? "Recomendado: abre este QR desde tu celular y configura ahi la llave privada." : "Inicia sesion para configurar este metodo."}</p>
        ${setupPanelHtml}
      </div>
    `;

    detailEl.querySelector("#btnEnableCryptoMethod")?.addEventListener("click", enable_crypto_signature_method);
    detailEl.querySelector("#btnRefreshMethodsState")?.addEventListener("click", () => {
      ensure_methods_context().finally(render);
    });
    detailEl.querySelector("#btnDisableCryptoMethod")?.addEventListener("click", disable_crypto_signature_method);
    detailEl.querySelector("#btnClearLocalCryptoKey")?.addEventListener("click", clear_local_crypto_key_for_current_device);
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

async function ensure_methods_context() {
  if (!state.methods) state.methods = {};
  const user = await fetch_current_user_profile();
  if (!user?.id) return null;

  const email = normalize_email(user.email || currentUserEmail);
  const localRecord = get_device_key_record(email);

  state.methods.userId = user.id;
  state.methods.email = email;
  state.methods.cryptoAuthEnabled = Boolean(user.cryptoAuthEnabled);
  state.methods.cryptoPublicKeyConfigured = Boolean(
    user.cryptoPublicKeyConfigured || user.cryptoPublicKeyPem
  );
  state.methods.localPrivateKeyAvailable = Boolean(localRecord?.privateKeyPkcs8B64);
  return user;
}

async function clear_local_crypto_key_for_current_device() {
  const user = await ensure_methods_context();
  if (!user?.email) return toast("No se pudo obtener el correo del usuario");
  clear_device_key_record(user.email);
  state.methods.localPrivateKeyAvailable = false;
  toast("Llave privada local eliminada de este dispositivo");
  render();
}

async function enable_crypto_signature_method() {
  if (!currentUserEmail) return toast("Debes iniciar sesion primero");
  const user = await ensure_methods_context();
  if (!user?.id) return toast("No se pudo cargar el usuario");

  const enableBtn = detailEl?.querySelector("#btnEnableCryptoMethod");
  const idleLabel = state?.methods?.cryptoAuthEnabled
    ? "Reconfigurar en celular"
    : "Configurar en celular";
  set_button_loading(enableBtn, "Preparando...", idleLabel, true);

  try {
    clear_device_key_record(user.email);
    state.methods.localPrivateKeyAvailable = false;
    state.methods.setupLink = build_mobile_setup_link({ email: user.email, userId: user.id });
    state.methods.setupQrUrl = get_qr_code_url(state.methods.setupLink, 260);
    const hostHint = mobile_qr_host_hint();
    toast(hostHint || "Escanea el QR con tu celular para generar la llave privada y activar firma criptografica");
    render();
  } catch (err) {
    toast(humanize_error(err, "No se pudo preparar la configuracion en celular"));
  } finally {
    set_button_loading(enableBtn, "Preparando...", idleLabel, false);
  }
}

async function disable_crypto_signature_method() {
  if (!currentUserEmail) return toast("Debes iniciar sesion primero");
  const user = await ensure_methods_context();
  if (!user?.id) return toast("No se pudo cargar el usuario");

  const disableBtn = detailEl?.querySelector("#btnDisableCryptoMethod");
  set_button_loading(disableBtn, "Desactivando...", "Desactivar", true);
  try {
    const data = await patch_json(`/users/${user.id}/methods/crypto-signature`, {
      habilitado: false,
    });
    toast(data?.message || "Firma criptografica desactivada");
    state.methods.setupLink = "";
    state.methods.setupQrUrl = "";
    await ensure_methods_context();
    render();
  } catch (err) {
    toast(humanize_error(err, "No se pudo desactivar firma criptografica"));
  } finally {
    set_button_loading(disableBtn, "Desactivando...", "Desactivar", false);
  }
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
  hide(mobileSignerApp);

  state.view = "ledger";
  navItems.forEach(n => n.classList.toggle("active", n.dataset.view === state.view));

  await ensure_security_context().catch(() => null);
  await ensure_methods_context().catch(() => null);
  await refresh_blockchain_panel().catch(() => {});
  render();
}

function go_to_landing() {
  show(landing);
  hide(dashboardApp);
  hide(mobileSignerApp);
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
btnCloseSignupOtp?.addEventListener("click", () => close_signup_otp());
signupOtpBackdrop?.addEventListener("click", (e) => e.target === signupOtpBackdrop && close_signup_otp());

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
btnCryptoLogin?.addEventListener("click", start_crypto_login);
btnCloseCryptoLogin?.addEventListener("click", close_crypto_login);
cryptoLoginBackdrop?.addEventListener("click", (e) => e.target === cryptoLoginBackdrop && close_crypto_login());
btnRefreshCryptoChallenge?.addEventListener("click", () => {
  const email = cryptoLoginSession?.email || normalize_email(liEmail?.value);
  if (!email) {
    toast("Ingresa un correo para generar challenge");
    return;
  }
  request_crypto_challenge_for_email(email).catch((err) => {
    const msg = humanize_error(err, "No se pudo regenerar challenge");
    set_crypto_status(msg, true);
    toast(msg);
  });
});
btnSignCryptoHere?.addEventListener("click", sign_current_challenge_here);
btnApproveMobileChallenge?.addEventListener("click", handle_mobile_signer_action);

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

    if (requiresEmailVerification || response_mentions_email_verification(data)) {
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
      response_mentions_email_verification(loginPayload)
      || loginDetail.includes("no está verificada")
      || (loginDetail.includes("verific") && loginDetail.includes("correo"))
      || loginDetail.includes("usuario no activo")
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

    if (state.view === "methods") {
      ensure_methods_context().finally(render);
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

  if (state.view === "security") {
    ensure_security_context().finally(render);
    return;
  }

  if (state.view === "methods") {
    ensure_methods_context().finally(render);
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
  close_signup_otp();
  close_login();
  close_login_otp();
  close_crypto_login();
});

// =========================
// Init
// =========================
state.items = load_items();
preload_login_identifier();
mobileSetupContext = parse_mobile_setup_context();
mobileSignerContext = parse_mobile_signer_context();
if (mobileSetupContext) {
  open_mobile_setup_mode(mobileSetupContext);
} else if (mobileSignerContext) {
  open_mobile_signer_mode(mobileSignerContext);
} else {
  go_to_landing();
}

void modalBackdrop;
void btnCompose;
void btnCloseModal;
void btnSendAction;
void actionTypeEl;
void actionDescEl;
