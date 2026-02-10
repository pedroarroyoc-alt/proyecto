// =========================
// Referencias HTML
// =========================
const landing = document.getElementById("landing");
const dashboardApp = document.getElementById("dashboardApp");

const btnEnter = document.getElementById("btnEnter");
const btnSignup = document.getElementById("btnSignup");
const btnAbout = document.getElementById("btnAbout");
const aboutBox = document.getElementById("aboutBox");

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

// ================
// Estado
// ================
const STORAGE_KEY = "cryptolock_items_v1";

const state = {
  view: "inbox",      // inbox | vault | methods | ledger
  query: "",
  selectedId: null,
  items: []
};

// =========================
// Helpers UI
// =========================
function show(el) {
  if (el) el.classList.remove("hidden");
}
function hide(el) {
  if (el) el.classList.add("hidden");
}
function set_active_nav(view) {
  navItems.forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.view === view);
  });
}
function open_modal() {
  if (modalBackdrop) modalBackdrop.classList.remove("hidden");
}
function close_modal() {
  if (modalBackdrop) modalBackdrop.classList.add("hidden");
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

  if (toastTimer) clearTimeout(toastTimer);

  toastTimer = setTimeout(() => {
    el.classList.remove("show");
  }, 1800);
}

// =========================
// Persistencia
// =========================
function default_items() {
  const now = new Date().toISOString();
  return [
    // inbox
    {
      id: "INB-1001",
      view: "inbox",
      title: "Login exitoso",
      subtitle: "Usuario Pedro • OTP",
      status: "OK",
      createdAt: now,
      body: "Inicio de sesión verificado con OTP. Se registró huella de auditoría."
    },
    {
      id: "INB-1002",
      view: "inbox",
      title: "Solicitud de acceso",
      subtitle: "Repo: proy • Rol: lectura",
      status: "PENDING",
      createdAt: now,
      body: "Solicitud de acceso al repositorio 'proy' con permisos de lectura."
    },

    // vault
    {
      id: "VLT-2001",
      view: "vault",
      title: "Clave generada (simulada)",
      subtitle: "KeyID: K-7F3A",
      status: "ACTIVE",
      createdAt: now,
      body: "Se generó un par de llaves. La privada permanece protegida en la bóveda."
    },

    // methods
    {
      id: "MTH-3001",
      view: "methods",
      title: "Método habilitado",
      subtitle: "OTP",
      status: "ENABLED",
      createdAt: now,
      body: "OTP habilitado para el usuario actual."
    },

    // ledger
    {
      id: "LED-4001",
      view: "ledger",
      title: "Bloque añadido",
      subtitle: "Hash: 0000ab...9f",
      status: "SEALED",
      createdAt: now,
      body: "Se añadió un bloque (simulado) con el evento de autenticación."
    }
  ];
}

function load_items() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return default_items();

    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed) || parsed.length === 0) return default_items();

    return parsed;
  } catch {
    return default_items();
  }
}

function save_items(items) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(items));
  } catch {
    // ignore
  }
}

function reset_demo_data() {
  state.items = default_items();
  save_items(state.items);
  toast("Datos recargados ✓");
  render();
}

// =========================
// Utilidades
// =========================
function format_date(iso) {
  try {
    const d = new Date(String(iso));
    if (Number.isNaN(d.getTime())) return String(iso);
    return d.toLocaleString();
  } catch {
    return String(iso);
  }
}

// =========================
// Pantallas
// =========================
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
// Filtros
// =========================
function items_for_view(view) {
  return state.items.filter((x) => x.view === view);
}

function apply_search(items, query) {
  const q = (query || "").trim().toLowerCase();
  if (!q) return items;

  return items.filter((x) => {
    const hay = `${x.id || ""} ${x.title || ""} ${x.subtitle || ""} ${x.status || ""} ${x.body || ""}`.toLowerCase();
    return hay.includes(q);
  });
}

// =========================
// Render: Lista
// =========================
function render_list(items) {
  if (!listEl) return;

  if (items.length === 0) {
    listEl.innerHTML = '<div class="empty">No hay resultados.</div>';
    return;
  }

  const html = items.map((item) => {
    const selected = item.id === state.selectedId ? "selected" : "";
    return `
      <button class="list-item ${selected}" data-id="${item.id}">
        <div class="li-top">
          <div class="li-title">${item.title || ""}</div>
          <div class="li-status">${item.status || ""}</div>
        </div>
        <div class="li-sub">${item.subtitle || ""}</div>
        <div class="li-meta">${format_date(item.createdAt || "")} • ${item.id || ""}</div>
      </button>
    `;
  });

  listEl.innerHTML = html.join("\n");

  // Click handlers
  listEl.querySelectorAll(".list-item").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.selectedId = btn.dataset.id;
      render();
    });
  });
}

// =========================
// Render: Detalle
// =========================
function update_status(iid, new_status) {
  state.items = state.items.map((x) => {
    if (x.id === iid) return { ...x, status: new_status };
    return x;
  });

  save_items(state.items);
  toast(`Estado: ${new_status}`);
  render();
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

  let actions_html = "";
  if (item.view === "inbox" && item.status === "PENDING") {
    actions_html = `
      <div class="detail-actions">
        <button class="btn" data-action="approve">Aprobar</button>
        <button class="btn btn-secondary" data-action="reject">Rechazar</button>
      </div>
    `;
  }

  detailEl.innerHTML = `
    <div class="detail-card">
      <div class="detail-head">
        <div>
          <div class="detail-title">${item.title || ""}</div>
          <div class="detail-sub">${item.subtitle || ""}</div>
        </div>
        <div class="detail-pill">${item.status || ""}</div>
      </div>

      <div class="detail-meta">
        <div><b>ID:</b> ${item.id || ""}</div>
        <div><b>Vista:</b> ${item.view || ""}</div>
        <div><b>Fecha:</b> ${format_date(item.createdAt || "")}</div>
      </div>

      <div class="detail-body">${item.body || "—"}</div>
      ${actions_html}
    </div>
  `;

  const btnApprove = detailEl.querySelector('[data-action="approve"]');
  const btnReject = detailEl.querySelector('[data-action="reject"]');

  if (btnApprove) btnApprove.addEventListener("click", () => update_status(item.id, "APPROVED"));
  if (btnReject) btnReject.addEventListener("click", () => update_status(item.id, "REJECTED"));
}

// =========================
// Render general
// =========================
function render() {
  set_active_nav(state.view);

  const base = items_for_view(state.view);
  const filtered = apply_search(base, state.query);

  if (!state.selectedId || !filtered.some((x) => x.id === state.selectedId)) {
    state.selectedId = filtered.length ? filtered[0].id : null;
  }

  render_list(filtered);

  const selected = filtered.find((x) => x.id === state.selectedId) || null;
  render_detail(selected);
}

// =========================
// Modal: crear item
// =========================
function handle_send_action() {
  const t = actionTypeEl ? actionTypeEl.value : "Solicitar acceso";
  const desc = actionDescEl ? actionDescEl.value : "";

  const t_lower = String(t).toLowerCase();

  let view, prefix, status;

  if (t_lower.includes("llave") || t_lower.includes("rotar")) {
    view = "vault"; prefix = "VLT"; status = "ACTIVE";
  } else if (t_lower.includes("dispositivo")) {
    view = "methods"; prefix = "MTH"; status = "ENABLED";
  } else if (t_lower.includes("reto") || t_lower.includes("challenge")) {
    view = "ledger"; prefix = "LED"; status = "SEALED";
  } else {
    view = "inbox"; prefix = "INB"; status = "PENDING";
  }

  const iid = `${prefix}-${Math.floor(1000 + Math.random() * 9000)}`;
  const now = new Date().toISOString();

  const item = {
    id: iid,
    view,
    title: String(t),
    subtitle: "Creado desde UI",
    status,
    createdAt: now,
    body: (desc || "").trim() || "Acción creada desde el modal."
  };

  state.items = [item, ...state.items];
  save_items(state.items);

  state.view = view;
  state.query = "";
  if (searchEl) searchEl.value = "";
  state.selectedId = iid;

  close_modal();
  render();
  toast("Creado ✓");
}

// =========================
// Listeners
// =========================
if (btnEnter) btnEnter.addEventListener("click", go_to_dashboard);

if (btnSignup) {
  btnSignup.addEventListener("click", () => {
    toast("Crear cuenta (demo): aquí irá el registro ✅");
    // Si quieres, puedes abrir tu modal actual para reutilizarlo:
    // open_modal();
  });
}

if (btnAbout) {
  btnAbout.addEventListener("click", () => {
    if (aboutBox) aboutBox.classList.toggle("hidden");
  });
}

// Navegación
navItems.forEach((btn) => {
  btn.addEventListener("click", () => {
    const view = btn.dataset.view;
    if (!view) return;

    state.view = view;
    state.query = "";
    if (searchEl) searchEl.value = "";
    state.selectedId = null;
    render();
  });
});

// Búsqueda
if (searchEl) {
  searchEl.addEventListener("input", (evt) => {
    state.query = evt.target.value || "";
    render();
  });
}

// Refresh
if (btnRefresh) btnRefresh.addEventListener("click", reset_demo_data);

// Modal
if (btnCompose) btnCompose.addEventListener("click", open_modal);
if (btnCloseModal) btnCloseModal.addEventListener("click", close_modal);

if (modalBackdrop) {
  modalBackdrop.addEventListener("click", (evt) => {
    if (evt.target === modalBackdrop) close_modal();
  });
}

if (btnSendAction) btnSendAction.addEventListener("click", handle_send_action);

// =========================
// Init
// =========================
state.items = load_items();
go_to_landing();
