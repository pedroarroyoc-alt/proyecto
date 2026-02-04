// --- Landing controls ---
const landing = document.getElementById("landing");
const dashboardApp = document.getElementById("dashboardApp");
const btnEnter = document.getElementById("btnEnter");
const btnAbout = document.getElementById("btnAbout");
const aboutBox = document.getElementById("aboutBox");

// Referencias HTML (dashboard)
const listEl = document.getElementById("list");
const detailEl = document.getElementById("detail");
const searchEl = document.getElementById("search");

const modalBackdrop = document.getElementById("modalBackdrop");
const btnCompose = document.getElementById("btnCompose");
const btnCloseModal = document.getElementById("btnCloseModal");
const btnSendAction = document.getElementById("btnSendAction");

const navItems = document.querySelectorAll(".nav-item");

// Modal helpers (con protección)
function openModal() {
  if (!modalBackdrop) return;
  modalBackdrop.classList.remove("hidden");
}
function closeModal() {
  if (!modalBackdrop) return;
  modalBackdrop.classList.add("hidden");
}

// ✅ Asegura que el modal arranque cerrado SIEMPRE
closeModal();

// ✅ Cierra modal con ESC (opcional pero útil)
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeModal();
});

if (btnEnter) {
  btnEnter.addEventListener("click", () => {
    // Al entrar al dashboard, cerrar modal por si estaba abierto
    closeModal();

    if (landing) landing.classList.add("hidden");
    if (dashboardApp) dashboardApp.classList.remove("hidden");
  });
}

if (btnAbout) {
  btnAbout.addEventListener("click", () => {
    if (!aboutBox) return;
    const isOpen = aboutBox.style.display === "block";
    aboutBox.style.display = isOpen ? "none" : "block";
  });
}

// Datos simulados (esto reemplaza al backend por ahora)
const events = [
  {
    id: 1,
    title: "Login exitoso con firma",
    user: "pedro@cryptolock.pe",
    method: "Firma",
    status: "Éxito",
    date: "2026-02-03 20:40",
    ip: "190.12.10.22",
    device: "Chrome / Windows",
    detail: "El usuario completó autenticación passwordless mediante firma digital.",
    hash_event: "a9f3c2...e12",
  },
  {
    id: 2,
    title: "OTP fallido (3 intentos)",
    user: "pedro@cryptolock.pe",
    method: "OTP",
    status: "Fallido",
    date: "2026-02-03 20:31",
    ip: "190.12.10.22",
    device: "Chrome / Windows",
    detail: "Se detectaron múltiples intentos de OTP incorrectos.",
    hash_event: "b2d8aa...91f",
  },
  {
    id: 3,
    title: "Intento de intrusión: firma inválida",
    user: "unknown",
    method: "Firma",
    status: "Bloqueado",
    date: "2026-02-03 20:10",
    ip: "201.44.88.19",
    device: "Firefox / Linux",
    detail: "La firma no coincide con la clave pública registrada. Acceso bloqueado.",
    hash_event: "c0a11f...7ad",
  },
  {
    id: 4,
    title: "Biometría simulada aprobada",
    user: "ana@cryptolock.pe",
    method: "Biometría",
    status: "Éxito",
    date: "2026-02-03 19:58",
    ip: "186.55.2.90",
    device: "Edge / Windows",
    detail: "Verificación biométrica simulada aprobada según política configurada.",
    hash_event: "d9b700...2c1",
  },
];

let selectedId = null;

// Render de lista (Inbox)
function renderList(filter = "") {
  if (!listEl) return;

  listEl.innerHTML = "";
  const q = filter.trim().toLowerCase();

  const filtered = events.filter((e) =>
    (e.title + " " + e.user + " " + e.method + " " + e.status)
      .toLowerCase()
      .includes(q)
  );

  filtered.forEach((e) => {
    const item = document.createElement("div");
    item.className = "item" + (e.id === selectedId ? " active" : "");
    item.onclick = () => selectEvent(e.id);

    item.innerHTML = `
      <div class="item-top">
        <div class="item-title">${e.title}</div>
        <div class="item-date">${e.date}</div>
      </div>
      <div class="item-sub">
        <span class="badge">${e.method}</span>
        <span class="badge">${e.status}</span>
        ${e.user}
      </div>
    `;

    listEl.appendChild(item);
  });

  if (filtered.length === 0) {
    listEl.innerHTML = `<div class="detail-empty">
      <div class="big">🔎</div>
      <h2>No hay resultados</h2>
      <p>Prueba con otro texto en el buscador.</p>
    </div>`;
  }
}

// Render detalle
function selectEvent(id) {
  selectedId = id;
  if (searchEl) renderList(searchEl.value);

  const e = events.find((x) => x.id === id);
  if (!e || !detailEl) return;

  detailEl.innerHTML = `
    <h2>${e.title}</h2>
    <div>
      <span class="badge">${e.method}</span>
      <span class="badge">${e.status}</span>
      <span class="badge">hash: ${e.hash_event}</span>
    </div>

    <p style="margin-top:12px; color:#333;">${e.detail}</p>

    <div class="kv">
      <div class="kv-row"><div>Usuario</div><div>${e.user}</div></div>
      <div class="kv-row"><div>Fecha</div><div>${e.date}</div></div>
      <div class="kv-row"><div>IP</div><div>${e.ip}</div></div>
      <div class="kv-row"><div>Dispositivo</div><div>${e.device}</div></div>
    </div>
  `;
}

// Eventos del modal
if (btnCompose) btnCompose.addEventListener("click", openModal);
if (btnCloseModal) btnCloseModal.addEventListener("click", closeModal);

if (modalBackdrop) {
  modalBackdrop.addEventListener("click", (ev) => {
    if (ev.target === modalBackdrop) closeModal();
  });
}

if (btnSendAction) {
  btnSendAction.addEventListener("click", () => {
    const typeEl = document.getElementById("actionType");
    const descEl = document.getElementById("actionDesc");
    if (!typeEl || !descEl) return;

    const type = typeEl.value;
    const desc = descEl.value.trim() || "(sin descripción)";

    const now = new Date();
    const pad = (n) => String(n).padStart(2, "0");
    const dateStr = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(
      now.getDate()
    )} ${pad(now.getHours())}:${pad(now.getMinutes())}`;

    const newEvent = {
      id: Math.max(...events.map((x) => x.id)) + 1,
      title: `Acción creada: ${type}`,
      user: "pedro@cryptolock.pe",
      method: "UI",
      status: "Pendiente",
      date: dateStr, // ✅ ahora sí usa hora actual
      ip: "local",
      device: "UI Mock",
      detail: `Acción registrada desde la interfaz: ${desc}`,
      hash_event: "mock...hash",
    };

    events.unshift(newEvent);
    descEl.value = "";

    closeModal(); // ✅ cierra SIEMPRE
    renderList(searchEl ? searchEl.value : "");
  });
}

// Buscador
if (searchEl) {
  searchEl.addEventListener("input", () => renderList(searchEl.value));
}

// Navegación (cambia el panel derecho solo por UI)
navItems.forEach((btn) => {
  btn.addEventListener("click", () => {
    // ✅ Si cambias de vista, cierra el modal para que no tape todo
    closeModal();

    navItems.forEach((x) => x.classList.remove("active"));
    btn.classList.add("active");

    const view = btn.dataset.view;
    selectedId = null;
    if (searchEl) searchEl.value = "";

    if (view === "inbox") {
      renderList("");
      if (detailEl) {
        detailEl.innerHTML = `<div class="detail-empty">
          <div class="big">📩</div>
          <h2>Bandeja de eventos</h2>
          <p>Selecciona un evento para ver detalles.</p>
        </div>`;
      }
    }

    if (view === "vault") {
      if (listEl) {
        listEl.innerHTML = `<div class="detail-empty">
          <div class="big">🗝️</div>
          <h2>Bóveda de llaves</h2>
          <p>Vista simulada (la clave privada nunca se muestra).</p>
        </div>`;
      }
      if (detailEl) {
        detailEl.innerHTML = `
          <h2>Bóveda de llaves</h2>
          <div class="kv">
            <div class="kv-row"><div>Clave pública</div><div>-----BEGIN PUBLIC KEY----- ...</div></div>
            <div class="kv-row"><div>Clave privada</div><div>🔒 Protegida (no accesible)</div></div>
            <div class="kv-row"><div>Estado</div><div>Encapsulada para firma digital</div></div>
          </div>`;
      }
    }

    if (view === "methods") {
      if (listEl) {
        listEl.innerHTML = `<div class="detail-empty">
          <div class="big">✅</div>
          <h2>Métodos</h2>
          <p>Activa o desactiva métodos (simulado).</p>
        </div>`;
      }
      if (detailEl) {
        detailEl.innerHTML = `
          <h2>Métodos de autenticación</h2>
          <div class="kv">
            <div class="kv-row"><div>Firma</div><div>🟢 Activo</div></div>
            <div class="kv-row"><div>OTP</div><div>🟡 Disponible</div></div>
            <div class="kv-row"><div>Biometría</div><div>🟡 Disponible</div></div>
          </div>`;
      }
    }

    if (view === "ledger") {
      if (listEl) {
        listEl.innerHTML = `<div class="detail-empty">
          <div class="big">⛓️</div>
          <h2>Ledger</h2>
          <p>Lista de bloques (simulada).</p>
        </div>`;
      }
      if (detailEl) {
        detailEl.innerHTML = `
          <h2>Blockchain de auditoría</h2>
          <div class="kv">
            <div class="kv-row"><div>Bloque #0</div><div>hash: 0000...genesis</div></div>
            <div class="kv-row"><div>Bloque #1</div><div>hash: 9ab1... prev: 0000...</div></div>
            <div class="kv-row"><div>Bloque #2</div><div>hash: 4c88... prev: 9ab1...</div></div>
          </div>
          <p style="margin-top:12px;color:#333;">(Tus compañeros luego reemplazan esto con datos reales.)</p>`;
      }
    }
  });
});

// Inicial (solo pinta la lista cuando estás en dashboard)
renderList("");
