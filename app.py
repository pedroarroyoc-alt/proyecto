from pyscript import window, document
from pyscript.ffi import create_proxy
import json
import random
from datetime import datetime

# =========================
# Referencias HTML
# =========================
landing = document.getElementById("landing")
dashboardApp = document.getElementById("dashboardApp")

btnEnter = document.getElementById("btnEnter")
btnAbout = document.getElementById("btnAbout")
aboutBox = document.getElementById("aboutBox")

listEl = document.getElementById("list")
detailEl = document.getElementById("detail")
searchEl = document.getElementById("search")

btnRefresh = document.getElementById("btnRefresh")

modalBackdrop = document.getElementById("modalBackdrop")
btnCompose = document.getElementById("btnCompose")
btnCloseModal = document.getElementById("btnCloseModal")
btnSendAction = document.getElementById("btnSendAction")

actionTypeEl = document.getElementById("actionType")
actionDescEl = document.getElementById("actionDesc")

navItems = document.querySelectorAll(".nav-item")

# ================
# Estado
# ================
STORAGE_KEY = "cryptolock_items_v1"

state = {
    "view": "inbox",     # inbox | vault | methods | ledger
    "query": "",
    "selectedId": None,
    "items": []
}

# =========================
# Helpers UI
# =========================
def show(el):
    if el:
        el.classList.remove("hidden")

def hide(el):
    if el:
        el.classList.add("hidden")

def set_active_nav(view):
    for i in range(navItems.length):
        btn = navItems.item(i)
        btn.classList.toggle("active", btn.dataset.view == view)

def open_modal():
    if modalBackdrop:
        modalBackdrop.classList.remove("hidden")

def close_modal():
    if modalBackdrop:
        modalBackdrop.classList.add("hidden")

# =========================
# Toast
# =========================
toast_timer = {"id": None}

def toast(msg):
    el = document.getElementById("toast")
    if not el:
        return
    el.textContent = msg
    el.classList.add("show")

    if toast_timer["id"] is not None:
        window.clearTimeout(toast_timer["id"])

    def _hide():
        el.classList.remove("show")

    toast_timer["id"] = window.setTimeout(create_proxy(lambda *_: _hide()), 1800)

# =========================
# Persistencia
# =========================
def default_items():
    now = datetime.now().isoformat()
    return [
        # inbox
        {
            "id": "INB-1001",
            "view": "inbox",
            "title": "Login exitoso",
            "subtitle": "Usuario Pedro • OTP",
            "status": "OK",
            "createdAt": now,
            "body": "Inicio de sesión verificado con OTP. Se registró huella de auditoría."
        },
        {
            "id": "INB-1002",
            "view": "inbox",
            "title": "Solicitud de acceso",
            "subtitle": "Repo: proy • Rol: lectura",
            "status": "PENDING",
            "createdAt": now,
            "body": "Solicitud de acceso al repositorio 'proy' con permisos de lectura."
        },

        # vault
        {
            "id": "VLT-2001",
            "view": "vault",
            "title": "Clave generada (simulada)",
            "subtitle": "KeyID: K-7F3A",
            "status": "ACTIVE",
            "createdAt": now,
            "body": "Se generó un par de llaves. La privada permanece protegida en la bóveda."
        },

        # methods
        {
            "id": "MTH-3001",
            "view": "methods",
            "title": "Método habilitado",
            "subtitle": "OTP",
            "status": "ENABLED",
            "createdAt": now,
            "body": "OTP habilitado para el usuario actual."
        },

        # ledger (blockchain/auditoría)
        {
            "id": "LED-4001",
            "view": "ledger",
            "title": "Bloque añadido",
            "subtitle": "Hash: 0000ab...9f",
            "status": "SEALED",
            "createdAt": now,
            "body": "Se añadió un bloque (simulado) con el evento de autenticación."
        },
    ]

def load_items():
    try:
        raw = window.localStorage.getItem(STORAGE_KEY)
        if not raw:
            return default_items()
        parsed = json.loads(raw)
        if not isinstance(parsed, list) or len(parsed) == 0:
            return default_items()
        return parsed
    except Exception:
        return default_items()

def save_items(items):
    try:
        window.localStorage.setItem(STORAGE_KEY, json.dumps(items))
    except Exception:
        pass

def reset_demo_data():
    state["items"] = default_items()
    save_items(state["items"])
    toast("Datos recargados ✓")
    render()

# =========================
# Utilidades
# =========================
def format_date(iso):
    try:
        d = window.Date.new(iso)
        if window.Number.isNaN(d.getTime()):
            return str(iso)
        return d.toLocaleString()
    except Exception:
        return str(iso)

# =========================
# Pantallas
# =========================
def go_to_dashboard():
    hide(landing)
    show(dashboardApp)
    render()

def go_to_landing():
    show(landing)
    hide(dashboardApp)

# =========================
# Filtros
# =========================
def items_for_view(view):
    return [x for x in state["items"] if x.get("view") == view]

def apply_search(items, query):
    q = (query or "").strip().lower()
    if not q:
        return items

    out = []
    for x in items:
        hay = f"{x.get('id','')} {x.get('title','')} {x.get('subtitle','')} {x.get('status','')} {x.get('body','')}".lower()
        if q in hay:
            out.append(x)
    return out

# =========================
# Render: Lista
# =========================
def render_list(items):
    if not listEl:
        return

    if len(items) == 0:
        listEl.innerHTML = '<div class="empty">No hay resultados.</div>'
        return

    html = []
    for item in items:
        selected = "selected" if item["id"] == state["selectedId"] else ""
        html.append(f"""
          <button class="list-item {selected}" data-id="{item['id']}">
            <div class="li-top">
              <div class="li-title">{item.get('title','')}</div>
              <div class="li-status">{item.get('status','')}</div>
            </div>
            <div class="li-sub">{item.get('subtitle','')}</div>
            <div class="li-meta">{format_date(item.get('createdAt',''))} • {item.get('id','')}</div>
          </button>
        """)

    listEl.innerHTML = "\n".join(html)

    # Click handlers
    btns = listEl.querySelectorAll(".list-item")
    for i in range(btns.length):
        btn = btns.item(i)

        def on_click(evt, _btn=btn):
            state["selectedId"] = _btn.dataset.id
            render()

        btn.addEventListener("click", create_proxy(on_click))

# =========================
# Render: Detalle
# =========================
def render_detail(item):
    if not detailEl:
        return

    if not item:
        detailEl.innerHTML = """
          <div class="detail-empty">
            <div class="big">📩</div>
            <h2>Selecciona un evento</h2>
            <p>Haz click en un elemento de la lista para ver el detalle.</p>
          </div>
        """
        return

    # Acciones solo para inbox (simular aprobar / rechazar solicitud)
    actions_html = ""
    if item.get("view") == "inbox" and item.get("status") == "PENDING":
        actions_html = """
          <div class="detail-actions">
            <button class="btn" data-action="approve">Aprobar</button>
            <button class="btn btn-secondary" data-action="reject">Rechazar</button>
          </div>
        """

    detailEl.innerHTML = f"""
      <div class="detail-card">
        <div class="detail-head">
          <div>
            <div class="detail-title">{item.get('title','')}</div>
            <div class="detail-sub">{item.get('subtitle','')}</div>
          </div>
          <div class="detail-pill">{item.get('status','')}</div>
        </div>

        <div class="detail-meta">
          <div><b>ID:</b> {item.get('id','')}</div>
          <div><b>Vista:</b> {item.get('view','')}</div>
          <div><b>Fecha:</b> {format_date(item.get('createdAt',''))}</div>
        </div>

        <div class="detail-body">{item.get('body') or '—'}</div>
        {actions_html}
      </div>
    """

    btnApprove = detailEl.querySelector('[data-action="approve"]')
    btnReject = detailEl.querySelector('[data-action="reject"]')

    if btnApprove:
        btnApprove.addEventListener("click", create_proxy(lambda e: update_status(item["id"], "APPROVED")))
    if btnReject:
        btnReject.addEventListener("click", create_proxy(lambda e: update_status(item["id"], "REJECTED")))

def update_status(iid, new_status):
    updated = []
    for x in state["items"]:
        if x.get("id") == iid:
            y = dict(x)
            y["status"] = new_status
            updated.append(y)
        else:
            updated.append(x)

    state["items"] = updated
    save_items(state["items"])
    toast(f"Estado: {new_status}")
    render()

# =========================
# Render general
# =========================
def render():
    set_active_nav(state["view"])

    base = items_for_view(state["view"])
    filtered = apply_search(base, state["query"])

    if (not state["selectedId"]) or (not any(x.get("id") == state["selectedId"] for x in filtered)):
        state["selectedId"] = filtered[0]["id"] if len(filtered) else None

    render_list(filtered)

    selected = None
    for x in filtered:
        if x.get("id") == state["selectedId"]:
            selected = x
            break

    render_detail(selected)

# =========================
# Modal: crear item
# =========================
def handle_send_action(evt=None):
    t = actionTypeEl.value if actionTypeEl else "Solicitar acceso"
    desc = actionDescEl.value if actionDescEl else ""

    # Mapea tipo -> vista
    t_lower = str(t).lower()
    if "llave" in t_lower or "rotar" in t_lower:
        view = "vault"
        prefix = "VLT"
        status = "ACTIVE"
    elif "dispositivo" in t_lower:
        view = "methods"
        prefix = "MTH"
        status = "ENABLED"
    elif "reto" in t_lower or "challenge" in t_lower:
        view = "ledger"
        prefix = "LED"
        status = "SEALED"
    else:
        view = "inbox"
        prefix = "INB"
        status = "PENDING"

    iid = f"{prefix}-{random.randint(1000, 9999)}"
    now = datetime.now().isoformat()

    item = {
        "id": iid,
        "view": view,
        "title": str(t),
        "subtitle": "Creado desde UI",
        "status": status,
        "createdAt": now,
        "body": desc.strip() or "Acción creada desde el modal."
    }

    state["items"] = [item] + state["items"]
    save_items(state["items"])

    state["view"] = view
    state["query"] = ""
    if searchEl:
        searchEl.value = ""
    state["selectedId"] = iid

    close_modal()
    render()
    toast("Creado ✓")

# =========================
# Listeners
# =========================
if btnEnter:
    btnEnter.addEventListener("click", create_proxy(lambda e: go_to_dashboard()))

if btnAbout:
    def toggle_about(_):
        if aboutBox:
            aboutBox.classList.toggle("hidden")
    btnAbout.addEventListener("click", create_proxy(toggle_about))

# Navegación
for i in range(navItems.length):
    btn = navItems.item(i)

    def on_nav_click(evt, _btn=btn):
        view = _btn.dataset.view
        if not view:
            return
        state["view"] = view
        state["query"] = ""
        if searchEl:
            searchEl.value = ""
        state["selectedId"] = None
        render()

    btn.addEventListener("click", create_proxy(on_nav_click))

# Búsqueda
if searchEl:
    def on_search(evt):
        state["query"] = evt.target.value or ""
        render()
    searchEl.addEventListener("input", create_proxy(on_search))

# Refresh
if btnRefresh:
    btnRefresh.addEventListener("click", create_proxy(lambda e: reset_demo_data()))

# Modal
if btnCompose:
    btnCompose.addEventListener("click", create_proxy(lambda e: open_modal()))
if btnCloseModal:
    btnCloseModal.addEventListener("click", create_proxy(lambda e: close_modal()))
if modalBackdrop:
    def on_backdrop_click(evt):
        if evt.target == modalBackdrop:
            close_modal()
    modalBackdrop.addEventListener("click", create_proxy(on_backdrop_click))
if btnSendAction:
    btnSendAction.addEventListener("click", create_proxy(handle_send_action))

# =========================
# Init
# =========================
state["items"] = load_items()
go_to_landing()