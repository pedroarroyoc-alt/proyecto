from dotenv import load_dotenv
load_dotenv(".env")

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.users import router as users_router
from api.auth import router as auth_router

# ✅ Primero creamos la app
app = FastAPI(title="CryptoLock Backend", version="0.1.0")

# ✅ Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Health check
@app.get("/health")
def health():
    return {"ok": True, "service": "cryptolock-api"}

# ✅ Luego incluimos los routers
app.include_router(users_router)
app.include_router(auth_router)
