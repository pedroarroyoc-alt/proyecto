from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.users import router as users_router

app = FastAPI(title="CryptoLock Backend", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    return {"ok": True, "service": "cryptolock-api"}

# ✅ unir rutas de usuarios
app.include_router(users_router)
