# ~/netguard/api/main.py

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# 1) crie o app primeiro
app = FastAPI(title="NetGuard API")

# 2) só depois configure o middleware/routers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # ajuste se precisar restringir
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3) (opcional) healthcheck para testar rápido
@app.get("/health")
def health():
    return {"status": "ok"}
