from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router

app = FastAPI(
    title="AIRLOCK",
    version="0.1.0",
    description="A zero-trust gateway for AI-agent actions.",
)

STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.include_router(router)


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
@app.get("/api/health", include_in_schema=False)
def health() -> dict[str, str]:
    return {"status": "ok", "service": "airlock"}
