import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import UUID

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.core.config import public_demo_enabled
from app.core.public_demo import (
    PUBLIC_MAX_CONTENT_BYTES,
    PUBLIC_SESSION_COOKIE,
    public_rate_limiter,
    sessions,
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    async def cleanup_loop() -> None:
        while True:
            await asyncio.sleep(300)
            sessions.cleanup()

    task = asyncio.create_task(cleanup_loop())
    try:
        yield
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


def _valid_uuid(value: str | None) -> bool:
    try:
        UUID(value or "")
    except (ValueError, TypeError, AttributeError):
        return False
    return True


def _set_security_headers(response) -> None:
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")

app = FastAPI(
    title="Bulkhead",
    version="0.1.0",
    description="Zero-trust policy gateway for AI-agent tool calls",
    lifespan=lifespan,
)

STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.include_router(router)


@app.middleware("http")
async def public_security_middleware(request: Request, call_next):
    public = public_demo_enabled()
    session_id: str | None = None
    set_session_cookie = False
    session_required = request.url.path not in {"/health", "/healthz", "/api/health"} and not request.url.path.startswith("/static")
    if public and session_required:
        cookie_id = request.cookies.get(PUBLIC_SESSION_COOKIE)
        query_id = request.query_params.get("s")
        candidate = query_id if _valid_uuid(query_id) else cookie_id
        session = sessions.get(candidate)
        if session is None:
            session = sessions.get_or_create(candidate if _valid_uuid(candidate) else None)
        session_id = session.session_id
        set_session_cookie = cookie_id != session_id
        request.state.session_id = session_id

        if request.url.path not in {"/health", "/healthz", "/api/health"} and not request.url.path.startswith("/static"):
            client_ip = request.client.host if request.client else "unknown"
            if not public_rate_limiter.allow(f"session:{session_id}", f"ip:{client_ip}"):
                response = JSONResponse({"detail": "Public demo rate limit exceeded"}, status_code=429)
                _set_security_headers(response)
                return response
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    too_large = int(content_length) > PUBLIC_MAX_CONTENT_BYTES
                except ValueError:
                    too_large = True
                if too_large:
                    response = JSONResponse({"detail": "Public demo requests are limited to 20 KB"}, status_code=413)
                    _set_security_headers(response)
                    return response
            if request.method in {"POST", "PUT", "PATCH"} and not content_length:
                body = await request.body()
                if len(body) > PUBLIC_MAX_CONTENT_BYTES:
                    response = JSONResponse({"detail": "Public demo requests are limited to 20 KB"}, status_code=413)
                    _set_security_headers(response)
                    return response

    response = await call_next(request)
    _set_security_headers(response)
    if public and session_required and session_id and set_session_cookie:
        response.set_cookie(
            PUBLIC_SESSION_COOKIE,
            session_id,
            max_age=7200,
            httponly=True,
            samesite="lax",
            secure=request.url.scheme == "https",
            path="/",
        )
    return response


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
@app.get("/healthz")
@app.get("/api/health", include_in_schema=False)
def health() -> dict[str, str]:
    return {"status": "ok", "service": "bulkhead"}
