"""FastAPI application and public-demo middleware."""

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import UUID

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.gzip import GZipMiddleware

from app.api.routes import router
from app.core.config import public_demo_enabled
from app.core.public_demo import (
    PUBLIC_MAX_CONTENT_BYTES,
    PUBLIC_RATE_LIMITED_PATHS,
    PUBLIC_SESSION_COOKIE,
    public_rate_limiter,
    sessions,
)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Run periodic cleanup for expired public demo sessions."""
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


def _set_security_headers(response: Response) -> None:
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")


async def _reject_oversized_public_request(request: Request) -> Response | None:
    """Return a limit response when a public request body exceeds the budget."""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            too_large = int(content_length) > PUBLIC_MAX_CONTENT_BYTES
        except ValueError:
            too_large = True
        if too_large:
            return JSONResponse({"detail": "Public demo requests are limited to 20 KB"}, status_code=413)
    if request.method in {"POST", "PUT", "PATCH"} and not content_length:
        body = await request.body()
        if len(body) > PUBLIC_MAX_CONTENT_BYTES:
            return JSONResponse({"detail": "Public demo requests are limited to 20 KB"}, status_code=413)
    return None


def _public_session(request: Request) -> tuple[str | None, bool]:
    """Resolve a public session and whether a replacement cookie is needed."""
    cookie_id = request.cookies.get(PUBLIC_SESSION_COOKIE)
    query_id = request.query_params.get("s")
    candidate = query_id if _valid_uuid(query_id) else cookie_id
    session = sessions.get(candidate)
    if session is None:
        session = sessions.get_or_create(candidate if _valid_uuid(candidate) else None)
    request.state.session_id = session.session_id
    return session.session_id, cookie_id != session.session_id

app = FastAPI(
    title="Bulkhead",
    version="0.1.0",
    description="Zero-trust policy gateway for AI-agent tool calls",
    lifespan=lifespan,
)
app.add_middleware(GZipMiddleware, minimum_size=1024)

STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.include_router(router)


@app.middleware("http")
async def public_security_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """Apply public limits, session cookies, and baseline security headers."""
    public = public_demo_enabled()
    session_id: str | None = None
    set_session_cookie = False
    session_required = request.url.path not in {"/health", "/healthz", "/api/health"} and not request.url.path.startswith("/static")
    if public and session_required:
        session_id, set_session_cookie = _public_session(request)

        if (request.method, request.url.path) in PUBLIC_RATE_LIMITED_PATHS:
            client_ip = request.client.host if request.client else "unknown"
            if not public_rate_limiter.allow(f"session:{session_id}", f"ip:{client_ip}"):
                limited_response: Response = JSONResponse(
                    {"detail": "Public demo rate limit exceeded"}, status_code=429
                )
                _set_security_headers(limited_response)
                return limited_response
            oversized_response = await _reject_oversized_public_request(request)
            if oversized_response is not None:
                _set_security_headers(oversized_response)
                return oversized_response

    response = await call_next(request)
    _set_security_headers(response)
    if request.url.path in {"/", "/static/index.html"}:
        response.headers["Cache-Control"] = "no-cache"
    elif request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
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
    """Serve the dashboard shell."""
    return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-cache"})


@app.get("/health")
@app.get("/healthz")
@app.get("/api/health", include_in_schema=False)
def health() -> dict[str, str]:
    """Return the service health status."""
    return {"status": "ok", "service": "bulkhead"}


def serve() -> None:
    """Run the Bulkhead HTTP server using environment-configured defaults."""
    import os

    uvicorn.run(
        "app.main:app",
        host=os.environ.get("BULKHEAD_HOST", "0.0.0.0"),
        port=int(os.environ.get("BULKHEAD_PORT", os.environ.get("PORT", "8000"))),
    )
