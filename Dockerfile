FROM python:3.11.9-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

COPY requirements.lock pyproject.toml README.md LICENSE ./
COPY app ./app

RUN python -m pip install --no-cache-dir --requirement requirements.lock \
    && python -m pip wheel --no-cache-dir --no-deps --no-build-isolation --wheel-dir /wheels .

FROM python:3.11.9-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

LABEL org.opencontainers.image.title="Bulkhead"
LABEL org.opencontainers.image.description="Zero-trust policy gateway for AI-agent tool calls"

COPY requirements.lock ./
RUN python -m venv /opt/venv \
    && /opt/venv/bin/python -m pip install --no-cache-dir --requirement requirements.lock
COPY --from=builder /wheels /wheels
RUN /opt/venv/bin/python -m pip install --no-cache-dir --no-index /wheels/*.whl \
    && rm -rf /wheels requirements.lock

RUN addgroup --system bulkhead && adduser --system --ingroup bulkhead bulkhead \
    && mkdir -p /app/data \
    && chown -R bulkhead:bulkhead /app /opt/venv

USER bulkhead

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('PORT', '8000') + '/healthz', timeout=4)"

CMD ["sh", "-c", "python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
