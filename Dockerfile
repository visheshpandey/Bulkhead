FROM python:3.11.9-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

LABEL org.opencontainers.image.title="Bulkhead"

COPY requirements.lock ./
RUN python -m pip install --no-cache-dir --requirement requirements.lock

COPY app ./app
COPY pyproject.toml ./
RUN python -m pip install --no-cache-dir --no-deps --no-build-isolation --editable .

RUN addgroup --system bulkhead && adduser --system --ingroup bulkhead bulkhead

COPY tests ./tests
COPY docs ./docs
COPY examples ./examples
COPY README.md .env.example ./

RUN mkdir -p /app/data && chown -R bulkhead:bulkhead /app
USER bulkhead

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('PORT', '8000') + '/healthz')"

CMD ["sh", "-c", "python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
