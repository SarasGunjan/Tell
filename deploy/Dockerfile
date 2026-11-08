# Tell web platform: FastAPI API + built Vite SPA. Build from repo root:
#   docker build -f deploy/Dockerfile -t tell .

# ---- Stage 1: build the frontend ----
FROM node:20-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# ---- Stage 2: runtime ----
FROM python:3.11-slim

WORKDIR /app

COPY deploy/requirements-web.txt /tmp/requirements-web.txt
RUN pip install --no-cache-dir -r /tmp/requirements-web.txt

# server.py resolves ROOT as parents[2] of src/api/server.py -> /app, so dist must be /app/web/dist
COPY src/__init__.py /app/src/__init__.py
COPY src/api/ /app/src/api/
COPY src/ai/ /app/src/ai/
COPY results/ /app/results/
# Member 2 Granite outputs: 2026 benchmark + historical research files (mvp_100 is excluded via .dockerignore)
COPY outputs/granite/ /app/outputs/granite/
COPY --from=web /web/dist /app/web/dist

# uid 1000: Hugging Face Spaces runs containers as this user
RUN useradd --no-create-home --uid 1000 tell \
    && mkdir -p /app/data \
    && chown -R tell /app
USER tell

ENV TELL_GRANITE_DIR=/app/outputs/granite \
    PYTHONPATH=/app \
    PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/status', timeout=4).status == 200 else 1)"]

CMD ["uvicorn", "src.api.server:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
