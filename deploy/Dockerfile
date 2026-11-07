# Tell Platform - Vultr Cloud Deployment Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (build-essential, git, libgomp1 for lightgbm)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python packages
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source, models, results, and docs
COPY src/ /app/src/
COPY results/ /app/results/
COPY models/ /app/models/
COPY docs/ /app/docs/
COPY README.md /app/README.md

# Set environment
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_HEADLESS=true

EXPOSE 8501

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Start Streamlit application
CMD ["streamlit", "run", "src/dashboard/app.py"]
