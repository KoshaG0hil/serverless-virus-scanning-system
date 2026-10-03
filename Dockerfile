# ==============================================================================
# Google Cloud Run ClamAV Malware Scanning Microservice
# ==============================================================================
FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8080

# Install ClamAV, daemon, freshclam updater, and system utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Initial virus signature database update
RUN freshclam --quiet || true

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and entrypoint
COPY src/ /app/src/
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Run as non-root where possible, or use entrypoint to start clamd & gunicorn
EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
