# CodeGrey SOC Server - Production Dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs database

# Set environment variables
ENV SOC_HOST=0.0.0.0
ENV SOC_PORT=443
ENV SOC_DEBUG=false
ENV PYTHONPATH=/app

# Expose port
EXPOSE 443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('https://localhost:443/api/system/status')" || exit 1

# Run the application
CMD ["python", "app.py"]



