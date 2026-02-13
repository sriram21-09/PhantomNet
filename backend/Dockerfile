FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (needed for Scapy/ML)
RUN apt-get update && apt-get install -y build-essential libpcap-dev && rm -rf /var/lib/apt/lists/*

# Copy backend files
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt || echo "Requirements skipped"

EXPOSE 8000

# ✅ CHANGED: Explicitly start Uvicorn server
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
