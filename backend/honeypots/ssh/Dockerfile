FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy necessary database, services, and honeypot files keeping exact package structure
COPY backend/database /app/backend/database
COPY backend/services/geo.py /app/backend/services/geo.py
COPY backend/services/geoip_service.py /app/backend/services/geoip_service.py
COPY backend/honeypots/db_logger.py /app/backend/honeypots/db_logger.py
COPY backend/honeypots/ssh /app/backend/honeypots/ssh

EXPOSE 2222
ENV PYTHONPATH=/app/backend

CMD ["python", "backend/honeypots/ssh/ssh_honeypot.py"]
