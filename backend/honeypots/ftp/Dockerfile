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
COPY backend/honeypots/ftp /app/backend/honeypots/ftp

EXPOSE 2121
ENV PYTHONPATH=/app/backend

CMD ["python", "backend/honeypots/ftp/ftp_honeypot.py"]
