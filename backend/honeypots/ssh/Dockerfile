FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy necessary database, services, schemas, and honeypot files keeping exact package structure
COPY backend/database /app/backend/database
COPY backend/services/__init__.py /app/backend/services/__init__.py
COPY backend/services/geoip_service.py /app/backend/services/geoip_service.py
COPY backend/services/origin_auth.py /app/backend/services/origin_auth.py
COPY backend/services/catastrophic_loss.py /app/backend/services/catastrophic_loss.py
COPY backend/schemas /app/backend/schemas
COPY backend/honeypots/__init__.py /app/backend/honeypots/__init__.py
COPY backend/honeypots/credential_sanitizer.py /app/backend/honeypots/credential_sanitizer.py
COPY backend/honeypots/db_logger.py /app/backend/honeypots/db_logger.py
COPY backend/honeypots/event_dispatcher.py /app/backend/honeypots/event_dispatcher.py
COPY backend/honeypots/spooler.py /app/backend/honeypots/spooler.py
COPY backend/honeypots/ssh /app/backend/honeypots/ssh

EXPOSE 2222
ENV PYTHONPATH=/app/backend

# Create unprivileged non-root user
RUN groupadd -g 10001 honeypot && useradd -m -u 10001 -g 10001 honeypot && \
    mkdir -p /app/backend/logs && chown -R honeypot:honeypot /app

USER 10001:10001

CMD ["python", "backend/honeypots/ssh/async_ssh_honeypot.py"]
