FROM python:3.11-slim

WORKDIR /app

COPY http_honeypot.py /app/http_honeypot.py

# Create logs directory inside container
RUN mkdir -p /logs

EXPOSE 8080

CMD ["python", "/app/http_honeypot.py"]
