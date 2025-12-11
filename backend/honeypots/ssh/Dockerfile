FROM python:3.11-slim

WORKDIR /app

COPY ssh_honeypot.py /app/ssh_honeypot.py

RUN mkdir -p /app/logs/ssh

CMD ["python", "/app/ssh_honeypot.py"]
