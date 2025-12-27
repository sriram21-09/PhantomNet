FROM python:3.11-slim

WORKDIR /app

COPY ftp_honeypot.py .
COPY ftp_root ./ftp_root

RUN pip install --no-cache-dir pyftpdlib

EXPOSE 2121

CMD ["python", "ftp_honeypot.py"]
