FROM python:3.9-slim
WORKDIR /app
COPY . .
# We use a simple socket listener for now to avoid complex paramiko dependencies
CMD ["python", "ssh_honeypot.py"]
