FROM python:3.11-slim

WORKDIR /app

# System deps for asyncssh
RUN apt-get update && apt-get install -y \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY async_ssh_honeypot.py .
COPY honeypot_host_key .

RUN pip install --no-cache-dir asyncssh

EXPOSE 2222

CMD ["python", "async_ssh_honeypot.py"]
