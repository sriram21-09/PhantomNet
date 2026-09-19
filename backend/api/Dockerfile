FROM python:3.11-slim

# Create app directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create a non-root user with UID/GID 10001
RUN groupadd -g 10001 phantom && useradd -m -u 10001 -g 10001 phantom

# Copy application code
COPY --chown=phantom:phantom . .

# Set directory permissions for the non-root user to allow creating files at runtime
RUN chown -R phantom:phantom /app

# Expose API port
EXPOSE 8000

USER 10001:10001

# Start FastAPI server with 4 workers for production concurrency
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
