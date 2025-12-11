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

# Copy FastAPI app
COPY . .

# Expose API port
EXPOSE 8000

# Start FastAPI server
CMD ["python", "main.py"]
