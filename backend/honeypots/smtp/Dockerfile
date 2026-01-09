FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy SMTP honeypot code
COPY smtp_honeypot.py /app/smtp_honeypot.py

# Create logs directory
RUN mkdir -p /app/logs

# Expose SMTP honeypot port
EXPOSE 2525

# Run the SMTP honeypot
CMD ["python", "smtp_honeypot.py"]
