# Test Web Application with Known Vulnerabilities
# This is a deliberately vulnerable FastAPI application for testing security scanners
# DO NOT DEPLOY TO PRODUCTION

FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir fastapi uvicorn[standard] python-multipart jinja2

# Copy application
COPY app.py .

# Expose port
EXPOSE 8080

# Run the application
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]