# Test API with REST and GraphQL Endpoints
# Deliberately vulnerable API for security scanner testing
# DO NOT DEPLOY TO PRODUCTION

FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir fastapi uvicorn[standard] strawberry-graphql python-multipart

# Copy application
COPY api.py .

# Expose port
EXPOSE 8081

# Run the application
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8081"]