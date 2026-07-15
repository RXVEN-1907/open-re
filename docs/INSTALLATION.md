# Installation Guide

This guide covers installing open-re in various environments.

## Quick Install (Docker)

### Prerequisites

- Docker 24+
- Docker Compose 2+

### One-Command Install

```bash
git clone https://github.com/RXVEN-1907/open-re.git
cd open-re
docker compose up -d
```

This starts:
- PostgreSQL on port 5432
- Redis on port 6379
- MinIO on ports 9000/9001
- API server on port 8080
- Frontend on port 3000
- Prometheus on port 9090
- Grafana on port 3001

### Access Points

| Service | URL | Credentials |
|---------|-----|-------------|
| Frontend | http://localhost:3000 | - |
| API | http://localhost:8080 | - |
| API Docs | http://localhost:8080/docs | - |
| MinIO Console | http://localhost:9001 | openre / openre_dev_password |
| Grafana | http://localhost:3001 | admin / admin |
| Prometheus | http://localhost:9090 | - |

## Manual Installation

### System Requirements

- **OS**: Linux (Ubuntu 22.04+, Debian 12+, Arch, Fedora 38+), macOS 13+, Windows 10/11 (WSL2)
- **CPU**: x86_64 or ARM64 (2+ cores recommended)
- **RAM**: 4 GB minimum, 8 GB+ recommended
- **Storage**: 10 GB+ free space
- **GPU**: Optional (NVIDIA CUDA for AI acceleration)

### Install Dependencies

#### Ubuntu/Debian

```bash
# System packages
sudo apt update && sudo apt install -y \
    postgresql-16 \
    redis-server \
    curl \
    git \
    build-essential \
    pkg-config \
    libssl-dev \
    libclang-dev \
    clang \
    cmake \
    protobuf-compiler \
    python3 \
    python3-pip \
    nodejs \
    npm

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Install pnpm
npm install -g pnpm@9

# Install Docker (optional)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

#### macOS

```bash
# Using Homebrew
brew install postgresql@16 redis git rust node pnpm docker

# Start services
brew services start postgresql@16
brew services start redis
```

#### Arch Linux

```bash
sudo pacman -S postgresql redis git rust nodejs npm pnpm docker clang cmake protobuf python
sudo systemctl enable --now postgresql redis docker
```

### Database Setup

```bash
# Create database and user
sudo -u postgres psql <<EOF
CREATE DATABASE openre;
CREATE USER openre WITH ENCRYPTED PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE openre TO openre;
EOF

# Run migrations
cd open-re
DATABASE_URL=postgresql://openre:your_secure_password@localhost:5432/openre \
cargo run --bin openre-cli -- db migrate
```

### Configuration

Create `config.toml`:

```toml
[server]
host = "0.0.0.0"
port = 8080
workers = 4

[database]
url = "postgresql://openre:your_secure_password@localhost:5432/openre"
max_connections = 20

[redis]
url = "redis://localhost:6379"
max_connections = 20

[storage]
type = "local"
local_path = "./data/storage"

[ai]
# Optional: Add OpenAI API key for remote models
# openai_api_key = "sk-..."

# Optional: Local models directory
# onnx_models_dir = "./models/onnx"
# llama_cpp_models_dir = "./models/llama"

[plugins]
plugins_dir = "./plugins"

[telemetry]
log_level = "info"
log_format = "json"
otlp_endpoint = ""  # Optional: OpenTelemetry collector

[auth]
jwt_secret = "your-super-secret-jwt-key-change-in-production"
access_token_ttl_seconds = 900
refresh_token_ttl_seconds = 604800

[rate_limit]
requests_per_minute = 100
```

### Build and Run

```bash
# Build all components
cargo build --workspace --release

# Build frontend
cd frontend && pnpm install && pnpm build && cd ..

# Run API server
./target/release/openre-api

# Run worker (in separate terminal)
./target/release/openre worker start

# Run AI worker (in separate terminal, if using AI)
./target/release/openre worker start --ai-enabled
```

## Production Deployment

### Docker Compose Production

```bash
# Copy production config
cp docker-compose.prod.yml docker-compose.yml

# Create .env file with secrets
cat > .env <<EOF
POSTGRES_PASSWORD=your_secure_db_password
REDIS_PASSWORD=your_secure_redis_password
MINIO_ROOT_USER=openre
MINIO_ROOT_PASSWORD=your_secure_minio_password
JWT_SECRET=your_super_secret_jwt_key
GRAFANA_PASSWORD=your_grafana_password
DOMAIN=your-domain.com
LETSENCRYPT_EMAIL=admin@your-domain.com
OPENAI_API_KEY=your_openai_key
VLLM_BASE_URL=http://your-vllm-server:8000
EOF

# Deploy
docker compose -f docker-compose.prod.yml up -d
```

### Kubernetes Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: openre-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: openre-api
  template:
    metadata:
      labels:
        app: openre-api
    spec:
      containers:
      - name: api
        image: ghcr.io/rxven-1907/open-re/api:latest
        ports:
        - containerPort: 8080
        envFrom:
        - secretRef:
            name: openre-secrets
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
---
apiVersion: v1
kind: Service
metadata:
  name: openre-api
spec:
  selector:
    app: openre-api
  ports:
  - port: 8080
    targetPort: 8080
```

### Reverse Proxy (Nginx)

```nginx
# /etc/nginx/sites-available/openre
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
    
    location /api/ {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /ws/ {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

### SSL with Let's Encrypt

```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal
sudo systemctl enable certbot.timer
```

## AI Models Setup

### Local Models (Recommended)

```bash
# Create models directory
mkdir -p models/onnx models/llama

# Download ONNX models (example)
wget -P models/onnx https://huggingface.co/.../model.onnx

# Download llama.cpp models (example)
wget -P models/llama https://huggingface.co/.../model.gguf

# Update config.toml
# ai.onnx_models_dir = "./models/onnx"
# ai.llama_cpp_models_dir = "./models/llama"
```

### Remote API (OpenAI/vLLM)

```toml
# config.toml
[ai]
openai_api_key = "sk-..."
# or
vllm_base_url = "http://your-vllm-server:8000/v1"
vllm_api_key = "your-vllm-key"
```

## Plugin Installation

```bash
# Install from registry
openre plugin install registry:ghidra-loader

# Install from local path
openre plugin install local:./my-plugin

# Install from Git
openre plugin install git:https://github.com/user/plugin.git

# List installed plugins
openre plugin list
```

## Verification

```bash
# Check API health
curl http://localhost:8080/health

# Check API readiness
curl http://localhost:8080/ready

# Test authentication
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"password"}'

# Test file upload
curl -X POST http://localhost:8080/api/files \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@test.bin"
```

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| Port 8080 in use | Change `server.port` in config.toml |
| Database connection failed | Check PostgreSQL is running and credentials |
| Redis connection failed | Check Redis is running on port 6379 |
| Frontend not loading | Check API server is running and CORS settings |
| AI models not loading | Verify model paths and GPU drivers |
| Plugin install fails | Check plugins directory permissions |

### Logs

```bash
# API logs
docker compose logs -f api

# Worker logs
docker compose logs -f worker

# All logs
docker compose logs -f

# Native logs
RUST_LOG=debug ./target/release/openre-api
```

### Health Checks

```bash
# Database
psql $DATABASE_URL -c "SELECT 1;"

# Redis
redis-cli ping

# MinIO
curl http://localhost:9000/minio/health/live

# API
curl http://localhost:8080/health
```

## Upgrading

```bash
# Pull latest changes
git pull origin main

# Update dependencies
cargo update

# Rebuild
cargo build --workspace --release

# Run migrations
cargo run --bin openre-cli -- db migrate

# Restart services
docker compose restart
# or
systemctl restart openre-api openre-worker
```

## Uninstalling

```bash
# Docker
docker compose down -v

# Native
# Stop services
# Remove database
dropdb openre
# Remove files
rm -rf /path/to/open-re
```