# deploy.ps1 - PhantomNet Deployment Script
$ErrorActionPreference = "Stop"

Write-Host "🚀 Starting PhantomNet Deployment..." -ForegroundColor Cyan

# 1. Update Codebase
Write-Host "📥 Pulling latest changes..."
git pull origin main

# 2. Check for .env
if (-not (Test-Path .env)) {
    Write-Host "⚠️ .env file not found! creating from example..." -ForegroundColor Yellow
    Copy-Item .env.example .env
    Write-Host "Please edit .env with production passwords." -ForegroundColor Red
}

# 3. Build & Start with Production Config
Write-Host "🐳 Building and Starting Containers (Production Mode)..."
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build --remove-orphans

# 4. Cleanup
Write-Host "🧹 Pruning unused images..."
docker image prune -f

Write-Host "✅ Deployment Complete! PhantomNet is running." -ForegroundColor Green
Write-Host "   Frontend: http://localhost"
Write-Host "   API:      http://localhost:8000"
