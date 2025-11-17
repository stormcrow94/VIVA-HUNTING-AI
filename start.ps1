# ============================================================
# VIVA-HUNTING-AI - Startup Script (PowerShell)
# Script de inicialização para Windows
# ============================================================

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  VIVA-HUNTING-AI - Starting Application" -ForegroundColor Cyan
Write-Host "  Chatbot Inteligente para FortiAnalyzer com OpenAI" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Verificar se Python está instalado
Write-Host "[1/5] Verificando Python..." -ForegroundColor Yellow
$pythonVersion = python --version 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  OK Python encontrado: $pythonVersion" -ForegroundColor Green
} else {
    Write-Host "  ERRO: Python nao encontrado!" -ForegroundColor Red
    Write-Host "  Instale Python 3.8+ de: https://www.python.org/downloads/" -ForegroundColor Red
    exit 1
}

# Verificar se arquivo .env existe
Write-Host ""
Write-Host "[2/5] Verificando configuracao (.env)..." -ForegroundColor Yellow
if (Test-Path ".env") {
    Write-Host "  OK Arquivo .env encontrado" -ForegroundColor Green
    
    # Verificar se as chaves principais existem
    $envContent = Get-Content ".env" -Raw
    $hasOpenAI = $envContent -match "OPENAI_API_KEY=sk-"
    $hasFAZ = $envContent -match "FAZ_HOST="
    
    if ($hasOpenAI) {
        Write-Host "  OK OPENAI_API_KEY configurada" -ForegroundColor Green
    } else {
        Write-Host "  AVISO: OPENAI_API_KEY pode nao estar configurada" -ForegroundColor Yellow
    }
    
    if ($hasFAZ) {
        Write-Host "  OK FAZ_HOST configurado" -ForegroundColor Green
    } else {
        Write-Host "  AVISO: FAZ_HOST pode nao estar configurado" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ERRO: Arquivo .env nao encontrado!" -ForegroundColor Red
    Write-Host "  Crie o arquivo .env na raiz do projeto" -ForegroundColor Red
    Write-Host "  Veja .env.example para referencia" -ForegroundColor Red
    exit 1
}

# Verificar/Criar ambiente virtual
Write-Host ""
Write-Host "[3/5] Verificando ambiente virtual..." -ForegroundColor Yellow
if (Test-Path "venv\Scripts\activate") {
    Write-Host "  OK Ambiente virtual encontrado" -ForegroundColor Green
} else {
    Write-Host "  Criando ambiente virtual..." -ForegroundColor Yellow
    python -m venv venv
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  OK Ambiente virtual criado" -ForegroundColor Green
    } else {
        Write-Host "  ERRO: Falha ao criar ambiente virtual" -ForegroundColor Red
        exit 1
    }
}

# Ativar ambiente virtual
Write-Host "  Ativando ambiente virtual..." -ForegroundColor Yellow
& "venv\Scripts\Activate.ps1"

# Instalar/Atualizar dependências
Write-Host ""
Write-Host "[4/5] Verificando dependencias..." -ForegroundColor Yellow
Write-Host "  Instalando/atualizando pacotes..." -ForegroundColor Yellow
pip install -r requirements.txt --quiet --disable-pip-version-check
if ($LASTEXITCODE -eq 0) {
    Write-Host "  OK Dependencias instaladas" -ForegroundColor Green
} else {
    Write-Host "  ERRO: Falha ao instalar dependencias" -ForegroundColor Red
    exit 1
}

# Iniciar aplicação
Write-Host ""
Write-Host "[5/5] Iniciando aplicacao..." -ForegroundColor Yellow
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Aplicacao iniciando..." -ForegroundColor Green
Write-Host "  Acesse: http://localhost:8000/login" -ForegroundColor Green
Write-Host "  Usuario padrao: admin / admin123" -ForegroundColor Green
Write-Host ""
Write-Host "  Pressione CTRL+C para parar" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Executar aplicação
python app.py

