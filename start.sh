#!/bin/bash

# FortiAnalyzer Chatbot - Startup Script

echo "============================================================"
echo "  FortiAnalyzer Chatbot - Inicialização"
echo "============================================================"
echo ""

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Verificar se Python está instalado
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ Python 3 não encontrado. Por favor, instale Python 3.10+${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Python encontrado: $(python3 --version)${NC}"

# Verificar se .env existe
if [ ! -f .env ]; then
    echo -e "${RED}✗ Arquivo .env não encontrado!${NC}"
    echo -e "${YELLOW}  Copie .env.example para .env e configure suas credenciais.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Arquivo .env encontrado${NC}"

# Criar ambiente virtual se não existir
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}⚙ Criando ambiente virtual...${NC}"
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo -e "${RED}✗ Erro ao criar ambiente virtual${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Ambiente virtual criado${NC}"
fi

# Ativar ambiente virtual
echo -e "${YELLOW}⚙ Ativando ambiente virtual...${NC}"
source venv/bin/activate

# Instalar/atualizar dependências
echo -e "${YELLOW}⚙ Instalando dependências...${NC}"
pip install -q --upgrade pip
pip install -q -r requirements.txt

if [ $? -ne 0 ]; then
    echo -e "${RED}✗ Erro ao instalar dependências${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Dependências instaladas${NC}"

# Criar diretório de logs se não existir
mkdir -p logs

echo ""
echo "============================================================"
echo -e "${GREEN}✓ Tudo pronto! Iniciando o chatbot...${NC}"
echo "============================================================"
echo ""
echo "  🌐 Acesse: http://localhost:8000"
echo "  📊 API Docs: http://localhost:8000/docs"
echo "  ❤️  Health: http://localhost:8000/api/health"
echo ""
echo "  Pressione Ctrl+C para parar o servidor"
echo ""
echo "============================================================"
echo ""

# Iniciar aplicação
python3 app.py
