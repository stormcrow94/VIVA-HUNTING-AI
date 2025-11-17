#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de Diagnostico - VIVA-HUNTING-AI
Verifica configuracoes e identifica problemas
"""

import os
import sys
from dotenv import load_dotenv

# Configurar encoding para Windows
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

print("=" * 60)
print("  VIVA-HUNTING-AI - Diagnostico do Sistema")
print("=" * 60)
print()

# Carregar .env
load_dotenv()

# 1. Verificar Python
print("[1/6] Verificando Python...")
print(f"  [OK] Python {sys.version}")
print()

# 2. Verificar variáveis de ambiente
print("[2/6] Verificando variáveis de ambiente (.env)...")
required_vars = {
    'OPENAI_API_KEY': 'Chave API do OpenAI',
    'FAZ_HOST': 'Endereço do FortiAnalyzer',
    'FAZ_USERNAME': 'Usuário do FortiAnalyzer',
    'FAZ_PASSWORD': 'Senha do FortiAnalyzer',
}

all_ok = True
for var, description in required_vars.items():
    value = os.getenv(var)
    if value:
        # Mostrar apenas primeiros caracteres para seguranca
        if 'KEY' in var or 'PASSWORD' in var:
            masked = value[:8] + '...' if len(value) > 8 else '***'
            print(f"  [OK] {var}: {masked}")
        else:
            print(f"  [OK] {var}: {value}")
    else:
        print(f"  [ERRO] {var}: NAO CONFIGURADO")
        all_ok = False
print()

# 3. Verificar dependencias
print("[3/6] Verificando dependencias instaladas...")
dependencies = [
    'fastapi',
    'uvicorn',
    'openai',
    'requests',
    'python-dotenv',
    'pydantic',
]

for dep in dependencies:
    try:
        __import__(dep.replace('-', '_'))
        print(f"  [OK] {dep}")
    except ImportError:
        print(f"  [ERRO] {dep} - NAO INSTALADO")
        all_ok = False
print()

# 4. Verificar arquivos criticos
print("[4/6] Verificando arquivos criticos...")
critical_files = [
    'app.py',
    'fortianalyzer_connector.py',
    'openai_handler.py',
    'auth.py',
    'static/index.html',
    'static/login.html',
    'static/admin.html',
]

for file in critical_files:
    if os.path.exists(file):
        print(f"  [OK] {file}")
    else:
        print(f"  [ERRO] {file} - NAO ENCONTRADO")
        all_ok = False
print()

# 5. Testar conexao com FortiAnalyzer (se configurado)
print("[5/6] Testando conexao com FortiAnalyzer...")
faz_host = os.getenv('FAZ_HOST')
faz_user = os.getenv('FAZ_USERNAME')
faz_pass = os.getenv('FAZ_PASSWORD')

if faz_host and faz_user and faz_pass:
    try:
        from fortianalyzer_connector import FortiAnalyzerConnector
        print(f"  -> Tentando conectar a {faz_host}...")
        
        connector = FortiAnalyzerConnector(
            host=faz_host,
            username=faz_user,
            password=faz_pass,
            verify_ssl=False
        )
        
        # Tentar login
        if connector.login():
            print(f"  [OK] Conexao bem-sucedida!")
            connector.logout()
        else:
            print(f"  [ERRO] Falha ao autenticar. Verifique usuario e senha.")
            all_ok = False
            
    except Exception as e:
        print(f"  [ERRO] Erro ao conectar: {str(e)}")
        all_ok = False
else:
    print(f"  [AVISO] FortiAnalyzer nao configurado (opcional)")
print()

# 6. Testar OpenAI API (se configurado)
print("[6/6] Testando OpenAI API...")
openai_key = os.getenv('OPENAI_API_KEY')

if openai_key and openai_key.startswith('sk-'):
    try:
        import openai
        openai.api_key = openai_key
        
        # Teste simples
        response = openai.models.list()
        print(f"  [OK] Chave API valida! Modelos disponiveis: {len(response.data)}")
        
    except Exception as e:
        print(f"  [ERRO] Erro ao validar chave: {str(e)}")
        all_ok = False
else:
    print(f"  [AVISO] OpenAI nao configurado (opcional se usar Gemini)")
print()

# Resumo final
print("=" * 60)
if all_ok:
    print("  [OK] DIAGNOSTICO: TUDO OK!")
    print("  O sistema esta pronto para uso.")
else:
    print("  [ERRO] DIAGNOSTICO: PROBLEMAS ENCONTRADOS")
    print("  Corrija os erros acima antes de iniciar.")
print("=" * 60)
print()

# Instrucoes
if not all_ok:
    print("PROXIMOS PASSOS:")
    print()
    print("1. Configure as variaveis faltantes no arquivo .env")
    print("2. Instale dependencias faltantes:")
    print("   pip install -r requirements.txt")
    print("3. Execute este diagnostico novamente:")
    print("   python diagnose.py")
    print()

sys.exit(0 if all_ok else 1)

