#!/usr/bin/env python3
"""
Test script para verificar quais logtypes estão disponíveis
"""

import os
from dotenv import load_dotenv
from fortianalyzer_connector import FortiAnalyzerConnector

# Carregar variáveis de ambiente
load_dotenv()

FAZ_HOST = os.getenv("FAZ_HOST")
FAZ_USERNAME = os.getenv("FAZ_USERNAME")
FAZ_PASSWORD = os.getenv("FAZ_PASSWORD")
FAZ_VERIFY_SSL = os.getenv("FAZ_VERIFY_SSL", "false").lower() == "true"

print(f"Conectando ao FortiAnalyzer: {FAZ_HOST}")
print("=" * 60)

# Criar conector
faz = FortiAnalyzerConnector(
    host=FAZ_HOST,
    username=FAZ_USERNAME,
    password=FAZ_PASSWORD,
    verify_ssl=FAZ_VERIFY_SSL
)

# Login
if not faz.login():
    print("❌ Falha no login!")
    exit(1)

print("✅ Login realizado com sucesso!")
print("=" * 60)

# Testar diferentes logtypes
logtypes = ["traffic", "event", "security", "attack", "virus", "webfilter", "app-ctrl"]
adom = "COFEMA"

for logtype in logtypes:
    print(f"\n🔍 Testando logtype: {logtype} (ADOM: {adom})")
    print("-" * 60)

    result = faz.query_logs(
        device="All_FortiGate",
        logtype=logtype,
        time_range="last-15-days",
        filter_str="",
        limit=5,
        adom=adom
    )

    if result and len(result) > 0:
        print(f"✅ {len(result)} registros encontrados")
        print(f"Campos disponíveis: {list(result[0].keys())}")
        if 'action' in result[0]:
            print(f"Campo 'action': {result[0]['action']}")
        if 'app' in result[0]:
            print(f"Campo 'app': {result[0]['app']}")
        if 'hostname' in result[0]:
            print(f"Campo 'hostname': {result[0]['hostname']}")
        if 'url' in result[0]:
            print(f"Campo 'url': {result[0]['url']}")
    else:
        print(f"❌ Nenhum registro encontrado")

# Logout
faz.logout()
print("\n" + "=" * 60)
print("✅ Testes concluídos!")
