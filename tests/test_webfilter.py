#!/usr/bin/env python3
"""
Test script para debug de consultas webfilter e app-ctrl
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

# Teste 1: Webfilter bloqueado no COFEMA
print("\n🔍 Teste 1: Sites bloqueados no COFEMA (últimos 15 dias)")
print("-" * 60)
result = faz.get_blocked_websites(
    device="All_FortiGate",
    time_range="last-15-days",
    limit=10,
    adom="COFEMA"
)
print(f"Resultado: {result}")
if result:
    print(f"Total de registros: {len(result)}")
    if len(result) > 0:
        print(f"Primeiro registro: {result[0]}")
else:
    print("⚠️ Nenhum resultado retornado")

# Teste 2: Webfilter permitido no COFEMA
print("\n🔍 Teste 2: Sites permitidos no COFEMA (últimos 15 dias)")
print("-" * 60)
result = faz.get_allowed_websites(
    device="All_FortiGate",
    time_range="last-15-days",
    limit=10,
    adom="COFEMA"
)
print(f"Resultado: {result}")
if result:
    print(f"Total de registros: {len(result)}")
    if len(result) > 0:
        print(f"Primeiro registro: {result[0]}")
else:
    print("⚠️ Nenhum resultado retornado")

# Teste 3: App-ctrl bloqueado no COFEMA
print("\n🔍 Teste 3: Aplicações bloqueadas no COFEMA (últimos 15 dias)")
print("-" * 60)
result = faz.get_blocked_applications(
    device="All_FortiGate",
    time_range="last-15-days",
    limit=10,
    adom="COFEMA"
)
print(f"Resultado: {result}")
if result:
    print(f"Total de registros: {len(result)}")
    if len(result) > 0:
        print(f"Primeiro registro: {result[0]}")
else:
    print("⚠️ Nenhum resultado retornado")

# Teste 4: Query genérica de webfilter (sem filtro de action)
print("\n🔍 Teste 4: Todos os logs webfilter no COFEMA (últimos 15 dias)")
print("-" * 60)
result = faz.query_logs(
    device="All_FortiGate",
    logtype="webfilter",
    time_range="last-15-days",
    filter_str="",
    limit=10,
    adom="COFEMA"
)
print(f"Resultado: {result}")
if result:
    print(f"Total de registros: {len(result)}")
    if len(result) > 0:
        print(f"Primeiro registro (chaves): {list(result[0].keys())}")
        print(f"Primeiro registro completo: {result[0]}")
        # Verificar qual o valor do campo action
        if 'action' in result[0]:
            print(f"Campo 'action' encontrado: {result[0]['action']}")
else:
    print("⚠️ Nenhum resultado retornado")

# Teste 5: Query genérica de app-ctrl (sem filtro de action)
print("\n🔍 Teste 5: Todos os logs app-ctrl no COFEMA (últimos 15 dias)")
print("-" * 60)
result = faz.query_logs(
    device="All_FortiGate",
    logtype="app-ctrl",
    time_range="last-15-days",
    filter_str="",
    limit=10,
    adom="COFEMA"
)
print(f"Resultado: {result}")
if result:
    print(f"Total de registros: {len(result)}")
    if len(result) > 0:
        print(f"Primeiro registro (chaves): {list(result[0].keys())}")
        print(f"Primeiro registro completo: {result[0]}")
        # Verificar qual o valor do campo action
        if 'action' in result[0]:
            print(f"Campo 'action' encontrado: {result[0]['action']}")
else:
    print("⚠️ Nenhum resultado retornado")

# Logout
faz.logout()
print("\n" + "=" * 60)
print("✅ Testes concluídos!")
