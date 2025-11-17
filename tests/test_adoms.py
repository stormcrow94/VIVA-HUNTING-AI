#!/usr/bin/env python3
"""
Test script para verificar quais ADOMs têm logs webfilter e app-ctrl
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

# ADOMs para testar
adoms = ["root", "COFEMA", "DEKRA", "CASIO", "IDENTIDADE_TECH", "NETPARK", "PASTORINHO"]

for adom in adoms:
    print(f"\n{'='*60}")
    print(f"ADOM: {adom}")
    print(f"{'='*60}")

    # Teste webfilter
    result_webfilter = faz.query_logs(
        device="All_FortiGate",
        logtype="webfilter",
        time_range="last-15-days",
        filter_str="",
        limit=1,
        adom=adom
    )

    # Teste app-ctrl
    result_appctrl = faz.query_logs(
        device="All_FortiGate",
        logtype="app-ctrl",
        time_range="last-15-days",
        filter_str="",
        limit=1,
        adom=adom
    )

    webfilter_status = "✅ TEM" if result_webfilter and len(result_webfilter) > 0 else "❌ NÃO TEM"
    appctrl_status = "✅ TEM" if result_appctrl and len(result_appctrl) > 0 else "❌ NÃO TEM"

    print(f"  Webfilter: {webfilter_status}")
    print(f"  App-ctrl:  {appctrl_status}")

    if result_webfilter and len(result_webfilter) > 0:
        print(f"    - Exemplo webfilter action: {result_webfilter[0].get('action', 'N/A')}")
        if 'hostname' in result_webfilter[0]:
            print(f"    - Exemplo hostname: {result_webfilter[0]['hostname']}")
        if 'url' in result_webfilter[0]:
            print(f"    - Exemplo url: {result_webfilter[0]['url'][:80]}...")

    if result_appctrl and len(result_appctrl) > 0:
        print(f"    - Exemplo app-ctrl action: {result_appctrl[0].get('action', 'N/A')}")
        if 'app' in result_appctrl[0]:
            print(f"    - Exemplo app: {result_appctrl[0]['app']}")

# Logout
faz.logout()
print("\n" + "=" * 60)
print("✅ Testes concluídos!")
