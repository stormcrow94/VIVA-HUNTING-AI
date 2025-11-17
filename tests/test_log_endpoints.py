#!/usr/bin/env python3
"""
Script para testar quais endpoints de log funcionam no FortiAnalyzer
"""

from fortianalyzer_connector import FortiAnalyzerConnector
from dotenv import load_dotenv
import os
import json

load_dotenv()

faz = FortiAnalyzerConnector(
    host=os.getenv("FAZ_HOST"),
    username=os.getenv("FAZ_USERNAME"),
    password=os.getenv("FAZ_PASSWORD"),
    verify_ssl=False
)

print("=" * 60)
print("Testando endpoints de LOG do FortiAnalyzer")
print("=" * 60)

if not faz.login():
    print("✗ Falha no login")
    exit(1)

print("✓ Login bem-sucedido\n")

# Lista de endpoints para testar
endpoints_to_test = [
    # Endpoints documentados
    "/cli/global/system/admin/user",

    # Endpoints de log (hipotéticos)
    "/logview/adom/root/logsearch",
    "/logview/adom/root/logstats",
    "/logview/logfiles",
    "/api/v2/logview/logfiles",

    # FortiView
    "/fortiview/statistics",
    "/api/v2/fortiview/data",

    # Event Management
    "/eventmgmt/adom/root/alerts",
    "/api/v2/eventmgmt/alerts",
]

for endpoint in endpoints_to_test:
    print(f"\nTestando: {endpoint}")
    print("-" * 60)

    try:
        result = faz._make_request(
            method="get",
            params=[{"url": endpoint}]
        )

        if result.get("result"):
            status = result["result"][0].get("status", {})
            code = status.get("code")
            message = status.get("message")

            if code == 0:
                print(f"  ✓ SUCESSO!")
                data = result["result"][0].get("data")
                if data:
                    print(f"  Dados retornados: {type(data)}")
                    if isinstance(data, list):
                        print(f"  Total de itens: {len(data)}")
                    elif isinstance(data, dict):
                        print(f"  Chaves: {list(data.keys())[:5]}")
            else:
                print(f"  ✗ Erro {code}: {message}")
        else:
            print(f"  ✗ Resposta inesperada: {result}")

    except Exception as e:
        print(f"  ✗ Exceção: {e}")

faz.logout()

print("\n" + "=" * 60)
print("Teste concluído!")
print("=" * 60)
