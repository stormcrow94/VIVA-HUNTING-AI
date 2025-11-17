#!/usr/bin/env python3
"""
Script para descobrir endpoints FortiAnalyzer disponíveis
Testa endpoints comuns baseados na documentação mencionada
"""

from fortianalyzer_connector import FortiAnalyzerConnector
from dotenv import load_dotenv
import os
import json
from datetime import datetime, timedelta

load_dotenv()

faz = FortiAnalyzerConnector(
    host=os.getenv("FAZ_HOST"),
    username=os.getenv("FAZ_USERNAME"),
    password=os.getenv("FAZ_PASSWORD"),
    verify_ssl=False
)

print("=" * 80)
print("DESCOBRINDO ENDPOINTS FORTIANALYZER DISPONÍVEIS")
print("=" * 80)

if not faz.login():
    print("✗ Falha no login")
    exit(1)

print("✓ Login bem-sucedido\n")

# Timestamp atual e 1 hora atrás
now = int(datetime.now().timestamp())
hour_ago = int((datetime.now() - timedelta(hours=1)).timestamp())

# Endpoints para testar com EXEC (não GET)
exec_endpoints = [
    # LogView - baseado no menu
    {
        "name": "LogView - List Devices",
        "url": "logview/adom/root/device/list",
        "method": "exec",
        "data": {}
    },
    {
        "name": "LogView - Get Stats",
        "url": "logview/adom/root/stats",
        "method": "exec",
        "data": {}
    },
    {
        "name": "FortiView - Get Data",
        "url": "fortiview/adom/root/run",
        "method": "exec",
        "data": {
            "apiver": 3,
            "filter": "",
            "time-range": {"from": hour_ago, "to": now}
        }
    },
    {
        "name": "Event Management - List",
        "url": "eventmgmt/adom/root/alerts/list",
        "method": "exec",
        "data": {}
    },
    {
        "name": "Report - List",
        "url": "report/adom/root/reports/list",
        "method": "exec",
        "data": {}
    },
    # Device Manager Database
    {
        "name": "DVMDB - List Devices",
        "url": "/dvmdb/adom/root/device",
        "method": "get",
        "data": None
    },
    {
        "name": "DVMDB - Get Device",
        "url": "/dvmdb/device",
        "method": "get",
        "data": None
    },
]

successful_endpoints = []

for endpoint in exec_endpoints:
    print(f"\n{'='*80}")
    print(f"Testando: {endpoint['name']}")
    print(f"URL: {endpoint['url']}")
    print(f"Método: {endpoint['method']}")
    print("-" * 80)

    try:
        if endpoint['data'] is not None:
            params = [{
                "url": endpoint['url'],
                "data": endpoint['data']
            }]
        else:
            params = [{"url": endpoint['url']}]

        result = faz._make_request(
            method=endpoint['method'],
            params=params
        )

        print(f"Resposta bruta: {json.dumps(result, indent=2, default=str)[:500]}...")

        # Checar se foi bem-sucedido
        if result.get("result"):
            status = result["result"][0].get("status", {})
            code = status.get("code")

            if code == 0:
                print(f"\n✓ SUCESSO! Endpoint funciona!")
                data = result["result"][0].get("data")
                if data:
                    print(f"  Tipo de dados: {type(data)}")
                    if isinstance(data, list):
                        print(f"  Itens retornados: {len(data)}")
                        if len(data) > 0:
                            print(f"  Exemplo: {json.dumps(data[0], indent=2, default=str)[:300]}")
                    elif isinstance(data, dict):
                        print(f"  Chaves: {list(data.keys())}")

                successful_endpoints.append({
                    "name": endpoint['name'],
                    "url": endpoint['url'],
                    "method": endpoint['method'],
                    "data_example": endpoint['data']
                })
            else:
                print(f"\n✗ Erro {code}: {status.get('message')}")

        elif result.get("error"):
            error = result["error"]
            print(f"\n✗ Erro API: {error.get('code')} - {error.get('message')}")

    except Exception as e:
        print(f"\n✗ Exceção: {e}")

faz.logout()

print("\n" + "=" * 80)
print("RESUMO - ENDPOINTS QUE FUNCIONAM:")
print("=" * 80)

if successful_endpoints:
    for ep in successful_endpoints:
        print(f"\n✓ {ep['name']}")
        print(f"  URL: {ep['url']}")
        print(f"  Método: {ep['method']}")
else:
    print("\n❌ Nenhum endpoint funcional descoberto")

print("\n" + "=" * 80)
print("Script concluído!")
print("=" * 80)
