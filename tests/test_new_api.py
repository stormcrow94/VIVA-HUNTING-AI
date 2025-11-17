#!/usr/bin/env python3
"""
Teste das novas funções do FortiAnalyzer (padrão assíncrono)
"""

import os
from dotenv import load_dotenv
from fortianalyzer_connector import FortiAnalyzerConnector
import logging

# Configurar logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

def main():
    # Carregar variáveis de ambiente
    load_dotenv()

    host = os.getenv("FAZ_HOST")
    username = os.getenv("FAZ_USERNAME")
    password = os.getenv("FAZ_PASSWORD")

    print("=" * 60)
    print("FortiAnalyzer - Teste API Assíncrona (2 etapas)")
    print("=" * 60)
    print(f"Host: {host}")
    print(f"User: {username}")
    print()

    # Conectar ao FortiAnalyzer
    faz = FortiAnalyzerConnector(host, username, password)

    try:
        # Login
        print("1. Fazendo login...")
        if not faz.login():
            print("❌ Falha no login!")
            return
        print("✅ Login OK!")
        print()

        # Teste 1: System Status (já funciona)
        print("2. Testando get_system_status()...")
        status = faz.get_system_status()
        if status:
            print(f"✅ Status OK!")
            print(f"   Hostname: {status.get('Hostname', 'N/A')}")
            print(f"   Version: {status.get('Version', 'N/A')}")
            print(f"   Serial: {status.get('Serial Number', 'N/A')}")
        else:
            print("❌ Falha ao obter status")
        print()

        # Teste 2: Query Logs (NOVO - padrão assíncrono)
        print("3. Testando query_logs() com padrão assíncrono...")
        logs = faz.query_logs(
            device="All_FortiGate",
            logtype="traffic",
            time_range="last-1-hour",
            limit=10
        )
        if logs is not None:
            print(f"✅ Logs OK! {len(logs)} registros retornados")
            if len(logs) > 0:
                print(f"   Primeiro log: {list(logs[0].keys())[:5]}")  # Mostrar primeiros 5 campos
            else:
                print(f"   ⚠️  Nenhum log encontrado no período")
        else:
            print("❌ Falha ao buscar logs")
        print()

        # Teste 3: Get Top Sources (NOVO - FortiView)
        print("4. Testando get_top_sources() com FortiView...")
        top_sources = faz.get_top_sources(
            device="All_FortiGate",
            time_range="last-1-hour",
            limit=5
        )
        if top_sources is not None:
            print(f"✅ Top Sources OK! {len(top_sources)} fontes retornadas")
            if len(top_sources) > 0:
                for i, source in enumerate(top_sources[:3], 1):
                    print(f"   #{i}: {source}")
            else:
                print(f"   ⚠️  Nenhum source encontrado no período")
        else:
            print("❌ Falha ao buscar top sources")
        print()

        # Teste 4: Get Log Count
        print("5. Testando get_log_count()...")
        count = faz.get_log_count(
            device="All_FortiGate",
            logtype="traffic",
            time_range="today"
        )
        if count is not None:
            print(f"✅ Log Count OK! {count} logs encontrados")
        else:
            print("❌ Falha ao contar logs")
        print()

        # Teste 5: Get Security Events
        print("6. Testando get_security_events()...")
        events = faz.get_security_events(
            device="All_FortiGate",
            time_range="today",
            limit=5
        )
        if events is not None:
            print(f"✅ Security Events OK! {len(events)} eventos retornados")
            if len(events) == 0:
                print(f"   ⚠️  Nenhum evento encontrado no período")
        else:
            print("❌ Falha ao buscar eventos de segurança")
        print()

    except Exception as e:
        logger.error(f"Erro no teste: {e}", exc_info=True)

    finally:
        # Logout
        print("7. Fazendo logout...")
        faz.logout()
        print("✅ Logout OK!")
        print()

    print("=" * 60)
    print("Testes concluídos!")
    print("=" * 60)

if __name__ == "__main__":
    main()
