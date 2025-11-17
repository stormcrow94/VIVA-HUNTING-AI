#!/usr/bin/env python3
"""
Teste para descobrir qual ADOM está disponível
"""

import os
from dotenv import load_dotenv
from fortianalyzer_connector import FortiAnalyzerConnector
import logging

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
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
    print("FortiAnalyzer - Teste ADOM")
    print("=" * 60)

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

        # Tentar listar ADOMs
        print("2. Listando ADOMs...")
        result = faz._make_request(
            method="get",
            params=[{
                "url": "/dvmdb/adom"
            }]
        )
        print(f"Resultado: {result}")
        print()

    except Exception as e:
        logger.error(f"Erro no teste: {e}", exc_info=True)

    finally:
        # Logout
        print("3. Fazendo logout...")
        faz.logout()
        print("✅ Logout OK!")
        print()

    print("=" * 60)
    print("Teste concluído!")
    print("=" * 60)

if __name__ == "__main__":
    main()
