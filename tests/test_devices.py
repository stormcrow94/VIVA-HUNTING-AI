#!/usr/bin/env python3
"""
Teste da função get_devices
"""

import os
from dotenv import load_dotenv
from fortianalyzer_connector import FortiAnalyzerConnector
import logging
import json

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
    print("FortiAnalyzer - Teste get_devices()")
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

        # Teste get_devices
        print("2. Listando dispositivos...")
        devices = faz.get_devices(adom="root")

        if devices is not None:
            print(f"✅ Encontrados {len(devices)} dispositivos!")
            print()

            for i, device in enumerate(devices, 1):
                print(f"Dispositivo #{i}:")
                print(f"  Nome: {device.get('name', 'N/A')}")
                print(f"  Hostname: {device.get('hostname', 'N/A')}")
                print(f"  IP: {device.get('ip', 'N/A')}")
                print(f"  Tipo: {device.get('dev_type', 'N/A')}")
                print(f"  Modelo: {device.get('platform', 'N/A')}")
                print(f"  Versão: {device.get('os_ver', 'N/A')}.{device.get('mr', 'N/A')}")
                print(f"  Serial: {device.get('sn', 'N/A')}")
                print(f"  Status: {device.get('conn_status', 'N/A')}")
                print()
        else:
            print("❌ Falha ao listar dispositivos")
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
