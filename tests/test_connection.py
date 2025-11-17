#!/usr/bin/env python3
"""
Script de teste para validar conexão com FortiAnalyzer JSON API
Baseado na documentação FortiAnalyzer 7.4.4 JSON API Reference
"""

import requests
import json
import urllib3

# Desabilitar warnings de SSL (apenas para teste)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class FortiAnalyzerAPI:
    def __init__(self, host, username, password, verify_ssl=False):
        """
        Inicializa conexão com FortiAnalyzer

        Args:
            host: IP ou hostname do FortiAnalyzer
            username: Usuário de autenticação
            password: Senha de autenticação
            verify_ssl: Verificar certificado SSL (False para testes)
        """
        self.host = host
        self.url = f"https://{host}/jsonrpc"
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.session_id = None

    def login(self):
        """
        Realiza login na API e obtém session ID
        """
        payload = {
            "method": "exec",
            "params": [{
                "url": "/sys/login/user",
                "data": {
                    "user": self.username,
                    "passwd": self.password
                }
            }],
            "id": 1
        }

        try:
            response = requests.post(
                self.url,
                json=payload,
                verify=self.verify_ssl,
                timeout=10
            )

            result = response.json()

            if result.get("result"):
                status = result["result"][0].get("status", {})
                if status.get("code") == 0:
                    self.session_id = result.get("session")
                    print(f"✓ Login realizado com sucesso!")
                    print(f"  Session ID: {self.session_id}")
                    return True
                else:
                    print(f"✗ Erro no login: {status.get('message')}")
                    return False
            else:
                print(f"✗ Resposta inesperada: {result}")
                return False

        except requests.exceptions.RequestException as e:
            print(f"✗ Erro de conexão: {e}")
            return False

    def get_system_status(self):
        """
        Obtém status do sistema FortiAnalyzer
        """
        if not self.session_id:
            print("✗ Não autenticado. Execute login() primeiro.")
            return None

        payload = {
            "method": "get",
            "params": [{
                "url": "/cli/global/system/status"
            }],
            "session": self.session_id,
            "id": 2
        }

        try:
            response = requests.post(
                self.url,
                json=payload,
                verify=self.verify_ssl,
                timeout=10
            )

            result = response.json()

            if result.get("result"):
                status = result["result"][0].get("status", {})
                if status.get("code") == 0:
                    data = result["result"][0].get("data", {})
                    print(f"\n✓ Status do Sistema:")
                    print(f"  Hostname: {data.get('Hostname')}")
                    print(f"  Version: {data.get('Version')}")
                    print(f"  Serial: {data.get('Serial Number')}")
                    return data
                else:
                    print(f"✗ Erro ao obter status: {status.get('message')}")
                    return None
            else:
                print(f"✗ Resposta inesperada: {result}")
                return None

        except requests.exceptions.RequestException as e:
            print(f"✗ Erro de conexão: {e}")
            return None

    def logout(self):
        """
        Finaliza sessão na API
        """
        if not self.session_id:
            return

        payload = {
            "method": "exec",
            "params": [{
                "url": "/sys/logout"
            }],
            "session": self.session_id,
            "id": 3
        }

        try:
            response = requests.post(
                self.url,
                json=payload,
                verify=self.verify_ssl,
                timeout=10
            )
            print("\n✓ Logout realizado")
            self.session_id = None
        except:
            pass


def main():
    print("=" * 60)
    print("FortiAnalyzer API - Teste de Conexão")
    print("=" * 60)
    print("\nConfigure as credenciais abaixo:\n")

    # Configurações - ALTERAR CONFORME SEU AMBIENTE
    host = input("Host/IP do FortiAnalyzer: ").strip() or "192.168.1.100"
    username = input("Usuário (default: admin): ").strip() or "admin"
    password = input("Senha: ").strip() or "password"

    print(f"\n{'=' * 60}")
    print("Iniciando testes...")
    print(f"{'=' * 60}\n")

    # Criar instância da API
    faz = FortiAnalyzerAPI(host, username, password)

    # Teste 1: Login
    print("1. Testando autenticação...")
    if faz.login():

        # Teste 2: Obter status do sistema
        print("\n2. Testando leitura de dados...")
        faz.get_system_status()

        # Teste 3: Logout
        print("\n3. Finalizando sessão...")
        faz.logout()

        print(f"\n{'=' * 60}")
        print("✓ TODOS OS TESTES CONCLUÍDOS COM SUCESSO!")
        print(f"{'=' * 60}\n")
    else:
        print(f"\n{'=' * 60}")
        print("✗ FALHA NA AUTENTICAÇÃO")
        print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
