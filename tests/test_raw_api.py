#!/usr/bin/env python3
"""
Teste RAW da API FortiAnalyzer para debug
"""

import os
import requests
import urllib3
from dotenv import load_dotenv
import json

# Desabilitar warnings SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    # Carregar variáveis de ambiente
    load_dotenv()

    host = os.getenv("FAZ_HOST")
    username = os.getenv("FAZ_USERNAME")
    password = os.getenv("FAZ_PASSWORD")
    url = f"https://{host}/jsonrpc"

    print("=" * 60)
    print("FortiAnalyzer - Teste RAW API")
    print("=" * 60)

    # 1. Login
    print("1. Login...")
    login_payload = {
        "method": "exec",
        "params": [{
            "url": "/sys/login/user",
            "data": {
                "user": username,
                "passwd": password
            }
        }],
        "jsonrpc": "2.0",
        "id": 1
    }

    resp = requests.post(url, json=login_payload, verify=False, timeout=30)
    login_result = resp.json()
    session = login_result.get("session")
    print(f"✅ Session: {session[:20]}...")
    print()

    # 2. Testar logsearch
    print("2. Testando logsearch (add)...")
    logsearch_payload = {
        "method": "add",
        "params": [{
            "url": "/logview/adom/root/logsearch",
            "apiver": 3,
            "device": [{"devid": "All_FortiGate"}],
            "logtype": "traffic",
            "time-range": {
                "start": "2025-10-05 00:00",
                "end": "2025-10-06 23:59"
            },
            "filter": "",
            "time-order": "desc"
        }],
        "jsonrpc": "2.0",
        "session": session,
        "id": 2
    }

    print(f"Payload: {json.dumps(logsearch_payload, indent=2)}")
    print()

    resp = requests.post(url, json=logsearch_payload, verify=False, timeout=30)
    logsearch_result = resp.json()
    print(f"Response: {json.dumps(logsearch_result, indent=2)}")
    print()

    # 3. Se deu erro, testar com outro ADOM
    if "error" in logsearch_result:
        print("3. Erro com ADOM root. Testando com CASIO...")
        logsearch_payload["params"][0]["url"] = "/logview/adom/CASIO/logsearch"

        resp = requests.post(url, json=logsearch_payload, verify=False, timeout=30)
        logsearch_result = resp.json()
        print(f"Response: {json.dumps(logsearch_result, indent=2)}")
        print()

    # 4. Logout
    print("4. Logout...")
    logout_payload = {
        "method": "exec",
        "params": [{"url": "/sys/logout"}],
        "jsonrpc": "2.0",
        "session": session,
        "id": 999
    }

    requests.post(url, json=logout_payload, verify=False, timeout=30)
    print("✅ Logout OK!")
    print()

    print("=" * 60)
    print("Teste concluído!")
    print("=" * 60)

if __name__ == "__main__":
    main()
