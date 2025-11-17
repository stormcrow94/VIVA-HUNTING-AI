#!/usr/bin/env python3
"""
Test script para testar integração completa do chatbot
Testa perguntas sobre sites e aplicações bloqueados
"""

import os
from dotenv import load_dotenv
from fortianalyzer_connector import FortiAnalyzerConnector
from gemini_handler import GeminiHandler

# Carregar variáveis de ambiente
load_dotenv()

FAZ_HOST = os.getenv("FAZ_HOST")
FAZ_USERNAME = os.getenv("FAZ_USERNAME")
FAZ_PASSWORD = os.getenv("FAZ_PASSWORD")
FAZ_VERIFY_SSL = os.getenv("FAZ_VERIFY_SSL", "false").lower() == "true"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-pro")

print("=" * 60)
print("Teste de Integração Completa do Chatbot")
print("=" * 60)

# Criar conector FortiAnalyzer
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

print("✅ Conectado ao FortiAnalyzer")

# Criar handler Gemini
gemini = GeminiHandler(api_key=GEMINI_API_KEY, model_name=GEMINI_MODEL)
print("✅ Gemini handler inicializado")
print("=" * 60)

# Testes de perguntas
perguntas = [
    "Quais sites foram bloqueados no ADOM COFEMA nos últimos 7 dias?",
    "Mostre aplicações bloqueadas no COFEMA nas últimas 24 horas",
    "Quais domínios foram bloqueados hoje no COFEMA?"
]

for i, pergunta in enumerate(perguntas, 1):
    print(f"\n{'=' * 60}")
    print(f"Teste {i}: {pergunta}")
    print('=' * 60)
    
    # Processar pergunta com Gemini
    ai_response = gemini.process_question(pergunta)
    
    if not ai_response.get("success"):
        print(f"❌ Gemini não conseguiu processar: {ai_response.get('message')}")
        continue
    
    function_name = ai_response["function_name"]
    parameters = ai_response["parameters"]
    
    print(f"✅ Gemini identificou: {function_name}")
    print(f"   Parâmetros: {parameters}")
    
    # Executar função
    if function_name == "get_blocked_websites":
        result = faz.get_blocked_websites(**parameters)
    elif function_name == "get_blocked_applications":
        result = faz.get_blocked_applications(**parameters)
    else:
        print(f"⚠️ Função não esperada: {function_name}")
        continue
    
    if result:
        print(f"✅ Resultado: {len(result)} registros encontrados")
        
        # Formatar resposta com Gemini
        formatted_response = gemini.format_response(
            question=pergunta,
            function_result=result[:5],  # Apenas primeiros 5 para teste
            function_name=function_name
        )
        
        print(f"\n📝 Resposta formatada pelo Gemini:")
        print(formatted_response)
    else:
        print("❌ Nenhum resultado encontrado")

# Logout
faz.logout()
print("\n" + "=" * 60)
print("✅ Testes concluídos!")
print("=" * 60)

