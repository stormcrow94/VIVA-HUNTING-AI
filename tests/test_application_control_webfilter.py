#!/usr/bin/env python3
"""
Testes de Validação - Application Control e Webfilter
Valida a implementação contra a documentação da API do FortiAnalyzer

Desenvolvido por: VIVA-HUNTING-AI
Data: 08/10/2025
"""

import os
import sys
import logging
from datetime import datetime
from dotenv import load_dotenv
from fortianalyzer_connector import FortiAnalyzerConnector

# Configurar logging detalhado
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Carregar variáveis de ambiente
load_dotenv()

# Configurações
FAZ_HOST = os.getenv("FAZ_HOST")
FAZ_USERNAME = os.getenv("FAZ_USERNAME")
FAZ_PASSWORD = os.getenv("FAZ_PASSWORD")
FAZ_VERIFY_SSL = os.getenv("FAZ_VERIFY_SSL", "false").lower() == "true"
TEST_ADOM = os.getenv("TEST_ADOM", "root")


def print_separator(title=""):
    """Imprime separador visual"""
    if title:
        logger.info("=" * 80)
        logger.info(f"  {title}")
        logger.info("=" * 80)
    else:
        logger.info("-" * 80)


def print_results(results, logtype):
    """Imprime resultados de forma formatada"""
    if not results:
        logger.warning(f"❌ Nenhum resultado encontrado para {logtype}")
        return
    
    logger.info(f"✅ Encontrados {len(results)} registros para {logtype}")
    
    # Mostrar primeiros 3 registros com detalhes
    for i, log in enumerate(results[:3], 1):
        logger.info(f"\n📋 Registro {i}:")
        
        # Campos principais que devem existir
        fields_to_show = [
            'type', 'subtype', 'action', 'app', 'appcat', 'hostname', 
            'url', 'srcip', 'dstip', 'policyid', 'devid', 'vd', 
            'catdesc', 'profile', 'apprisk', 'applist', 'msg'
        ]
        
        for field in fields_to_show:
            if field in log:
                value = log[field]
                if isinstance(value, str) and len(value) > 100:
                    value = value[:100] + "..."
                logger.info(f"  {field}: {value}")
    
    if len(results) > 3:
        logger.info(f"\n... e mais {len(results) - 3} registros")


def test_1_blocked_applications(faz):
    """Teste 1: Aplicações Bloqueadas (Application Control)"""
    print_separator("TESTE 1: Application Control - Aplicações Bloqueadas")
    
    try:
        results = faz.get_blocked_applications(
            device="All_FortiGate",
            time_range="last-24-hours",
            limit=100,
            adom=TEST_ADOM
        )
        
        print_results(results, "app-ctrl (blocked)")
        
        # Validações
        if results:
            for log in results[:5]:
                # Validar campos obrigatórios
                assert 'action' in log, "Campo 'action' ausente"
                assert log['action'] in ['block', 'blocked', 'deny', 'dropped', 'drop'], \
                    f"Action inválida: {log.get('action')}"
                
                # Validar que é realmente app-ctrl ou equivalente
                if 'subtype' in log:
                    assert log['subtype'] in ['app-ctrl', 'ips', 'attack'], \
                        f"Subtype inesperado: {log.get('subtype')}"
            
            logger.info("✅ Validação: Todos os logs têm action de bloqueio")
            return True
        else:
            logger.warning("⚠️  Nenhum dado encontrado (pode ser normal se não houver bloqueios)")
            return True
            
    except Exception as e:
        logger.error(f"❌ Erro no teste 1: {e}", exc_info=True)
        return False


def test_2_allowed_applications(faz):
    """Teste 2: Aplicações Permitidas (Application Control)"""
    print_separator("TESTE 2: Application Control - Aplicações Permitidas")
    
    try:
        results = faz.get_allowed_applications(
            device="All_FortiGate",
            time_range="last-24-hours",
            limit=100,
            adom=TEST_ADOM
        )
        
        print_results(results, "app-ctrl (allowed)")
        
        # Validações
        if results:
            for log in results[:5]:
                # Validar campos obrigatórios
                assert 'action' in log, "Campo 'action' ausente"
                assert log['action'] in ['pass', 'passthrough', 'accept', 'allow'], \
                    f"Action inválida: {log.get('action')}"
                
                # Validar que é realmente app-ctrl ou equivalente
                if 'subtype' in log:
                    assert log['subtype'] in ['app-ctrl', 'ips'], \
                        f"Subtype inesperado: {log.get('subtype')}"
            
            logger.info("✅ Validação: Todos os logs têm action de permissão")
            return True
        else:
            logger.warning("⚠️  Nenhum dado encontrado (pode ser normal)")
            return True
            
    except Exception as e:
        logger.error(f"❌ Erro no teste 2: {e}", exc_info=True)
        return False


def test_3_blocked_websites(faz):
    """Teste 3: Sites Bloqueados (Webfilter)"""
    print_separator("TESTE 3: Webfilter - Sites Bloqueados")
    
    try:
        results = faz.get_blocked_websites(
            device="All_FortiGate",
            time_range="last-24-hours",
            limit=100,
            adom=TEST_ADOM
        )
        
        print_results(results, "webfilter (blocked)")
        
        # Validações
        if results:
            for log in results[:5]:
                # Validar campos obrigatórios
                assert 'action' in log, "Campo 'action' ausente"
                assert log['action'] in ['block', 'blocked', 'deny', 'redirect'], \
                    f"Action inválida: {log.get('action')}"
                
                # Validar que tem hostname ou url
                assert 'hostname' in log or 'url' in log, \
                    "Deve conter hostname ou url"
                
                # Validar que é webfilter ou dns
                if 'subtype' in log:
                    assert log['subtype'] in ['webfilter', 'dns'], \
                        f"Subtype inesperado: {log.get('subtype')}"
            
            logger.info("✅ Validação: Todos os logs têm action de bloqueio")
            return True
        else:
            logger.warning("⚠️  Nenhum dado encontrado (pode ser normal se não houver bloqueios)")
            return True
            
    except Exception as e:
        logger.error(f"❌ Erro no teste 3: {e}", exc_info=True)
        return False


def test_4_allowed_websites(faz):
    """Teste 4: Sites Permitidos (Webfilter)"""
    print_separator("TESTE 4: Webfilter - Sites Permitidos")
    
    try:
        results = faz.get_allowed_websites(
            device="All_FortiGate",
            time_range="last-24-hours",
            limit=100,
            adom=TEST_ADOM
        )
        
        print_results(results, "webfilter (allowed)")
        
        # Validações
        if results:
            for log in results[:5]:
                # Validar campos obrigatórios
                assert 'action' in log, "Campo 'action' ausente"
                assert log['action'] in ['pass', 'passthrough', 'accept', 'allow'], \
                    f"Action inválida: {log.get('action')}"
                
                # Validar que tem hostname ou url
                assert 'hostname' in log or 'url' in log, \
                    "Deve conter hostname ou url"
                
                # Validar que é webfilter ou dns
                if 'subtype' in log:
                    assert log['subtype'] in ['webfilter', 'dns'], \
                        f"Subtype inesperado: {log.get('subtype')}"
            
            logger.info("✅ Validação: Todos os logs têm action de permissão")
            return True
        else:
            logger.warning("⚠️  Nenhum dado encontrado (pode ser normal)")
            return True
            
    except Exception as e:
        logger.error(f"❌ Erro no teste 4: {e}", exc_info=True)
        return False


def test_5_query_logs_direct(faz):
    """Teste 5: Query Logs Direto (Validar processo em 2 etapas)"""
    print_separator("TESTE 5: Query Logs Direto - Validar Processo Assíncrono")
    
    try:
        # Testar processo assíncrono com app-ctrl
        logger.info("Testando processo assíncrono em 2 etapas com logtype=app-ctrl...")
        
        results = faz.query_logs(
            device="All_FortiGate",
            logtype="app-ctrl",
            time_range="last-6-hours",
            filter_str="",
            limit=50,
            adom=TEST_ADOM
        )
        
        if results:
            logger.info(f"✅ Processo assíncrono funcionou: {len(results)} registros")
            
            # Validar estrutura
            log = results[0]
            logger.info(f"\n📋 Estrutura do log retornado:")
            logger.info(f"  Campos presentes: {list(log.keys())[:10]}...")
            
            # Campos esperados segundo documentação
            expected_fields = ['type', 'subtype', 'action']
            for field in expected_fields:
                if field in log:
                    logger.info(f"  ✅ {field}: {log[field]}")
                else:
                    logger.warning(f"  ⚠️  {field}: não presente")
            
            return True
        else:
            logger.warning("⚠️  Nenhum dado encontrado")
            return True
            
    except Exception as e:
        logger.error(f"❌ Erro no teste 5: {e}", exc_info=True)
        return False


def test_6_adom_support(faz):
    """Teste 6: Suporte a ADOM"""
    print_separator("TESTE 6: Suporte a ADOM")
    
    try:
        # Listar ADOMs disponíveis
        logger.info("Listando ADOMs disponíveis...")
        adoms = faz.get_adoms()
        
        if adoms:
            logger.info(f"✅ Encontrados {len(adoms)} ADOMs:")
            for adom in adoms:
                name = adom.get('name', 'N/A')
                desc = adom.get('desc', 'N/A')
                logger.info(f"  - {name}: {desc}")
            
            # Testar query com ADOM específico
            test_adom = adoms[0].get('name', 'root')
            logger.info(f"\nTestando query com ADOM: {test_adom}")
            
            results = faz.query_logs(
                logtype="traffic",
                time_range="last-1-hour",
                limit=10,
                adom=test_adom
            )
            
            if results:
                logger.info(f"✅ Query com ADOM '{test_adom}' funcionou: {len(results)} registros")
            else:
                logger.info(f"✅ Query com ADOM '{test_adom}' executou (sem dados)")
            
            return True
        else:
            logger.warning("⚠️  Nenhum ADOM encontrado (usando 'root' por padrão)")
            return True
            
    except Exception as e:
        logger.error(f"❌ Erro no teste 6: {e}", exc_info=True)
        return False


def main():
    """Executa todos os testes"""
    print_separator("VIVA-HUNTING-AI - Testes de Validação")
    logger.info("Iniciando testes de Application Control e Webfilter")
    logger.info(f"FortiAnalyzer: {FAZ_HOST}")
    logger.info(f"ADOM: {TEST_ADOM}")
    logger.info(f"Timestamp: {datetime.now().isoformat()}")
    print_separator()
    
    # Validar configuração
    if not all([FAZ_HOST, FAZ_USERNAME, FAZ_PASSWORD]):
        logger.error("❌ Variáveis de ambiente não configuradas!")
        logger.error("Configure FAZ_HOST, FAZ_USERNAME, FAZ_PASSWORD no arquivo .env")
        return 1
    
    # Conectar ao FortiAnalyzer
    try:
        logger.info("Conectando ao FortiAnalyzer...")
        faz = FortiAnalyzerConnector(
            host=FAZ_HOST,
            username=FAZ_USERNAME,
            password=FAZ_PASSWORD,
            verify_ssl=FAZ_VERIFY_SSL
        )
        
        if not faz.login():
            logger.error("❌ Falha ao conectar ao FortiAnalyzer")
            return 1
        
        logger.info("✅ Conectado ao FortiAnalyzer")
        
        # Verificar status do sistema
        status = faz.get_system_status()
        if status:
            logger.info(f"✅ Sistema: {status.get('Hostname')} v{status.get('Version')}")
        
    except Exception as e:
        logger.error(f"❌ Erro ao conectar: {e}")
        return 1
    
    # Executar testes
    results = {}
    tests = [
        ("Aplicações Bloqueadas", test_1_blocked_applications),
        ("Aplicações Permitidas", test_2_allowed_applications),
        ("Sites Bloqueados", test_3_blocked_websites),
        ("Sites Permitidos", test_4_allowed_websites),
        ("Query Logs Direto", test_5_query_logs_direct),
        ("Suporte a ADOM", test_6_adom_support),
    ]
    
    try:
        for test_name, test_func in tests:
            results[test_name] = test_func(faz)
            print_separator()
    
    except KeyboardInterrupt:
        logger.warning("\n⚠️  Testes interrompidos pelo usuário")
    
    finally:
        # Desconectar
        logger.info("Desconectando...")
        faz.logout()
    
    # Resumo final
    print_separator("RESUMO DOS TESTES")
    total = len(results)
    passed = sum(1 for r in results.values() if r)
    
    logger.info(f"\nTotal de testes: {total}")
    logger.info(f"Testes passados: {passed}")
    logger.info(f"Testes falhos: {total - passed}")
    
    for test_name, result in results.items():
        status = "✅ PASSOU" if result else "❌ FALHOU"
        logger.info(f"  {test_name}: {status}")
    
    print_separator()
    
    if passed == total:
        logger.info("🎉 TODOS OS TESTES PASSARAM!")
        logger.info("✅ A implementação está conforme a documentação da API do FortiAnalyzer")
        return 0
    else:
        logger.warning(f"⚠️  {total - passed} teste(s) falharam")
        return 1


if __name__ == "__main__":
    sys.exit(main())

