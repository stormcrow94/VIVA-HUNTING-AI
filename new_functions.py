#!/usr/bin/env python3
"""
Novas funções implementadas baseadas na documentação da API FortiAnalyzer
"""

from fortianalyzer_connector import FortiAnalyzerConnector
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

# Função para obter instância do conector
def get_faz_connector() -> FortiAnalyzerConnector:
    """Retorna instância configurada do FortiAnalyzerConnector"""
    import os
    from dotenv import load_dotenv
    
    load_dotenv()
    
    return FortiAnalyzerConnector(
        host=os.getenv('FAZ_HOST'),
        username=os.getenv('FAZ_USERNAME'),
        password=os.getenv('FAZ_PASSWORD'),
        verify_ssl=False
    )

# ===== FORTIVIEW FUNCTIONS =====

def get_top_sources(adom: str = "root", time_range: str = "last-24-hours", limit: int = 10) -> Dict[str, Any]:
    """
    Busca top IPs de origem com mais tráfego
    
    Args:
        adom: Nome do ADOM
        time_range: Período de tempo
        limit: Número máximo de resultados
        
    Returns:
        Dict com dados dos top sources
    """
    try:
        faz = get_faz_connector()
        if not faz.login():
            return {"error": "Falha no login", "data": []}
        
        # Tentar FortiView primeiro
        try:
            result = faz.get_top_sources(
                device="All_FortiGate",
                time_range=time_range,
                limit=limit,
                adom=adom
            )
            
            if result and len(result) > 0:
                faz.logout()
                return {
                    "success": True,
                    "message": f"Top {len(result)} IPs de origem encontrados",
                    "data": result,
                    "total_count": len(result),
                    "adom": adom,
                    "time_range": time_range,
                    "method": "fortiview"
                }
        except Exception as fortiview_error:
            logger.warning(f"FortiView failed, falling back to logs: {fortiview_error}")
        
        # FALLBACK: Usar query_logs se FortiView falhar
        logger.info("Using query_logs fallback for get_top_sources")
        logs = faz.query_logs(
            adom=adom,
            logtype="traffic",
            time_range=time_range,
            limit=limit * 10  # Buscar mais logs para agregar
        )
        
        faz.logout()
        
        if logs:
            # Agregar por srcip
            ip_stats = {}
            for log in logs:
                srcip = log.get("srcip", "unknown")
                if srcip not in ip_stats:
                    ip_stats[srcip] = {
                        "srcip": srcip,
                        "user": log.get("user", log.get("srcuser", "")),
                        "sessions": 0,
                        "bandwidth": 0,
                        "traffic_in": 0,
                        "traffic_out": 0
                    }
                ip_stats[srcip]["sessions"] += 1
                ip_stats[srcip]["bandwidth"] += log.get("sentbyte", 0) + log.get("rcvdbyte", 0)
                ip_stats[srcip]["traffic_in"] += log.get("rcvdbyte", 0)
                ip_stats[srcip]["traffic_out"] += log.get("sentbyte", 0)
            
            # Ordenar por bandwidth e pegar top N
            top_ips = sorted(ip_stats.values(), key=lambda x: x["bandwidth"], reverse=True)[:limit]
            
            return {
                "success": True,
                "message": f"Top {len(top_ips)} IPs de origem encontrados (via logs)",
                "data": top_ips,
                "total_count": len(top_ips),
                "adom": adom,
                "time_range": time_range,
                "method": "logs_aggregation"
            }
        else:
            return {
                "error": "Nenhum dado disponível para o período solicitado",
                "data": [],
                "adom": adom,
                "time_range": time_range
            }
            
    except Exception as e:
        logger.error(f"Error in get_top_sources: {e}")
        return {"error": str(e), "data": []}

def get_top_destinations(adom: str = "root", time_range: str = "last-24-hours", limit: int = 10) -> Dict[str, Any]:
    """
    Busca top IPs de destino com mais tráfego
    
    Args:
        adom: Nome do ADOM
        time_range: Período de tempo
        limit: Número máximo de resultados
        
    Returns:
        Dict com dados dos top destinations
    """
    try:
        faz = get_faz_connector()
        if not faz.login():
            return {"error": "Falha no login", "data": []}
        
        # Converter time_range para start/end
        time_data = faz._parse_time_range_string(time_range)
        
        result = faz.get_top_destinations(
            adom=adom,
            start_time=time_data["start"],
            end_time=time_data["end"],
            limit=limit
        )
        
        faz.logout()
        
        if result.get("success"):
            return {
                "success": True,
                "message": f"Top {len(result['data'])} IPs de destino encontrados",
                "data": result["data"],
                "total_count": result.get("total_count", 0),
                "adom": adom,
                "time_range": time_range
            }
        else:
            return {"error": result.get("error", "Erro desconhecido"), "data": []}
            
    except Exception as e:
        logger.error(f"Error in get_top_destinations: {e}")
        return {"error": str(e), "data": []}

def get_top_threats(adom: str = "root", time_range: str = "last-24-hours", limit: int = 10) -> Dict[str, Any]:
    """
    Busca top ameaças de segurança detectadas
    
    Args:
        adom: Nome do ADOM
        time_range: Período de tempo
        limit: Número máximo de resultados
        
    Returns:
        Dict com dados das top threats
    """
    try:
        faz = get_faz_connector()
        if not faz.login():
            return {"error": "Falha no login", "data": []}
        
        # Converter time_range para start/end
        time_data = faz._parse_time_range_string(time_range)
        
        result = faz.get_top_threats(
            adom=adom,
            start_time=time_data["start"],
            end_time=time_data["end"],
            limit=limit
        )
        
        faz.logout()
        
        if result.get("success"):
            return {
                "success": True,
                "message": f"Top {len(result['data'])} ameaças encontradas",
                "data": result["data"],
                "total_count": result.get("total_count", 0),
                "adom": adom,
                "time_range": time_range
            }
        else:
            return {"error": result.get("error", "Erro desconhecido"), "data": []}
            
    except Exception as e:
        logger.error(f"Error in get_top_threats: {e}")
        return {"error": str(e), "data": []}

def get_top_applications(adom: str = "root", time_range: str = "last-24-hours", limit: int = 10) -> Dict[str, Any]:
    """
    Busca top aplicações mais utilizadas
    
    Args:
        adom: Nome do ADOM
        time_range: Período de tempo
        limit: Número máximo de resultados
        
    Returns:
        Dict com dados das top applications
    """
    try:
        faz = get_faz_connector()
        if not faz.login():
            return {"error": "Falha no login", "data": []}
        
        # Converter time_range para start/end
        time_data = faz._parse_time_range_string(time_range)
        
        result = faz.get_top_applications(
            adom=adom,
            start_time=time_data["start"],
            end_time=time_data["end"],
            limit=limit
        )
        
        faz.logout()
        
        if result.get("success"):
            return {
                "success": True,
                "message": f"Top {len(result['data'])} aplicações encontradas",
                "data": result["data"],
                "total_count": result.get("total_count", 0),
                "adom": adom,
                "time_range": time_range
            }
        else:
            return {"error": result.get("error", "Erro desconhecido"), "data": []}
            
    except Exception as e:
        logger.error(f"Error in get_top_applications: {e}")
        return {"error": str(e), "data": []}

def get_top_countries(adom: str = "root", time_range: str = "last-24-hours", limit: int = 10) -> Dict[str, Any]:
    """
    Busca top países por tráfego
    
    Args:
        adom: Nome do ADOM
        time_range: Período de tempo
        limit: Número máximo de resultados
        
    Returns:
        Dict com dados dos top countries
    """
    try:
        faz = get_faz_connector()
        if not faz.login():
            return {"error": "Falha no login", "data": []}
        
        # Converter time_range para start/end
        time_data = faz._parse_time_range_string(time_range)
        
        result = faz.get_top_countries(
            adom=adom,
            start_time=time_data["start"],
            end_time=time_data["end"],
            limit=limit
        )
        
        faz.logout()
        
        if result.get("success"):
            return {
                "success": True,
                "message": f"Top {len(result['data'])} países encontrados",
                "data": result["data"],
                "total_count": result.get("total_count", 0),
                "adom": adom,
                "time_range": time_range
            }
        else:
            return {"error": result.get("error", "Erro desconhecido"), "data": []}
            
    except Exception as e:
        logger.error(f"Error in get_top_countries: {e}")
        return {"error": str(e), "data": []}

def get_policy_hits(adom: str = "root", time_range: str = "last-24-hours", limit: int = 10) -> Dict[str, Any]:
    """
    Busca políticas de firewall mais utilizadas
    
    Args:
        adom: Nome do ADOM
        time_range: Período de tempo
        limit: Número máximo de resultados
        
    Returns:
        Dict com dados das policy hits
    """
    try:
        faz = get_faz_connector()
        if not faz.login():
            return {"error": "Falha no login", "data": []}
        
        # Converter time_range para start/end
        time_data = faz._parse_time_range_string(time_range)
        
        result = faz.get_policy_hits(
            adom=adom,
            start_time=time_data["start"],
            end_time=time_data["end"],
            limit=limit
        )
        
        faz.logout()
        
        if result.get("success"):
            return {
                "success": True,
                "message": f"Top {len(result['data'])} políticas encontradas",
                "data": result["data"],
                "total_count": result.get("total_count", 0),
                "adom": adom,
                "time_range": time_range
            }
        else:
            return {"error": result.get("error", "Erro desconhecido"), "data": []}
            
    except Exception as e:
        logger.error(f"Error in get_policy_hits: {e}")
        return {"error": str(e), "data": []}

# ===== EVENT MANAGEMENT FUNCTIONS =====

def get_alerts(adom: str = "root", time_range: str = "last-24-hours", 
               severity_filter: str = None, limit: int = 50) -> Dict[str, Any]:
    """
    Busca alertas de segurança
    
    Args:
        adom: Nome do ADOM
        time_range: Período de tempo
        severity_filter: Filtro de severidade (critical, high, medium, low)
        limit: Número máximo de alertas
        
    Returns:
        Dict com dados dos alertas
    """
    try:
        faz = get_faz_connector()
        if not faz.login():
            return {"error": "Falha no login", "data": []}
        
        # Converter time_range para start/end
        time_data = faz._parse_time_range_string(time_range)
        
        result = faz.get_alerts(
            adom=adom,
            start_time=time_data["start"],
            end_time=time_data["end"],
            severity_filter=severity_filter,
            limit=limit
        )
        
        faz.logout()
        
        if result.get("success"):
            return {
                "success": True,
                "message": f"{len(result['alerts'])} alertas encontrados",
                "data": result["alerts"],
                "total_count": result.get("total_count", 0),
                "adom": adom,
                "time_range": time_range,
                "severity_filter": severity_filter
            }
        else:
            return {"error": result.get("error", "Erro desconhecido"), "data": []}
            
    except Exception as e:
        logger.error(f"Error in get_alerts: {e}")
        return {"error": str(e), "data": []}

def get_alert_count(adom: str = "root", time_range: str = "last-24-hours", 
                   group_by: str = "severity") -> Dict[str, Any]:
    """
    Conta alertas por categoria
    
    Args:
        adom: Nome do ADOM
        time_range: Período de tempo
        group_by: Categoria para agrupar (severity, mgmt_state, triggername)
        
    Returns:
        Dict com contagem de alertas
    """
    try:
        faz = get_faz_connector()
        if not faz.login():
            return {"error": "Falha no login", "data": []}
        
        # Converter time_range para start/end
        time_data = faz._parse_time_range_string(time_range)
        
        result = faz.get_alert_count(
            adom=adom,
            start_time=time_data["start"],
            end_time=time_data["end"],
            group_by=group_by
        )
        
        faz.logout()
        
        if result.get("success"):
            return {
                "success": True,
                "message": f"Contagem de alertas por {group_by}",
                "data": result["counts"],
                "adom": adom,
                "time_range": time_range,
                "group_by": group_by
            }
        else:
            return {"error": result.get("error", "Erro desconhecido"), "data": []}
            
    except Exception as e:
        logger.error(f"Error in get_alert_count: {e}")
        return {"error": str(e), "data": []}
