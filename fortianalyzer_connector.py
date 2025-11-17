#!/usr/bin/env python3
"""
FortiAnalyzer API Connector
Gerencia conexão e operações com FortiAnalyzer JSON-RPC API
"""

import requests
import urllib3
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import logging
import time

# Desabilitar warnings SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class FortiAnalyzerConnector:
    """Conector para FortiAnalyzer JSON-RPC API"""

    def __init__(self, host: str, username: str, password: str, verify_ssl: bool = False):
        """
        Inicializa conexão com FortiAnalyzer

        Args:
            host: IP ou hostname do FortiAnalyzer
            username: Usuário de autenticação
            password: Senha de autenticação
            verify_ssl: Verificar certificado SSL
        """
        self.host = host
        self.url = f"https://{host}/jsonrpc"
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.session_id = None
        self.request_id = 0
        self.last_login_time = None
        self.session_timeout = 300  # 5 minutos em segundos

    def _get_next_id(self) -> int:
        """Gera ID sequencial para requests"""
        self.request_id += 1
        return self.request_id

    def _make_request(self, method: str, params: List[Dict], use_session: bool = True) -> Dict:
        """
        Faz request JSON-RPC para FortiAnalyzer

        Args:
            method: Método (get, set, add, update, delete, exec)
            params: Parâmetros da requisição
            use_session: Se deve incluir session_id

        Returns:
            Resposta JSON do FortiAnalyzer
        """
        # Verificar e renovar sessão se necessário (exceto para login/logout)
        if use_session and method != "exec":
            if not self._check_and_renew_session():
                raise Exception("Failed to maintain valid session")

        payload = {
            "method": method,
            "params": params,
            "jsonrpc": "2.0",
            "id": self._get_next_id()
        }

        if use_session and self.session_id:
            payload["session"] = self.session_id

        # Log do payload para debug
        logger.debug(f"Request payload: {payload}")

        try:
            response = requests.post(
                self.url,
                json=payload,
                verify=self.verify_ssl,
                timeout=30
            )
            response.raise_for_status()
            result = response.json()

            # Log da resposta para debug
            logger.debug(f"Response: {result}")

            # Tratar erro JSON-RPC no topo
            if isinstance(result, dict) and "error" in result:
                logger.error(f"JSON-RPC error: {result['error']}")
                return result

            return result

        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {e}")
            raise

    def login(self) -> bool:
        """
        Realiza login e obtém session ID

        Returns:
            True se login bem-sucedido
        """
        try:
            result = self._make_request(
                method="exec",
                params=[{
                    "url": "/sys/login/user",
                    "data": {
                        "user": self.username,
                        "passwd": self.password
                    }
                }],
                use_session=False
            )

            if result.get("result"):
                status = result["result"][0].get("status", {})
                if status.get("code") == 0:
                    self.session_id = result.get("session")
                    self.last_login_time = time.time()
                    logger.info(f"Login successful, session: {self.session_id}")
                    return True
                else:
                    logger.error(f"Login failed: {status.get('message')}")
                    return False

        except Exception as e:
            logger.error(f"Login exception: {e}")
            return False

    def _check_and_renew_session(self) -> bool:
        """
        Verifica se a sessão precisa ser renovada e renova se necessário

        Returns:
            True se a sessão está válida ou foi renovada com sucesso
        """
        if not self.session_id or not self.last_login_time:
            logger.info("No active session, performing login")
            return self.login()

        # Calcular tempo desde último login
        time_elapsed = time.time() - self.last_login_time

        # Se passou mais de 5 minutos, renovar sessão
        if time_elapsed >= self.session_timeout:
            logger.info(f"Session expired ({time_elapsed:.0f}s elapsed), renewing...")
            self.logout()
            return self.login()

        return True

    def logout(self):
        """Finaliza sessão"""
        if not self.session_id:
            return

        try:
            self._make_request(
                method="exec",
                params=[{"url": "/sys/logout"}]
            )
            logger.info("Logout successful")
        except Exception as e:
            logger.debug(f"Logout error ignored: {e}")
        finally:
            self.session_id = None

    def get_system_status(self) -> Optional[Dict]:
        """
        Obtém status do sistema FortiAnalyzer

        Returns:
            Dict com informações do sistema ou None
        """
        try:
            result = self._make_request(
                method="get",
                params=[{"url": "/cli/global/system/status"}]
            )

            logger.debug(f"get_system_status raw result: {result}")

            if result.get("result"):
                status = result["result"][0].get("status", {})
                if status.get("code") == 0:
                    data = result["result"][0].get("data", {})
                    logger.info(f"System status data: {data}")
                    return data
                else:
                    logger.error(f"System status error code: {status.get('code')}, message: {status.get('message')}")

        except Exception as e:
            logger.error(f"Error getting system status: {e}")

        return None

    def query_logs(
        self,
        device: str = "All_FortiGate",
        logtype: str = "traffic",
        time_range: str = "last-1-hour",
        filter_str: str = "",
        limit: int = 100,
        adom: str = "root",
        _retry_count: int = 0  # Proteção contra recursão infinita
    ) -> Optional[List[Dict]]:
        """
        Consulta logs no FortiAnalyzer (padrão assíncrono em 2 etapas)

        Args:
            device: Nome do device ou "All_FortiGate"
            logtype: Tipo de log (traffic, event, security, attack, etc)
            time_range: Período (last-1-hour, last-24-hours, today, etc)
            filter_str: Filtro adicional (ex: "srcip==192.168.1.1")
            limit: Número máximo de registros
            adom: ADOM alvo (padrão: root)
            _retry_count: Contador interno de tentativas (proteção contra loop)

        Returns:
            Lista de logs ou None
        """
        try:
            # Proteção contra recursão infinita
            if _retry_count > 0:
                logger.error(f"Device '{device}' não encontrado mesmo após correção automática. Abortando para evitar loop.")
                return {
                    "error": "device_not_found_after_retry",
                    "message": f"O dispositivo '{device}' aparece na lista de devices do ADOM '{adom}', mas a API não consegue acessá-lo. Possíveis causas: device offline, sem permissão, ou desabilitado.",
                    "device": device,
                    "adom": adom
                }
            
            # Normalizar ADOM para uppercase (API do FortiAnalyzer é case-sensitive)
            adom = adom.upper() if adom else "root"
            
            # Calcular timerange
            time_params = self._parse_time_range_string(time_range)

            # Etapa 1: Iniciar busca (add) - retorna tid
            logger.info(f"Starting log search: device={device}, logtype={logtype}, time_range={time_range}")

            add_params: Dict[str, Any] = {
                "url": f"/logview/adom/{adom}/logsearch",
                "apiver": 3,
                "logtype": logtype,
                "time-range": time_params,
                "filter": filter_str,
                "time-order": "desc"
            }
            # SEMPRE incluir device, mesmo que seja All_FortiGate
            # Usar 'devname' para nomes de devices, 'devid' apenas para IDs especiais (All_FortiGate, serial numbers)
            if device:
                if device == "All_FortiGate" or device.startswith("All_"):
                    # IDs especiais usam devid
                    add_params["device"] = [{"devid": device}]
                else:
                    # Nomes de devices usam devname
                    add_params["device"] = [{"devname": device}]

            result_add = self._make_request(
                method="add",
                params=[add_params]
            )

            # Verificar resposta e obter tid
            if not result_add.get("result"):
                # Verificar se é erro de device não encontrado
                error_msg = result_add.get("error", {}).get("message", "")
                if "device(s) can be found" in error_msg or "None of the device" in error_msg:
                    logger.warning(f"Device '{device}' not found in ADOM '{adom}'. Searching for similar devices...")
                    # Tentar listar devices disponíveis para ajudar o usuário
                    try:
                        available_devices = self.get_devices(adom=adom)
                        if available_devices:
                            device_names = [d.get('name', d.get('hostname', 'unknown')) for d in available_devices]
                            logger.info(f"Available devices in ADOM '{adom}': {device_names}")
                            
                            # Tentar encontrar device similar (busca case-insensitive e parcial)
                            suggested = None
                            search_term = device.lower().replace(" ", "").replace("-", "").replace("_", "")
                            for dev_name in device_names:
                                dev_normalized = dev_name.lower().replace(" ", "").replace("-", "").replace("_", "")
                                if search_term in dev_normalized or dev_normalized in search_term:
                                    suggested = dev_name
                                    break
                            
                            # Se encontrou device similar, TENTAR AUTOMATICAMENTE com ele
                            # MAS APENAS SE FOR DIFERENTE do device original (evitar loop!)
                            if suggested and suggested.lower().replace("-", "").replace("_", "") != device.lower().replace("-", "").replace("_", ""):
                                logger.info(f"Found similar device '{suggested}' for '{device}'. Retrying automatically...")
                                # Recursive call with suggested device + increment retry count
                                result = self.query_logs(
                                    device=suggested,
                                    logtype=logtype,
                                    time_range=time_range,
                                    filter_str=filter_str,
                                    limit=limit,
                                    adom=adom,
                                    _retry_count=_retry_count + 1  # Incrementar contador!
                                )
                                
                                # Se deu certo, adicionar informação de que usou device sugerido
                                if result and isinstance(result, list):
                                    logger.info(f"✓ Query succeeded with suggested device '{suggested}'")
                                    # Adicionar metadado aos resultados
                                    return {
                                        "auto_corrected": True,
                                        "original_device": device,
                                        "used_device": suggested,
                                        "data": result
                                    }
                                elif result and isinstance(result, dict):
                                    result["auto_corrected"] = True
                                    result["original_device"] = device
                                    result["used_device"] = suggested
                                    return result
                            
                            # Se o device sugerido é O MESMO (normalizado), significa que ele existe na lista
                            # mas não pode ser acessado (offline, sem permissão, etc)
                            elif suggested:
                                logger.warning(f"Device '{device}' found in list but API cannot access it")
                                return {
                                    "error": "device_not_accessible",
                                    "message": f"O dispositivo '{device}' existe no ADOM '{adom}', mas não pode ser acessado. Possíveis causas: device offline, sem logs no período, ou sem permissão de acesso.",
                                    "device": device,
                                    "adom": adom,
                                    "available_devices": device_names
                                }
                            
                            # Se não encontrou device similar algum
                            return {
                                "error": "device_not_found",
                                "message": f"Dispositivo '{device}' não encontrado no ADOM '{adom}'",
                                "available_devices": device_names,
                                "adom": adom
                            }
                    except Exception as e:
                        logger.error(f"Error during device search/retry: {e}")
                
                logger.error(f"Failed to start log search: {result_add}")
                return None

            add_result_data = result_add["result"]
            
            # Para operações 'add', o resultado pode vir direto como dict com tid
            # ou como lista com status
            if isinstance(add_result_data, dict) and "tid" in add_result_data:
                # Formato direto: {"tid": 123456}
                tid = add_result_data["tid"]
            elif isinstance(add_result_data, list) and len(add_result_data) > 0:
                # Formato com status: [{"status": {"code": 0}, "tid": 123456}]
                add_result_data = add_result_data[0]
                status = add_result_data.get("status", {})
                if status.get("code") != 0:
                    logger.error(f"Log search add failed: {status}")
                    return None
                tid = add_result_data.get("tid")
            else:
                logger.error(f"Unexpected result format: {add_result_data}")
                return None

            if not tid:
                logger.error(f"No tid returned from log search: {result_add}")
                return None

            logger.info(f"Log search started with tid: {tid}")

            # Etapa 2: Buscar resultado (get) usando tid com polling inteligente
            # Para consultas longas (15 dias), o FortiAnalyzer precisa de tempo para processar
            # mesmo retornando status "succeeded" imediatamente
            
            # Calcular delay inicial baseado no time_range
            # Consultas curtas (< 24h): 2s
            # Consultas médias (1-7 dias): 3s
            # Consultas longas (>= 7 dias): 5s
            # time_params já foi calculado acima, reutilizar
            if time_params:
                try:
                    start_str = time_params.get("start", "")
                    end_str = time_params.get("end", "")
                    if start_str and end_str:
                        start_dt = datetime.strptime(start_str, "%Y-%m-%d %H:%M:%S")
                        end_dt = datetime.strptime(end_str, "%Y-%m-%d %H:%M:%S")
                        days_diff = (end_dt - start_dt).days
                        
                        if days_diff >= 7:
                            initial_delay = 5  # 5 segundos para consultas longas
                            max_wait_time = 60  # 60 segundos máximo
                            poll_interval = 2  # Verificar a cada 2 segundos
                        elif days_diff >= 1:
                            initial_delay = 3  # 3 segundos para consultas médias
                            max_wait_time = 45  # 45 segundos máximo
                            poll_interval = 2
                        else:
                            initial_delay = 2  # 2 segundos para consultas curtas
                            max_wait_time = 30  # 30 segundos máximo
                            poll_interval = 2
                    else:
                        # Fallback para valores padrão
                        initial_delay = 2
                        max_wait_time = 30
                        poll_interval = 2
                except Exception:
                    # Em caso de erro, usar valores padrão
                    initial_delay = 2
                    max_wait_time = 30
                    poll_interval = 2
            else:
                # Sem time_range válido, usar valores padrão
                initial_delay = 2
                max_wait_time = 30
                poll_interval = 2
            
            # Aguardar delay inicial antes do primeiro GET
            if initial_delay > 0:
                logger.debug(f"Waiting {initial_delay}s before first GET (time_range: {time_range})")
                time.sleep(initial_delay)
            
            # Polling até obter dados ou atingir timeout
            max_attempts = max_wait_time // poll_interval
            data = None
            total_count = 0
            
            for attempt in range(1, max_attempts + 1):
                result_get = self._make_request(
                    method="get",
                    params=[{
                        "url": f"/logview/adom/{adom}/logsearch/{tid}",
                        "apiver": 3,
                        "offset": 0,
                        "limit": limit
                    }]
                )

                if result_get.get("result"):
                    # Resposta pode estar em result[0] OU result direto (dependendo da versão da API)
                    result_data = result_get["result"]
                    if isinstance(result_data, list) and len(result_data) > 0:
                        result_data = result_data[0]

                    status = result_data.get("status", {})
                    status_code = status.get("code", -1)
                    status_msg = status.get("message", "")
                    
                    if status_code == 0 or status_msg == "succeeded":
                        data = result_data.get("data", [])
                        total_count = result_data.get("total-count", 0)
                        
                        # Se temos dados OU total_count > 0, retornar sucesso
                        if data or total_count > 0:
                            logger.info(f"Log search completed: {len(data)} records returned (total: {total_count}) after {attempt} attempt(s)")
                            return data
                        # Se status é "succeeded" mas não há dados, pode ser que ainda esteja processando
                        # Continuar polling se não atingimos o máximo de tentativas
                        elif attempt < max_attempts:
                            logger.debug(f"Status succeeded but no data yet (attempt {attempt}/{max_attempts}), continuing polling...")
                            time.sleep(poll_interval)
                            continue
                        else:
                            # Atingimos o máximo de tentativas e ainda não temos dados
                            logger.warning(f"Status succeeded but no data returned after {max_attempts} attempts")
                            return data  # Retornar lista vazia
                    else:
                        # Status não é "succeeded", pode ser erro ou ainda processando
                        if status_code == -1 or status_msg == "in progress" or status_msg == "":
                            # Ainda processando, continuar polling
                            if attempt < max_attempts:
                                logger.debug(f"Status: {status_code} ({status_msg}), continuing polling (attempt {attempt}/{max_attempts})...")
                                time.sleep(poll_interval)
                                continue
                            else:
                                logger.error(f"Log search still in progress after {max_attempts} attempts: {status}")
                                return None
                        else:
                            # Erro definitivo
                            logger.error(f"Log search failed: {status}")
                            return None
                else:
                    # Erro no GET
                    if attempt < max_attempts:
                        logger.warning(f"GET request failed (attempt {attempt}/{max_attempts}), retrying...")
                        time.sleep(poll_interval)
                        continue
                    else:
                        logger.error(f"GET request failed after {max_attempts} attempts: {result_get}")
                        return None
            
            # Se chegou aqui, esgotamos todas as tentativas sem sucesso
            logger.error(f"Log search timed out after {max_attempts} attempts")
            return data if data is not None else None

        except Exception as e:
            logger.error(f"Error querying logs: {e}")

        return None

    def get_log_count(
        self,
        device: str = "All_FortiGate",
        logtype: str = "traffic",
        time_range: str = "today",
        filter_str: str = "",
        adom: str = "root"
    ) -> Optional[int]:
        """
        Conta número de logs (usa query_logs e conta resultados)

        Args:
            device: Nome do device
            logtype: Tipo de log
            time_range: Período
            filter_str: Filtro
            adom: ADOM alvo (padrão: root)

        Returns:
            Número de logs ou None
        """
        try:
            # Normalizar ADOM para uppercase
            adom = adom.upper() if adom else "root"
            
            # Usar query_logs para buscar logs e contar
            logs = self.query_logs(
                device=device,
                logtype=logtype,
                time_range=time_range,
                filter_str=filter_str,
                limit=1000,  # Limite alto para contar
                adom=adom
            )

            if logs is not None:
                count = len(logs)
                logger.info(f"Log count: {count} records")
                return count

        except Exception as e:
            logger.error(f"Error counting logs: {e}")

        return None

    def get_top_sources(
        self,
        device: str = "All_FortiGate",
        time_range: str = "last-1-hour",
        limit: int = 10,
        adom: str = "root"
    ) -> Optional[List[Dict]]:
        """
        Obtém top IPs de origem por volume de tráfego usando FortiView (padrão assíncrono)

        Args:
            device: Nome do device
            time_range: Período
            limit: Número de resultados
            adom: ADOM alvo (padrão: root)

        Returns:
            Lista com top sources ou None
        """
        try:
            # Normalizar ADOM para uppercase
            adom = adom.upper() if adom else "root"
            
            time_params = self._parse_time_range_string(time_range)

            # Etapa 1: Iniciar FortiView (add) - retorna tid
            logger.info(f"Starting FortiView top-sources: device={device}, time_range={time_range}")

            add_params_fv: Dict[str, Any] = {
                "url": f"/fortiview/adom/{adom}/top-sources/run",
                "apiver": 3,
                "time-range": time_params,
                "limit": limit,
                "sort-by": [{"field": "bytes", "order": "desc"}]
            }
            # SEMPRE incluir device, mesmo que seja All_FortiGate
            # Usar 'devname' para nomes de devices, 'devid' apenas para IDs especiais (All_FortiGate, serial numbers)
            if device:
                if device == "All_FortiGate" or device.startswith("All_"):
                    # IDs especiais usam devid
                    add_params_fv["device"] = [{"devid": device}]
                else:
                    # Nomes de devices usam devname
                    add_params_fv["device"] = [{"devname": device}]

            logger.debug(f"FortiView request params: {add_params_fv}")
            
            result_add = self._make_request(
                method="add",
                params=[add_params_fv]
            )

            logger.debug(f"FortiView add response: {result_add}")

            # Verificar resposta e obter tid
            if not result_add.get("result"):
                logger.error(f"Failed to start FortiView: {result_add}")
                return None

            add_result_data = result_add["result"]
            
            # Para operações 'add', o resultado pode vir direto como dict com tid
            # ou como lista com status
            if isinstance(add_result_data, dict) and "tid" in add_result_data:
                # Formato direto: {"tid": 123456}
                tid = add_result_data["tid"]
            elif isinstance(add_result_data, list) and len(add_result_data) > 0:
                # Formato com status: [{"status": {"code": 0}, "tid": 123456}]
                add_result_data = add_result_data[0]
                status = add_result_data.get("status", {})
                if status.get("code") != 0:
                    logger.error(f"FortiView add failed: {status}")
                    return None
                tid = add_result_data.get("tid")
            else:
                logger.error(f"Unexpected result format: {add_result_data}")
                return None

            if not tid:
                logger.error(f"No tid returned from FortiView: {result_add}")
                return None

            logger.info(f"FortiView started with tid: {tid}")

            # Etapa 2: Buscar resultado (get) usando tid
            result_get = self._make_request(
                method="get",
                params=[{
                    "url": f"/fortiview/adom/{adom}/top-sources/run/{tid}",
                    "apiver": 3
                }]
            )

            if result_get.get("result"):
                # Resposta pode estar em result[0] OU result direto (dependendo da versão da API)
                result_data = result_get["result"]
                if isinstance(result_data, list) and len(result_data) > 0:
                    result_data = result_data[0]

                status = result_data.get("status", {})
                if status.get("code") == 0 or status.get("message") == "succeeded":
                    data = result_data.get("data", [])
                    logger.info(f"FortiView completed: {len(data)} sources returned")
                    return data
                else:
                    logger.error(f"FortiView failed: {status}")

        except Exception as e:
            logger.error(f"Error getting top sources: {e}")

        return None

    def get_security_events(
        self,
        device: str = "All_FortiGate",
        time_range: str = "today",
        severity: str = "",
        limit: int = 100,
        adom: str = "root"
    ) -> Optional[List[Dict]]:
        """
        Busca eventos de segurança

        Args:
            device: Nome do device
            time_range: Período
            severity: Severidade (critical, high, medium, low)
            limit: Número de registros
            adom: ADOM alvo (padrão: root)

        Returns:
            Lista de eventos ou None
        """
        # Normalizar ADOM para uppercase
        adom = adom.upper() if adom else "root"
        
        filter_str = ""
        if severity:
            # Mapear severidade para níveis (aplicável a alguns tipos de log "event")
            severity_map = {
                "critical": "level>=5",
                "high": "level==4",
                "medium": "level==3",
                "low": "level<=2"
            }
            filter_str = severity_map.get(severity.lower(), "")

        # 1) Buscar eventos do tipo "event"
        events: List[Dict] = []
        try:
            event_logs = self.query_logs(
                device=device,
                logtype="event",
                time_range=time_range,
                filter_str=filter_str,
                limit=limit,
                adom=adom
            )
            if event_logs:
                events.extend(event_logs)
        except Exception as e:
            logger.debug(f"get_security_events: event logs fetch error: {e}")

        # 2) Se ainda tiver espaço no limite, tentar "security"
        if len(events) < limit:
            try:
                security_logs = self.query_logs(
                    device=device,
                    logtype="security",
                    time_range=time_range,
                    filter_str="",
                    limit=limit - len(events),
                    adom=adom
                )
                if security_logs:
                    events.extend(security_logs)
            except Exception as e:
                logger.debug(f"get_security_events: security logs fetch error: {e}")

        # 3) Se ainda tiver espaço, incluir "attack" (muitos ambientes populam aqui)
        if len(events) < limit:
            try:
                attack_logs = self.query_logs(
                    device=device,
                    logtype="attack",
                    time_range=time_range,
                    filter_str="",
                    limit=limit - len(events),
                    adom=adom
                )
                if attack_logs:
                    events.extend(attack_logs)
            except Exception as e:
                logger.debug(f"get_security_events: attack logs fetch error: {e}")

        logger.info(f"get_security_events returned {len(events)} records (adom={adom}, time_range={time_range})")
        return events

    def get_blocked_traffic(
        self,
        device: str = "All_FortiGate",
        time_range: str = "last-1-hour",
        limit: int = 100,
        adom: str = "root"
    ) -> Optional[List[Dict]]:
        """
        Busca tráfego bloqueado

        Args:
            device: Nome do device
            time_range: Período
            limit: Número de registros
            adom: ADOM alvo (padrão: root)

        Returns:
            Lista de logs bloqueados ou None
        """
        # Normalizar ADOM para uppercase
        adom = adom.upper() if adom else "root"
        
        # Buscar tráfego bloqueado com filtros mais abrangentes
        blocked_logs = []

        # 1) Tráfego com action deny/block/drop
        try:
            traffic_logs = self.query_logs(
                device=device,
                logtype="traffic",
                time_range=time_range,
                filter_str="action==deny OR action==block OR action==drop",
                limit=limit,
                adom=adom
            )
            if traffic_logs:
                blocked_logs.extend(traffic_logs)
        except Exception as e:
            logger.debug(f"get_blocked_traffic: traffic logs error: {e}")

        # 2) Se ainda há espaço, buscar eventos de segurança bloqueados
        if len(blocked_logs) < limit:
            try:
                security_logs = self.query_logs(
                    device=device,
                    logtype="security",
                    time_range=time_range,
                    filter_str="action==deny OR action==block OR action==drop",
                    limit=limit - len(blocked_logs),
                    adom=adom
                )
                if security_logs:
                    blocked_logs.extend(security_logs)
            except Exception as e:
                logger.debug(f"get_blocked_traffic: security logs error: {e}")

        # 3) Se ainda há espaço, buscar ataques bloqueados
        if len(blocked_logs) < limit:
            try:
                attack_logs = self.query_logs(
                    device=device,
                    logtype="attack",
                    time_range=time_range,
                    filter_str="action==deny OR action==block OR action==drop",
                    limit=limit - len(blocked_logs),
                    adom=adom
                )
                if attack_logs:
                    blocked_logs.extend(attack_logs)
            except Exception as e:
                logger.debug(f"get_blocked_traffic: attack logs error: {e}")

        logger.info(f"get_blocked_traffic returned {len(blocked_logs)} records (adom={adom}, time_range={time_range})")
        return blocked_logs

    def get_blocked_websites(
        self,
        device: str = "All_FortiGate",
        time_range: str = "last-1-hour",
        limit: int = 100,
        adom: str = "root"
    ) -> Optional[List[Dict]]:
        """
        Busca sites/URLs bloqueados pelo webfilter
        
        Nota: Webfilter logs podem ter diferentes valores de action dependendo da versão:
        - blocked, deny, passthrough, etc.

        Args:
            device: Nome do device
            time_range: Período
            limit: Número de registros
            adom: ADOM alvo (padrão: root)

        Returns:
            Lista de sites bloqueados ou None
        """
        # Normalizar ADOM para uppercase
        adom = adom.upper() if adom else "root"
        
        blocked_sites = []
        
        # Estratégia 1: Buscar TODOS os logs webfilter primeiro (sem filtro)
        # Depois filtraremos por campos que indicam bloqueio
        try:
            logs = self.query_logs(
                device=device,
                logtype="webfilter",
                time_range=time_range,
                filter_str="",  # Sem filtro para pegar todos os logs webfilter
                limit=limit * 2,  # Pegar mais para filtrar depois
                adom=adom
            )
            if logs:
                # Filtrar logs que indicam bloqueio
                # Campos comuns: action, eventtype, utmaction
                for log in logs:
                    action = str(log.get('action', '')).lower()
                    eventtype = str(log.get('eventtype', '')).lower()
                    utmaction = str(log.get('utmaction', '')).lower()
                    
                    # Verificar se é bloqueio
                    if any(keyword in action for keyword in ['block', 'deny', 'drop']) or \
                       any(keyword in eventtype for keyword in ['block', 'deny']) or \
                       any(keyword in utmaction for keyword in ['block', 'deny']):
                        blocked_sites.append(log)
                        if len(blocked_sites) >= limit:
                            break
                            
                logger.info(f"get_blocked_websites: Found {len(logs)} webfilter logs, {len(blocked_sites)} blocked")
        except Exception as e:
            logger.warning(f"get_blocked_websites: webfilter logs error: {e}")
        
        # Estratégia 2: Se não encontrou em webfilter, tentar DNS (fallback não documentado oficialmente)
        # Nota: 'dns' não é um logtype oficial na documentação 7.4.8, mas pode funcionar em algumas versões
        if len(blocked_sites) < limit:
            try:
                dns_logs = self.query_logs(
                    device=device,
                    logtype="dns",
                    time_range=time_range,
                    filter_str="",  # Buscar todos DNS
                    limit=limit * 2,
                    adom=adom
                )
                if dns_logs:
                    for log in dns_logs:
                        action = str(log.get('action', '')).lower()
                        # DNS pode ter action=redirect para sites bloqueados
                        if any(keyword in action for keyword in ['redirect', 'block', 'deny']):
                            blocked_sites.append(log)
                            if len(blocked_sites) >= limit:
                                break
                    logger.info(f"get_blocked_websites: Found {len(dns_logs)} dns logs, added {len([l for l in blocked_sites if l in dns_logs])} blocked")
            except Exception as e:
                logger.warning(f"get_blocked_websites: dns logs error: {e}")
        
        logger.info(f"get_blocked_websites returned {len(blocked_sites)} records (adom={adom}, time_range={time_range})")
        return blocked_sites[:limit] if blocked_sites else None

    def get_allowed_websites(
        self,
        device: str = "All_FortiGate",
        time_range: str = "last-1-hour",
        limit: int = 100,
        adom: str = "root"
    ) -> Optional[List[Dict]]:
        """
        Busca sites/URLs permitidos pelo webfilter
        
        Nota: Em alguns FortiAnalyzers, sites permitidos aparecem nos logs DNS
        com action=pass ao invés de logs webfilter dedicados

        Args:
            device: Nome do device
            time_range: Período
            limit: Número de registros
            adom: ADOM alvo (padrão: root)

        Returns:
            Lista de sites permitidos ou None
        """
        # Normalizar ADOM para uppercase
        adom = adom.upper() if adom else "root"
        
        allowed_sites = []
        
        # Estratégia 1: Tentar logs webfilter tradicionais
        try:
            logs = self.query_logs(
                device=device,
                logtype="webfilter",
                time_range=time_range,
                filter_str="action==pass OR action==passthrough OR action==accept",
                limit=limit,
                adom=adom
            )
            if logs:
                allowed_sites.extend(logs)
        except Exception as e:
            logger.debug(f"get_allowed_websites: webfilter logs error: {e}")
        
        # Estratégia 2: Se não encontrou em webfilter, tentar DNS (action=pass)
        # Nota: 'dns' não é um logtype oficial na documentação 7.4.8, mas pode funcionar em algumas versões
        if len(allowed_sites) < limit:
            try:
                dns_logs = self.query_logs(
                    device=device,
                    logtype="dns",
                    time_range=time_range,
                    filter_str="action==pass OR action==passthrough OR action==accept",
                    limit=limit - len(allowed_sites),
                    adom=adom
                )
                if dns_logs:
                    allowed_sites.extend(dns_logs)
            except Exception as e:
                logger.debug(f"get_allowed_websites: dns logs error: {e}")
        
        logger.info(f"get_allowed_websites returned {len(allowed_sites)} records (adom={adom}, time_range={time_range})")
        return allowed_sites if allowed_sites else None

    def get_blocked_applications(
        self,
        device: str = "All_FortiGate",
        time_range: str = "last-1-hour",
        limit: int = 100,
        adom: str = "root"
    ) -> Optional[List[Dict]]:
        """
        Busca aplicações bloqueadas pelo Application Control
        
        Nota: Em alguns FortiAnalyzers, aplicações bloqueadas aparecem nos logs IPS/ATTACK
        com action=dropped ao invés de logs app-ctrl dedicados

        Args:
            device: Nome do device
            time_range: Período
            limit: Número de registros
            adom: ADOM alvo (padrão: root)

        Returns:
            Lista de aplicações bloqueadas ou None
        """
        # Normalizar ADOM para uppercase
        adom = adom.upper() if adom else "root"
        
        blocked_apps = []
        
        # Estratégia 1: Tentar logs app-ctrl tradicionais
        try:
            logs = self.query_logs(
                device=device,
                logtype="app-ctrl",
                time_range=time_range,
                filter_str="action==block OR action==blocked OR action==deny",
                limit=limit,
                adom=adom
            )
            if logs:
                blocked_apps.extend(logs)
        except Exception as e:
            logger.debug(f"get_blocked_applications: app-ctrl logs error: {e}")
        
        # Estratégia 2: Se não encontrou em app-ctrl, tentar IPS (action=dropped)
        # Nota: 'ips' não é um logtype oficial na documentação 7.4.8, use 'attack' para ataques/IPS
        if len(blocked_apps) < limit:
            try:
                ips_logs = self.query_logs(
                    device=device,
                    logtype="ips",
                    time_range=time_range,
                    filter_str="action==dropped OR action==blocked OR action==deny",
                    limit=limit - len(blocked_apps),
                    adom=adom
                )
                if ips_logs:
                    blocked_apps.extend(ips_logs)
            except Exception as e:
                logger.debug(f"get_blocked_applications: ips logs error: {e}")
        
        # Estratégia 3: Se ainda não encontrou, tentar ATTACK
        if len(blocked_apps) < limit:
            try:
                attack_logs = self.query_logs(
                    device=device,
                    logtype="attack",
                    time_range=time_range,
                    filter_str="action==dropped OR action==blocked OR action==deny",
                    limit=limit - len(blocked_apps),
                    adom=adom
                )
                if attack_logs:
                    blocked_apps.extend(attack_logs)
            except Exception as e:
                logger.debug(f"get_blocked_applications: attack logs error: {e}")
        
        logger.info(f"get_blocked_applications returned {len(blocked_apps)} records (adom={adom}, time_range={time_range})")
        return blocked_apps if blocked_apps else None

    def get_allowed_applications(
        self,
        device: str = "All_FortiGate",
        time_range: str = "last-1-hour",
        limit: int = 100,
        adom: str = "root"
    ) -> Optional[List[Dict]]:
        """
        Busca aplicações permitidas pelo Application Control
        
        Nota: Em alguns FortiAnalyzers, aplicações permitidas aparecem nos logs IPS
        com action=pass ao invés de logs app-ctrl dedicados

        Args:
            device: Nome do device
            time_range: Período
            limit: Número de registros
            adom: ADOM alvo (padrão: root)

        Returns:
            Lista de aplicações permitidas ou None
        """
        # Normalizar ADOM para uppercase
        adom = adom.upper() if adom else "root"
        
        allowed_apps = []
        
        # Estratégia 1: Tentar logs app-ctrl tradicionais
        try:
            logs = self.query_logs(
                device=device,
                logtype="app-ctrl",
                time_range=time_range,
                filter_str="action==pass OR action==passthrough OR action==accept",
                limit=limit,
                adom=adom
            )
            if logs:
                allowed_apps.extend(logs)
        except Exception as e:
            logger.debug(f"get_allowed_applications: app-ctrl logs error: {e}")
        
        # Estratégia 2: Se não encontrou em app-ctrl, tentar IPS (action=pass)
        # Nota: 'ips' não é um logtype oficial na documentação 7.4.8, use 'attack' para ataques/IPS
        if len(allowed_apps) < limit:
            try:
                ips_logs = self.query_logs(
                    device=device,
                    logtype="ips",
                    time_range=time_range,
                    filter_str="action==pass OR action==passthrough OR action==accept",
                    limit=limit - len(allowed_apps),
                    adom=adom
                )
                if ips_logs:
                    allowed_apps.extend(ips_logs)
            except Exception as e:
                logger.debug(f"get_allowed_applications: ips logs error: {e}")
        
        logger.info(f"get_allowed_applications returned {len(allowed_apps)} records (adom={adom}, time_range={time_range})")
        return allowed_apps if allowed_apps else None

    def get_adoms(self) -> Optional[List[Dict]]:
        """
        Lista todos os ADOMs (Administrative Domains) disponíveis no FortiAnalyzer

        Returns:
            Lista de ADOMs ou None
        """
        try:
            result = self._make_request(
                method="get",
                params=[{
                    "url": "/dvmdb/adom"
                }]
            )

            logger.debug(f"get_adoms raw result: {result}")

            if result.get("result"):
                status = result["result"][0].get("status", {})
                if status.get("code") == 0:
                    adoms = result["result"][0].get("data", [])
                    logger.info(f"Found {len(adoms)} ADOMs")
                    return adoms
                else:
                    logger.error(f"get_adoms error: {status}")

        except Exception as e:
            logger.error(f"Error getting ADOMs: {e}")

        return None

    def get_devices(self, adom: str = "root") -> Optional[List[Dict]]:
        """
        Lista todos os dispositivos registrados no FortiAnalyzer

        Args:
            adom: Nome do ADOM (padrão: root)

        Returns:
            Lista de dispositivos ou None
        """
        # Normalizar ADOM para uppercase
        adom = adom.upper() if adom else "root"
        
        try:
            result = self._make_request(
                method="get",
                params=[{
                    "url": f"/dvmdb/adom/{adom}/device"
                }]
            )

            logger.debug(f"get_devices raw result: {result}")

            if result.get("result"):
                status = result["result"][0].get("status", {})
                if status.get("code") == 0:
                    devices = result["result"][0].get("data", [])
                    logger.info(f"Found {len(devices)} devices")
                    return devices
                else:
                    logger.error(f"get_devices error: {status}")

        except Exception as e:
            logger.error(f"Error getting devices: {e}")

        return None

    # ===== FORTIVIEW FUNCTIONS =====
    
    def get_fortiview_data(self, adom: str = "root", view_name: str = "top-sources",
                          start_time: str = None, end_time: str = None, 
                          limit: int = 10, device_filter: str = None) -> Dict[str, Any]:
        """
        Busca dados do FortiView (análise de tráfego e segurança)
        
        Args:
            adom: Nome do ADOM
            view_name: Nome da view (top-sources, top-destinations, top-threats, etc.)
            start_time: Tempo de início (formato: YYYY-MM-DD HH:MM:SS)
            end_time: Tempo de fim (formato: YYYY-MM-DD HH:MM:SS)
            limit: Número máximo de registros
            device_filter: Filtro de dispositivo
            
        Returns:
            Dict com os dados da view
        """
        if not self.session_id:
            raise Exception("Não há sessão ativa")
        
        # Usar horários padrão se não especificados
        if not start_time or not end_time:
            end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            start_time = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            # Normalizar ADOM
            adom = adom.upper() if adom and adom.lower() != "root" else "root"
            
            # Preparar payload
            payload = {
                "url": f"/fortiview/adom/{adom}/{view_name}/run",
                "apiver": 3,
                "time-range": {
                    "start": start_time,
                    "end": end_time
                },
                "limit": limit,
                "count-total": True,
                # Sempre incluir device All_FortiGate para buscar de todos os devices
                "device": [{"devid": "All_FortiGate"}]
            }
            
            # Iniciar busca
            result = self._make_request(
                method="add",
                params=[payload]
            )
            
            if not result.get("result"):
                return {"error": f"Falha ao iniciar busca FortiView {view_name}", "data": []}
            
            # Extrair TID
            tid = result["result"]
            if isinstance(tid, list) and len(tid) > 0:
                tid = tid[0].get("tid")
            elif isinstance(tid, dict):
                tid = tid.get("tid")
            
            if not tid:
                return {"error": "TID não encontrado", "data": []}
            
            # Buscar resultados
            get_payload = {
                "url": f"/fortiview/adom/{adom}/{view_name}/run/{tid}",
                "apiver": 3
            }
            
            result = self._make_request(
                method="get",
                params=[get_payload]
            )
            
            if not result.get("result"):
                return {"error": "Falha ao buscar resultados", "data": []}
            
            data = result["result"]
            if isinstance(data, list) and len(data) > 0:
                data = data[0]
            
            total_count = data.get("total-count", 0)
            records = data.get("data", [])
            
            return {
                "success": True,
                "view_name": view_name,
                "total_count": total_count,
                "data": records,
                "adom": adom,
                "time_range": f"{start_time} - {end_time}"
            }
            
        except Exception as e:
            logger.error(f"Error getting FortiView data: {e}")
            return {"error": str(e), "data": []}

    def get_top_sources(self, adom: str = "root", start_time: str = None, 
                       end_time: str = None, limit: int = 10) -> Dict[str, Any]:
        """Busca top IPs de origem com mais tráfego"""
        return self.get_fortiview_data(adom, "top-sources", start_time, end_time, limit)

    def get_top_destinations(self, adom: str = "root", start_time: str = None, 
                            end_time: str = None, limit: int = 10) -> Dict[str, Any]:
        """Busca top IPs de destino com mais tráfego"""
        return self.get_fortiview_data(adom, "top-destinations", start_time, end_time, limit)

    def get_top_threats(self, adom: str = "root", start_time: str = None, 
                       end_time: str = None, limit: int = 10) -> Dict[str, Any]:
        """Busca top ameaças detectadas"""
        return self.get_fortiview_data(adom, "top-threats", start_time, end_time, limit)

    def get_top_applications(self, adom: str = "root", start_time: str = None, 
                            end_time: str = None, limit: int = 10) -> Dict[str, Any]:
        """Busca top aplicações utilizadas"""
        return self.get_fortiview_data(adom, "top-applications", start_time, end_time, limit)

    def get_top_countries(self, adom: str = "root", start_time: str = None, 
                         end_time: str = None, limit: int = 10) -> Dict[str, Any]:
        """Busca top países por tráfego"""
        return self.get_fortiview_data(adom, "top-countries", start_time, end_time, limit)

    def get_policy_hits(self, adom: str = "root", start_time: str = None, 
                       end_time: str = None, limit: int = 10) -> Dict[str, Any]:
        """Busca políticas de firewall mais utilizadas"""
        return self.get_fortiview_data(adom, "policy-hits", start_time, end_time, limit)

    # ===== EVENT MANAGEMENT FUNCTIONS =====
    
    def get_alerts(self, adom: str = "root", start_time: str = None, 
                   end_time: str = None, limit: int = 50, severity_filter: str = None) -> Dict[str, Any]:
        """
        Busca alertas de segurança
        
        Args:
            adom: Nome do ADOM
            start_time: Tempo de início
            end_time: Tempo de fim
            limit: Número máximo de alertas
            severity_filter: Filtro de severidade (critical, high, medium, low)
        """
        if not self.session_id:
            raise Exception("Não há sessão ativa")
        
        # Usar horários padrão se não especificados
        if not start_time or not end_time:
            end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            start_time = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            # Normalizar ADOM
            adom = adom.upper() if adom and adom.lower() != "root" else "root"
            
            # Preparar filtro
            filter_expr = ""
            if severity_filter:
                severity_map = {
                    "critical": "4",
                    "high": "3", 
                    "medium": "2",
                    "low": "1"
                }
                severity_num = severity_map.get(severity_filter.lower())
                if severity_num:
                    filter_expr = f"severity >= {severity_num}"
            
            payload = {
                "url": f"/eventmgmt/adom/{adom}/alerts",
                "apiver": 3,
                "time-range": {
                    "start": start_time,
                    "end": end_time
                },
                "limit": limit,
                "offset": 0
            }
            
            if filter_expr:
                payload["filter"] = filter_expr
            
            result = self._make_request(
                method="get",
                params=[payload]
            )
            
            if not result.get("result"):
                return {"error": "Falha ao buscar alertas", "alerts": []}
            
            alerts = result["result"].get("data", [])
            
            return {
                "success": True,
                "total_count": len(alerts),
                "alerts": alerts,
                "adom": adom,
                "time_range": f"{start_time} - {end_time}",
                "severity_filter": severity_filter
            }
            
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
            return {"error": str(e), "alerts": []}

    def get_alert_count(self, adom: str = "root", start_time: str = None, 
                       end_time: str = None, group_by: str = "severity") -> Dict[str, Any]:
        """
        Conta alertas por categoria
        
        Args:
            adom: Nome do ADOM
            start_time: Tempo de início
            end_time: Tempo de fim
            group_by: Agrupar por (severity, mgmt_state, etc.)
        """
        if not self.session_id:
            raise Exception("Não há sessão ativa")
        
        # Usar horários padrão se não especificados
        if not start_time or not end_time:
            end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            start_time = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            # Normalizar ADOM
            adom = adom.upper() if adom and adom.lower() != "root" else "root"
            
            payload = {
                "url": f"/eventmgmt/adom/{adom}/alerts/count",
                "apiver": 3,
                "time-range": {
                    "start": start_time,
                    "end": end_time
                },
                "group-by": group_by
            }
            
            result = self._make_request(
                method="get",
                params=[payload]
            )
            
            if not result.get("result"):
                return {"error": "Falha ao contar alertas", "counts": []}
            
            counts = result["result"].get("data", [])
            
            return {
                "success": True,
                "counts": counts,
                "adom": adom,
                "time_range": f"{start_time} - {end_time}",
                "group_by": group_by
            }
            
        except Exception as e:
            logger.error(f"Error getting alert count: {e}")
            return {"error": str(e), "counts": []}

    def _parse_time_range_string(self, time_range: str) -> Dict:
        """
        Converte string de tempo para formato FortiAnalyzer (string format)

        Args:
            time_range: String como "last-1-hour", "today", "last-7-days"

        Returns:
            Dict com start/end em formato 'YYYY-MM-DD HH:mm:ss'
        """
        now = datetime.now()

        if time_range == "last-1-hour":
            start = now - timedelta(hours=1)
        elif time_range == "last-2-hours":
            start = now - timedelta(hours=2)
        elif time_range == "last-6-hours":
            start = now - timedelta(hours=6)
        elif time_range == "last-12-hours":
            start = now - timedelta(hours=12)
        elif time_range == "last-24-hours":
            start = now - timedelta(hours=24)
        elif time_range == "last-6-days":
            start = now - timedelta(days=6)
        elif time_range == "last-7-days":
            start = now - timedelta(days=7)
        elif time_range == "last-15-days":
            start = now - timedelta(days=15)
        elif time_range == "last-30-days":
            start = now - timedelta(days=30)
        elif time_range == "today":
            start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif time_range == "yesterday":
            start = (now - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
            now = now.replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            # Default: última hora
            start = now - timedelta(hours=1)

        # Formato com segundos: "YYYY-MM-DD HH:mm:ss"
        return {
            "start": start.strftime("%Y-%m-%d %H:%M:%S"),
            "end": now.strftime("%Y-%m-%d %H:%M:%S")
        }

    def _parse_time_range(self, time_range: str) -> Dict:
        """
        Converte string de tempo para formato FortiAnalyzer (timestamp format)
        DEPRECATED: Usar _parse_time_range_string para novas implementações

        Args:
            time_range: String como "last-1-hour", "today", "last-7-days"

        Returns:
            Dict com from/to timestamps
        """
        now = datetime.now()

        if time_range == "last-1-hour":
            start = now - timedelta(hours=1)
        elif time_range == "last-2-hours":
            start = now - timedelta(hours=2)
        elif time_range == "last-24-hours":
            start = now - timedelta(hours=24)
        elif time_range == "today":
            start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif time_range == "last-7-days":
            start = now - timedelta(days=7)
        elif time_range == "last-30-days":
            start = now - timedelta(days=30)
        else:
            # Default: última hora
            start = now - timedelta(hours=1)

        return {
            "from": int(start.timestamp()),
            "to": int(now.timestamp())
        }

    def __enter__(self):
        """Context manager entry"""
        self.login()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.logout()
