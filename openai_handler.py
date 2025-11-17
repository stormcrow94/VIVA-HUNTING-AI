#!/usr/bin/env python3
"""
OpenAI Integration Handler
Gerencia interação com OpenAI para processamento de NLU
Substitui o Gemini Handler com melhor custo-benefício
"""

from openai import OpenAI
from typing import Dict, List, Optional, Any
import json
import logging

logger = logging.getLogger(__name__)


class OpenAIHandler:
    """Handler para integração com OpenAI usando Function Calling com memória contextual"""

    def __init__(self, api_key: str, model_name: str = "gpt-4o-mini"):
        """
        Inicializa handler da OpenAI

        Args:
            api_key: API key da OpenAI
            model_name: Nome do modelo (gpt-4o-mini recomendado para custo-benefício)
        """
        self.client = OpenAI(api_key=api_key)
        self.model_name = model_name
        self.conversation_history = []
        
        # Contexto da sessão atual
        self.session_context = {
            "current_adom": None,
            "last_query_type": None,
            "last_logtype": None,  # Logtype usado na última consulta (webfilter, app-ctrl, etc)
            "last_time_range": None,
            "last_results_summary": None,
            "mentioned_devices": [],
            "conversation_topics": []
        }
        
        # Definir as funções disponíveis para o modelo
        self.tools = self._create_tools()

    def _create_tools(self) -> List[Dict]:
        """
        Cria tools no formato da OpenAI Function Calling
        """
        return [
            {
                "type": "function",
                "function": {
                    "name": "get_system_status",
                    "description": "Obtém informações sobre o status e saúde do sistema FortiAnalyzer (versão, hostname, serial, uptime, etc)",
                    "parameters": {
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "query_logs",
                    "description": "Consulta logs no FortiAnalyzer com filtros específicos",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "adom": {
                                "type": "string",
                                "description": "Nome do ADOM (domínio administrativo). Padrão: 'root'"
                            },
                            "device": {
                                "type": "string",
                                "description": "ID do device específico. Omitir para todos os devices."
                            },
                            "logtype": {
                                "type": "string",
                                "description": "Tipo de log a consultar. IMPORTANTE: Para 'eventos de segurança' use 'event', para 'ataques/IPS' use 'attack'",
                                "enum": ["traffic", "event", "attack", "virus", "webfilter", "app-ctrl", "content", "dlp", "emailfilter"]
                            },
                            "time_range": {
                                "type": "string",
                                "description": "Período de tempo para consulta",
                                "enum": ["last-1-hour", "last-2-hours", "last-6-hours", "last-12-hours", "last-24-hours", "today", "yesterday", "last-6-days", "last-7-days", "last-15-days", "last-30-days"]
                            },
                            "filter_str": {
                                "type": "string",
                                "description": "Filtro adicional (ex: 'srcip==192.168.1.1', 'action==deny')"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Número máximo de registros (padrão: 100)"
                            }
                        },
                        "required": ["logtype", "time_range"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_log_count",
                    "description": "Conta o número total de logs em um período específico",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "adom": {
                                "type": "string",
                                "description": "Nome do ADOM (domínio administrativo). Padrão: 'root'"
                            },
                            "device": {
                                "type": "string",
                                "description": "ID do device específico. Omitir para todos os devices."
                            },
                            "logtype": {
                                "type": "string",
                                "description": "Tipo de log a contar. IMPORTANTE: Para 'eventos de segurança' use 'event', para 'ataques/IPS' use 'attack'",
                                "enum": ["traffic", "event", "attack", "virus", "webfilter", "app-ctrl", "content", "dlp", "emailfilter"]
                            },
                            "time_range": {
                                "type": "string",
                                "description": "Período de tempo",
                                "enum": ["last-1-hour", "last-2-hours", "last-24-hours", "today", "last-7-days", "last-30-days"]
                            },
                            "filter_str": {
                                "type": "string",
                                "description": "Filtro adicional opcional"
                            }
                        },
                        "required": ["logtype", "time_range"]
                    }
                }
            },
            # TEMPORARIAMENTE DESABILITADO: get_top_sources (FortiView não disponível via API)
            # Será reativado quando FortiView for configurado no FortiAnalyzer
            {
                "type": "function",
                "function": {
                    "name": "get_top_threats",
                    "description": "AVANÇADO: Usa FortiView para estatísticas agregadas de ameaças (pode não estar disponível em todos ADOMs). PREFIRA usar 'query_logs' com logtype='attack' para consultas básicas de ataques. USE get_top_threats SOMENTE quando o usuário pedir explicitamente 'ranking', 'top X', 'mais frequentes'.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "adom": {
                                "type": "string",
                                "description": "Nome do ADOM (domínio administrativo). Padrão: 'root'"
                            },
                            "time_range": {
                                "type": "string",
                                "description": "Período de tempo",
                                "enum": ["last-1-hour", "last-2-hours", "last-6-hours", "last-12-hours", "last-24-hours", "today", "yesterday", "last-6-days", "last-7-days", "last-15-days", "last-30-days"]
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Número máximo de ameaças a retornar (padrão: 10)"
                            }
                        },
                        "required": ["time_range"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_logs",
                    "description": "Busca logs DETALHADOS e RAW no FortiAnalyzer. USE SOMENTE quando o usuário pedir: 'logs detalhados', 'registros brutos', 'detalhes específicos de um evento'. NÃO USE para perguntas sobre 'top', 'mais', 'principais', 'ranking'.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "adom": {
                                "type": "string",
                                "description": "Nome do ADOM (domínio administrativo). Padrão: 'root'"
                            },
                            "logtype": {
                                "type": "string",
                                "description": "Tipo de log. IMPORTANTE: Use 'event' para eventos de segurança gerais, 'attack' para ataques/IPS, 'traffic' para tráfego de rede",
                                "enum": ["traffic", "event", "attack", "virus", "webfilter", "app-ctrl", "content", "dlp", "emailfilter"]
                            },
                            "time_range": {
                                "type": "string",
                                "description": "Período de tempo",
                                "enum": ["last-1-hour", "last-2-hours", "last-6-hours", "last-12-hours", "last-24-hours", "today", "yesterday", "last-6-days", "last-7-days", "last-15-days", "last-30-days"]
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Número máximo de logs (padrão: 50, máximo recomendado: 100)"
                            }
                        },
                        "required": ["logtype", "time_range"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_blocked_traffic",
                    "description": "Busca tráfego bloqueado pelas políticas de firewall",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "adom": {
                                "type": "string",
                                "description": "Nome do ADOM (domínio administrativo). Padrão: 'root'"
                            },
                            "device": {
                                "type": "string",
                                "description": "ID do device específico. Omitir para todos os devices."
                            },
                            "time_range": {
                                "type": "string",
                                "description": "Período de tempo",
                                "enum": ["last-1-hour", "last-2-hours", "last-24-hours", "today", "last-7-days"]
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Número máximo de registros (padrão: 100)"
                            }
                        },
                        "required": ["time_range"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_devices",
                    "description": "Lista todos os dispositivos (FortiGates, FortiMails, etc) registrados e gerenciados pelo FortiAnalyzer",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "adom": {
                                "type": "string",
                                "description": "Nome do ADOM (domínio administrativo). Use 'root' como padrão se não especificado."
                            }
                        },
                        "required": []
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_adoms",
                    "description": "Lista todos os ADOMs (Administrative Domains) disponíveis no FortiAnalyzer",
                    "parameters": {
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_blocked_websites",
                    "description": "Busca sites/URLs/domínios bloqueados pelo webfilter ou DNS filter. Inclui sites bloqueados por categoria (ex: redes sociais, proxy, etc) e domínios em listas de bloqueio.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "adom": {
                                "type": "string",
                                "description": "Nome do ADOM (domínio administrativo). Padrão: 'root'"
                            },
                            "device": {
                                "type": "string",
                                "description": "ID do device específico. Omitir para todos os devices."
                            },
                            "time_range": {
                                "type": "string",
                                "description": "Período de tempo",
                                "enum": ["last-1-hour", "last-2-hours", "last-6-hours", "last-12-hours", "last-24-hours", "today", "yesterday", "last-6-days", "last-7-days", "last-15-days", "last-30-days"]
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Número máximo de registros (padrão: 100)"
                            }
                        },
                        "required": ["time_range"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_allowed_websites",
                    "description": "Busca sites/URLs permitidos/acessados pelo webfilter",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "adom": {
                                "type": "string",
                                "description": "Nome do ADOM (domínio administrativo). Padrão: 'root'"
                            },
                            "device": {
                                "type": "string",
                                "description": "ID do device específico. Omitir para todos os devices."
                            },
                            "time_range": {
                                "type": "string",
                                "description": "Período de tempo",
                                "enum": ["last-1-hour", "last-2-hours", "last-6-hours", "last-12-hours", "last-24-hours", "today", "yesterday", "last-6-days", "last-7-days", "last-15-days", "last-30-days"]
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Número máximo de registros (padrão: 100)"
                            }
                        },
                        "required": ["time_range"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_blocked_applications",
                    "description": "Busca aplicações e serviços específicos bloqueados pelo Application Control (ex: Facebook, Teams, WhatsApp, Skype, Dropbox). NÃO use para ataques IPS/IDS.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "adom": {
                                "type": "string",
                                "description": "Nome do ADOM (domínio administrativo). Padrão: 'root'"
                            },
                            "device": {
                                "type": "string",
                                "description": "ID do device específico. Omitir para todos os devices."
                            },
                            "time_range": {
                                "type": "string",
                                "description": "Período de tempo",
                                "enum": ["last-1-hour", "last-2-hours", "last-6-hours", "last-12-hours", "last-24-hours", "today", "yesterday", "last-6-days", "last-7-days", "last-15-days", "last-30-days"]
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Número máximo de registros (padrão: 100)"
                            }
                        },
                        "required": ["time_range"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_allowed_applications",
                    "description": "Busca aplicações permitidas/utilizadas pelo Application Control",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "adom": {
                                "type": "string",
                                "description": "Nome do ADOM (domínio administrativo). Padrão: 'root'"
                            },
                            "device": {
                                "type": "string",
                                "description": "ID do device específico. Omitir para todos os devices."
                            },
                            "time_range": {
                                "type": "string",
                                "description": "Período de tempo",
                                "enum": ["last-1-hour", "last-2-hours", "last-6-hours", "last-12-hours", "last-24-hours", "today", "yesterday", "last-6-days", "last-7-days", "last-15-days", "last-30-days"]
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Número máximo de registros (padrão: 100)"
                            }
                        },
                        "required": ["time_range"]
                    }
                }
            }
        ]

    def process_question(self, question: str) -> Dict[str, Any]:
        """
        Processa pergunta do usuário e identifica função a chamar
        Mantém contexto da conversação para queries em sequência

        Args:
            question: Pergunta em linguagem natural

        Returns:
            Dict com função e parâmetros extraídos
        """
        try:
            # Construir contexto da conversa
            context_info = self._build_context_string()
            
            # Criar mensagem com contexto para o modelo
            system_message = f"""Você é um assistente especializado em FortiAnalyzer que ajuda usuários a consultar
logs e dados de segurança usando linguagem natural.

{context_info}

Analise a pergunta do usuário e determine qual função chamar e com quais parâmetros.

Regras importantes:
- LOGTYPES: 'event' para eventos de segurança gerais, 'attack' para ataques/IPS/ameaças, 'traffic' para tráfego, 'webfilter' para sites, 'app-ctrl' para aplicações
- Se o usuário perguntar "quantos logs", "total de logs", use get_log_count
- Se pedir "mostre logs", "exiba logs", "liste logs", "últimos eventos", use query_logs com logtype apropriado
- Se pedir "eventos de segurança", "alertas", "eventos críticos", use query_logs com logtype='event'
- Se pedir "ataques", "ataques bloqueados", "ameaças", "exploits", "IPS", "invasões", use query_logs com logtype='attack' (NÃO use get_top_threats ou get_blocked_traffic)
- Se pedir "top IPs", "principais IPs", "IPs com mais tráfego", "máquina que mais consumiu", "consumo de banda", use query_logs com logtype='traffic' e analise os bytes enviados/recebidos
- Se perguntar sobre "bloqueios" de tráfego, "tráfego bloqueado", use get_blocked_traffic
- Se perguntar sobre "sites bloqueados", "URLs bloqueadas", use get_blocked_websites
- Se perguntar sobre "aplicações bloqueadas" (Facebook, Teams), use get_blocked_applications
- Se perguntar sobre "status do FortiAnalyzer", "versão do FortiAnalyzer", use get_system_status
- IMPORTANTE: get_system_status retorna informações do SERVIDOR FortiAnalyzer, NÃO dos firewalls gerenciados
- Se perguntar sobre "firewall específico", "memória do firewall", "CPU do firewall", "performance de um firewall", use query_logs com logtype='event' e filtro para o device
- Se perguntar sobre "dispositivos", "FortiGates", "lista de firewalls", use get_devices
- Se perguntar sobre "ADOMs", use get_adoms
- Interprete expressões de tempo em português (ex: "hoje", "última hora", "últimas 24 horas", "últimos 7 dias")
- Se o usuário mencionar um ADOM específico (ex: "no adom dekra", "adom cofema"), inclua o parâmetro "adom" com esse nome
- Se mencionar um device/firewall específico pelo nome (ex: "firewall guimaraes sanches", "no FGT-XYZ"), inclua o parâmetro "device" com esse nome
- IMPORTANTE: Métricas de performance (CPU, memória, disk) de firewalls são encontradas em logs do tipo 'event' com subtype='system'
- Exemplo: "memoria do firewall X" → use query_logs com logtype='event' e device='X'
- CRÍTICO - CONTEXTO DE FOLLOW-UP: Se o usuário perguntar "e os usuários?", "quais IPs?", "qual a origem?", "e os detalhes?" logo após uma consulta, você DEVE usar o mesmo logtype da consulta anterior que está no contexto
- Exemplo: Se last_query_type='get_blocked_websites', e usuário pergunta "e os usuários envolvidos?", use get_logs com logtype='webfilter' (não 'event')
- Exemplo: Se last_query_type='get_blocked_applications', e usuário pergunta "quais IPs?", use get_logs com logtype='app-ctrl' (não 'event')
- Os logs webfilter, app-ctrl, attack, traffic TÊM campos de srcip, dstip, user - use-os para perguntas de follow-up
"""
            
            messages = [
                {"role": "system", "content": system_message},
                *self.conversation_history[-10:],  # Últimas 10 mensagens para contexto
                {"role": "user", "content": question}
            ]

            # Fazer chamada à API da OpenAI com function calling
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                tools=self.tools,
                tool_choice="auto"
            )

            # Processar resposta
            message = response.choices[0].message

            # Verificar se o modelo quer chamar uma função
            if message.tool_calls:
                tool_call = message.tool_calls[0]
                function_name = tool_call.function.name
                function_args = json.loads(tool_call.function.arguments)

                # Adicionar apenas a pergunta do usuário ao histórico
                # A resposta da função será adicionada depois via format_response
                self.conversation_history.append({
                    "role": "user",
                    "content": question
                })

                return {
                    "function_name": function_name,
                    "parameters": function_args,
                    "success": True,
                    "tool_call_id": tool_call.id  # Salvar ID para resposta posterior
                }

            # Se não retornou function call, pedir esclarecimento
            clarification = message.content if message.content else "Pode especificar o que deseja consultar (ex.: eventos de segurança, período e ADOM)?"

            return {
                "function_name": None,
                "parameters": {},
                "success": False,
                "message": clarification
            }

        except Exception as e:
            logger.error(f"Error processing question: {e}")
            return {
                "function_name": None,
                "parameters": {},
                "success": False,
                "message": f"Erro ao processar pergunta: {str(e)}"
            }

    def format_response(self, question: str, function_result: Any, function_name: str) -> str:
        """
        Formata resultado da função em resposta humanizada

        Args:
            question: Pergunta original do usuário
            function_result: Resultado da função executada
            function_name: Nome da função que foi executada

        Returns:
            Resposta formatada em linguagem natural
        """
        try:
            # Criar mensagem para formatação (sem usar o histórico problemático)
            messages = [
                {
                    "role": "system",
                    "content": """Você é um assistente de FortiAnalyzer. Formate os resultados de forma clara e direta em português brasileiro.

Regras:
- Seja conciso e objetivo
- Responda DIRETO ao usuário em tom conversacional (sem "Caro usuário", sem assinatura, sem [Seu Nome])
- Use linguagem clara e técnica quando apropriado
- Se houver muitos dados, resuma os principais pontos
- Se for uma lista, mostre os itens mais relevantes
- Inclua números e estatísticas quando relevante
- Se não houver dados suficientes:
  * Explique exatamente o que foi buscado
  * Informe quais dados foram retornados (se houver)
  * Sugira alternativas práticas (ex: "Você pode verificar no FortiView do FortiAnalyzer")
  * Seja específico sobre o que falta (ex: "Logs de eventos de sistema não contêm histórico de memória")
- NUNCA use formato de email formal, assinatura ou placeholder como "[Seu Nome]"
"""
                },
                {
                    "role": "user",
                    "content": f"""O usuário fez a seguinte pergunta:
"{question}"

Você executou a função: {function_name}

E obteve o seguinte resultado:
{json.dumps(function_result, indent=2, default=str, ensure_ascii=False)}

IMPORTANTE:
- Se o resultado contém "auto_corrected": true:
  * Explique que o sistema corrigiu automaticamente o nome do dispositivo
  * Mostre qual device foi usado (campo "used_device")
  * Processe normalmente os dados retornados (campo "data")
  * Exemplo: "Você perguntou sobre 'guimaraes sanches', mas identifiquei automaticamente que se refere ao firewall 'GUIMARAES-SANCHES-1'. Aqui estão os resultados:"
- Se o resultado contém "error": "device_not_accessible":
  * Explique que o dispositivo EXISTE mas não pode ser acessado no momento
  * Possíveis causas: device offline, sem logs no período consultado, sem permissão
  * Sugira verificar no FortiAnalyzer se o device está online
  * Liste outros devices disponíveis como alternativa
- Se o resultado contém "error": "device_not_found":
  * Explique que o dispositivo não foi encontrado
  * Liste TODOS os dispositivos disponíveis como alternativas
  * Sugira ao usuário repetir a consulta com o nome correto
- Se o resultado é None ou vazio, explique claramente o que foi buscado e sugira alternativas específicas
- Seja direto, útil e específico na resposta

Gere uma resposta clara e útil para o usuário."""
                }
            ]

            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                temperature=0.7
            )

            formatted_response = response.choices[0].message.content
            
            # Adicionar a resposta ao histórico de conversação
            self.conversation_history.append({
                "role": "assistant",
                "content": formatted_response
            })

            return formatted_response

        except Exception as e:
            logger.error(f"Error formatting response: {e}")
            return f"Obtive os dados, mas tive dificuldade em formatá-los. Resultado: {function_result}"

    def chat_message(self, message: str) -> str:
        """
        Envia mensagem simples ao chat (sem function calling)

        Args:
            message: Mensagem do usuário

        Returns:
            Resposta da OpenAI
        """
        try:
            self.conversation_history.append({
                "role": "user",
                "content": message
            })

            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=self.conversation_history
            )

            assistant_message = response.choices[0].message.content
            
            self.conversation_history.append({
                "role": "assistant",
                "content": assistant_message
            })

            return assistant_message

        except Exception as e:
            logger.error(f"Error in chat: {e}")
            return f"Erro ao processar mensagem: {str(e)}"

    def _build_context_string(self) -> str:
        """
        Constrói string de contexto da sessão atual
        
        Returns:
            String com informações de contexto
        """
        context_parts = []
        
        if self.session_context["current_adom"]:
            context_parts.append(f"ADOM atual: {self.session_context['current_adom']}")
        
        if self.session_context["last_query_type"]:
            context_parts.append(f"Última consulta: {self.session_context['last_query_type']}")
        
        if self.session_context.get("last_logtype"):
            context_parts.append(f"IMPORTANTE - Último logtype usado: {self.session_context['last_logtype']} (use este para follow-ups sobre usuários/IPs)")
        
        if self.session_context["last_time_range"]:
            context_parts.append(f"Último período: {self.session_context['last_time_range']}")
        
        if self.session_context["last_results_summary"]:
            context_parts.append(f"Resumo do último resultado: {self.session_context['last_results_summary']}")
        
        if self.session_context["mentioned_devices"]:
            devices = ", ".join(self.session_context["mentioned_devices"][-3:])  # Últimos 3
            context_parts.append(f"Dispositivos mencionados: {devices}")
        
        if context_parts:
            return "CONTEXTO DA SESSÃO ATUAL:\n" + "\n".join(context_parts) + "\n"
        
        return ""
    
    def update_context(self, function_name: str, parameters: Dict, result: Any):
        """
        Atualiza contexto da sessão com informações da última query
        
        Args:
            function_name: Nome da função executada
            parameters: Parâmetros usados
            result: Resultado obtido
        """
        # Atualizar ADOM atual
        if "adom" in parameters:
            self.session_context["current_adom"] = parameters["adom"]
        
        # Atualizar tipo de consulta
        self.session_context["last_query_type"] = function_name
        
        # Atualizar logtype usado (IMPORTANTE para follow-ups)
        if "logtype" in parameters:
            self.session_context["last_logtype"] = parameters["logtype"]
        else:
            # Mapear funções para logtypes implícitos
            logtype_mapping = {
                "get_blocked_websites": "webfilter",
                "get_allowed_websites": "webfilter",
                "get_blocked_applications": "app-ctrl",
                "get_allowed_applications": "app-ctrl",
                "get_blocked_traffic": "attack"
            }
            self.session_context["last_logtype"] = logtype_mapping.get(function_name, None)
        
        # Atualizar time range
        if "time_range" in parameters:
            self.session_context["last_time_range"] = parameters["time_range"]
        
        # Criar resumo do resultado
        if isinstance(result, dict):
            if "data" in result and isinstance(result["data"], list):
                count = len(result["data"])
                self.session_context["last_results_summary"] = f"{count} registros retornados"
            elif "count" in result:
                self.session_context["last_results_summary"] = f"{result['count']} registros encontrados"
        elif isinstance(result, list):
            count = len(result)
            self.session_context["last_results_summary"] = f"{count} registros retornados"
        
        # Registrar tópico da conversa
        if function_name not in self.session_context["conversation_topics"]:
            self.session_context["conversation_topics"].append(function_name)
        
        logger.info(f"Context updated: {self.session_context}")
    
    def reset_chat(self):
        """Reinicia a conversa e limpa o contexto"""
        self.conversation_history = []
        self.session_context = {
            "current_adom": None,
            "last_query_type": None,
            "last_logtype": None,
            "last_time_range": None,
            "last_results_summary": None,
            "mentioned_devices": [],
            "conversation_topics": []
        }
        logger.info("Chat and context reset")

