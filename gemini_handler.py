#!/usr/bin/env python3
"""
Gemini AI Integration Handler
Gerencia interação com Google Gemini para processamento de NLU

⚠️ DEPRECATED: Este módulo está obsoleto a partir da v2.0.0
Use 'openai_handler.py' em seu lugar.

Mantido apenas para referência histórica e compatibilidade legacy.
"""

import google.generativeai as genai
from google.generativeai.types import content_types
from typing import Dict, List, Optional, Any
import json
import logging

logger = logging.getLogger(__name__)


class GeminiHandler:
    """Handler para integração com Google Gemini usando Function Calling"""

    def __init__(self, api_key: str, model_name: str = "gemini-pro"):
        """
        Inicializa handler do Gemini

        Args:
            api_key: API key do Google Gemini
            model_name: Nome do modelo (gemini-1.5-pro ou gemini-1.5-flash)
        """
        genai.configure(api_key=api_key)

        # Criar declarações de função usando o formato correto da API
        tools = self._create_tools()

        self.model = genai.GenerativeModel(
            model_name=model_name,
            tools=tools
        )
        self.chat = self.model.start_chat()

    def _create_tools(self):
        """
        Cria tools no formato correto para a API do Gemini
        """
        # Função 1: Status do Sistema
        get_system_status = genai.protos.FunctionDeclaration(
            name="get_system_status",
            description="Obtém informações sobre o status e saúde do sistema FortiAnalyzer (versão, hostname, serial, uptime, etc)",
            parameters=genai.protos.Schema(
                type=genai.protos.Type.OBJECT,
                properties={}
            )
        )

        # Função 2: Consultar Logs
        query_logs = genai.protos.FunctionDeclaration(
            name="query_logs",
            description="Consulta logs no FortiAnalyzer com filtros específicos",
            parameters=genai.protos.Schema(
                type=genai.protos.Type.OBJECT,
                properties={
                    "adom": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Nome do ADOM (domínio administrativo). Padrão: 'root'"
                    ),
                    "device": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="ID do device específico. Omitir para todos os devices."
                    ),
                    "logtype": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Tipo de log a consultar",
                        enum=["traffic", "event", "security", "attack", "virus", "webfilter", "app-ctrl"]
                    ),
                    "time_range": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Período de tempo para consulta",
                        enum=["last-1-hour", "last-2-hours", "last-6-hours", "last-12-hours", "last-24-hours", "today", "yesterday", "last-6-days", "last-7-days", "last-15-days", "last-30-days"]
                    ),
                    "filter_str": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Filtro adicional (ex: 'srcip==192.168.1.1', 'action==deny')"
                    ),
                    "limit": genai.protos.Schema(
                        type=genai.protos.Type.INTEGER,
                        description="Número máximo de registros (padrão: 100)"
                    )
                },
                required=["logtype", "time_range"]
            )
        )

        # Função 3: Contar Logs
        get_log_count = genai.protos.FunctionDeclaration(
            name="get_log_count",
            description="Conta o número total de logs em um período específico",
            parameters=genai.protos.Schema(
                type=genai.protos.Type.OBJECT,
                properties={
                    "adom": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Nome do ADOM (domínio administrativo). Padrão: 'root'"
                    ),
                    "device": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="ID do device específico. Omitir para todos os devices."
                    ),
                    "logtype": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Tipo de log a contar",
                        enum=["traffic", "event", "security", "attack", "virus", "webfilter", "app-ctrl"]
                    ),
                    "time_range": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Período de tempo",
                        enum=["last-1-hour", "last-2-hours", "last-24-hours", "today", "last-7-days", "last-30-days"]
                    ),
                    "filter_str": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Filtro adicional opcional"
                    )
                },
                required=["logtype", "time_range"]
            )
        )

        # Função 4: Top Sources
        get_top_sources = genai.protos.FunctionDeclaration(
            name="get_top_sources",
            description="FUNÇÃO PRINCIPAL para análise de tráfego. USE ESTA FUNÇÃO quando o usuário perguntar sobre: 'top IPs', 'principais IPs', 'IPs com mais tráfego', 'usuários que mais consumiram', 'maior consumo de banda', 'ranking de tráfego'. Retorna IPs de origem COM usuários, bandwidth, sessões. Tem FALLBACK inteligente que sempre retorna dados.",
            parameters=genai.protos.Schema(
                type=genai.protos.Type.OBJECT,
                properties={
                    "adom": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Nome do ADOM (domínio administrativo). Padrão: 'root'"
                    ),
                    "time_range": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Período de tempo",
                        enum=["last-1-hour", "last-2-hours", "last-6-hours", "last-12-hours", "last-24-hours", "today", "yesterday", "last-6-days", "last-7-days", "last-15-days", "last-30-days"]
                    ),
                    "limit": genai.protos.Schema(
                        type=genai.protos.Type.INTEGER,
                        description="Número de IPs a retornar (padrão: 10)"
                    )
                },
                required=["time_range"]
            )
        )

        # Função 5: Top Ameaças (FortiView)
        get_top_threats = genai.protos.FunctionDeclaration(
            name="get_top_threats",
            description="Busca as principais ameaças/ataques detectados no FortiAnalyzer usando FortiView. IMPORTANTE: Esta função retorna apenas ESTATÍSTICAS agregadas (top ameaças, contagem). Para informações DETALHADAS incluindo USUÁRIOS específicos, use 'get_logs' com logtype='attack'. Use esta função quando perguntar: 'quais ataques', 'principais ameaças', 'top ataques'.",
            parameters=genai.protos.Schema(
                type=genai.protos.Type.OBJECT,
                properties={
                    "adom": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Nome do ADOM (domínio administrativo). Padrão: 'root'"
                    ),
                    "time_range": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Período de tempo",
                        enum=["last-1-hour", "last-2-hours", "last-6-hours", "last-12-hours", "last-24-hours", "today", "yesterday", "last-6-days", "last-7-days", "last-15-days", "last-30-days"]
                    ),
                    "limit": genai.protos.Schema(
                        type=genai.protos.Type.INTEGER,
                        description="Número máximo de ameaças a retornar (padrão: 10)"
                    )
                },
                required=["time_range"]
            )
        )
        
        # Função 6: Logs Detalhados (COM informações de usuários)
        get_logs = genai.protos.FunctionDeclaration(
            name="get_logs",
            description="Busca logs DETALHADOS e RAW no FortiAnalyzer. USE SOMENTE quando o usuário pedir: 'logs detalhados', 'registros brutos', 'detalhes específicos de um evento'. NÃO USE para perguntas sobre 'top', 'mais', 'principais', 'ranking' - para essas use get_top_sources.",
            parameters=genai.protos.Schema(
                type=genai.protos.Type.OBJECT,
                properties={
                    "adom": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Nome do ADOM (domínio administrativo). Padrão: 'root'"
                    ),
                    "logtype": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Tipo de log. Use 'attack' para ataques/ameaças, 'traffic' para tráfego, 'security' para eventos de segurança",
                        enum=["traffic", "security", "event", "attack", "virus", "webfilter", "app-ctrl", "utm", "ips", "dns"]
                    ),
                    "time_range": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Período de tempo",
                        enum=["last-1-hour", "last-2-hours", "last-6-hours", "last-12-hours", "last-24-hours", "today", "yesterday", "last-6-days", "last-7-days", "last-15-days", "last-30-days"]
                    ),
                    "limit": genai.protos.Schema(
                        type=genai.protos.Type.INTEGER,
                        description="Número máximo de logs (padrão: 50, máximo recomendado: 100)"
                    )
                },
                required=["logtype", "time_range"]
            )
        )

        # Função 6: Tráfego Bloqueado
        get_blocked_traffic = genai.protos.FunctionDeclaration(
            name="get_blocked_traffic",
            description="Busca tráfego bloqueado pelas políticas de firewall",
            parameters=genai.protos.Schema(
                type=genai.protos.Type.OBJECT,
                properties={
                    "adom": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Nome do ADOM (domínio administrativo). Padrão: 'root'"
                    ),
                    "device": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="ID do device específico. Omitir para todos os devices."
                    ),
                    "time_range": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Período de tempo",
                        enum=["last-1-hour", "last-2-hours", "last-24-hours", "today", "last-7-days"]
                    ),
                    "limit": genai.protos.Schema(
                        type=genai.protos.Type.INTEGER,
                        description="Número máximo de registros (padrão: 100)"
                    )
                },
                required=["time_range"]
            )
        )

        # Função 7: Listar Dispositivos
        get_devices = genai.protos.FunctionDeclaration(
            name="get_devices",
            description="Lista todos os dispositivos (FortiGates, FortiMails, etc) registrados e gerenciados pelo FortiAnalyzer",
            parameters=genai.protos.Schema(
                type=genai.protos.Type.OBJECT,
                properties={
                    "adom": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Nome do ADOM (domínio administrativo). Use 'root' como padrão se não especificado."
                    )
                }
            )
        )

        # Função 8: Listar ADOMs
        get_adoms = genai.protos.FunctionDeclaration(
            name="get_adoms",
            description="Lista todos os ADOMs (Administrative Domains) disponíveis no FortiAnalyzer",
            parameters=genai.protos.Schema(
                type=genai.protos.Type.OBJECT,
                properties={}
            )
        )

        # Função 9: Sites Bloqueados
        get_blocked_websites = genai.protos.FunctionDeclaration(
            name="get_blocked_websites",
            description="Busca sites/URLs/domínios bloqueados pelo webfilter ou DNS filter. Inclui sites bloqueados por categoria (ex: redes sociais, proxy, etc) e domínios em listas de bloqueio. Use esta função para perguntas sobre sites, URLs ou domínios bloqueados.",
            parameters=genai.protos.Schema(
                type=genai.protos.Type.OBJECT,
                properties={
                    "adom": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Nome do ADOM (domínio administrativo). Padrão: 'root'"
                    ),
                    "device": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="ID do device específico. Omitir para todos os devices."
                    ),
                    "time_range": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Período de tempo",
                        enum=["last-1-hour", "last-2-hours", "last-6-hours", "last-12-hours", "last-24-hours", "today", "yesterday", "last-6-days", "last-7-days", "last-15-days", "last-30-days"]
                    ),
                    "limit": genai.protos.Schema(
                        type=genai.protos.Type.INTEGER,
                        description="Número máximo de registros (padrão: 100)"
                    )
                },
                required=["time_range"]
            )
        )

        # Função 10: Sites Permitidos
        get_allowed_websites = genai.protos.FunctionDeclaration(
            name="get_allowed_websites",
            description="Busca sites/URLs permitidos/acessados pelo webfilter",
            parameters=genai.protos.Schema(
                type=genai.protos.Type.OBJECT,
                properties={
                    "adom": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Nome do ADOM (domínio administrativo). Padrão: 'root'"
                    ),
                    "device": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="ID do device específico. Omitir para todos os devices."
                    ),
                    "time_range": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Período de tempo",
                        enum=["last-1-hour", "last-2-hours", "last-6-hours", "last-12-hours", "last-24-hours", "today", "yesterday", "last-6-days", "last-7-days", "last-15-days", "last-30-days"]
                    ),
                    "limit": genai.protos.Schema(
                        type=genai.protos.Type.INTEGER,
                        description="Número máximo de registros (padrão: 100)"
                    )
                },
                required=["time_range"]
            )
        )

        # Função 11: Aplicações Bloqueadas
        get_blocked_applications = genai.protos.FunctionDeclaration(
            name="get_blocked_applications",
            description="Busca aplicações e serviços específicos bloqueados pelo Application Control (ex: Facebook, Teams, WhatsApp, Skype, Dropbox). NÃO use esta função para ataques IPS/IDS - para ataques use get_security_events. Use esta função SOMENTE quando o usuário perguntar especificamente sobre 'aplicações bloqueadas', 'apps bloqueados', 'serviços bloqueados' como redes sociais, aplicativos de comunicação, ou serviços específicos.",
            parameters=genai.protos.Schema(
                type=genai.protos.Type.OBJECT,
                properties={
                    "adom": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Nome do ADOM (domínio administrativo). Padrão: 'root'"
                    ),
                    "device": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="ID do device específico. Omitir para todos os devices."
                    ),
                    "time_range": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Período de tempo",
                        enum=["last-1-hour", "last-2-hours", "last-6-hours", "last-12-hours", "last-24-hours", "today", "yesterday", "last-6-days", "last-7-days", "last-15-days", "last-30-days"]
                    ),
                    "limit": genai.protos.Schema(
                        type=genai.protos.Type.INTEGER,
                        description="Número máximo de registros (padrão: 100)"
                    )
                },
                required=["time_range"]
            )
        )

        # Função 12: Aplicações Permitidas
        get_allowed_applications = genai.protos.FunctionDeclaration(
            name="get_allowed_applications",
            description="Busca aplicações permitidas/utilizadas pelo Application Control",
            parameters=genai.protos.Schema(
                type=genai.protos.Type.OBJECT,
                properties={
                    "adom": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Nome do ADOM (domínio administrativo). Padrão: 'root'"
                    ),
                    "device": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="ID do device específico. Omitir para todos os devices."
                    ),
                    "time_range": genai.protos.Schema(
                        type=genai.protos.Type.STRING,
                        description="Período de tempo",
                        enum=["last-1-hour", "last-2-hours", "last-6-hours", "last-12-hours", "last-24-hours", "today", "yesterday", "last-6-days", "last-7-days", "last-15-days", "last-30-days"]
                    ),
                    "limit": genai.protos.Schema(
                        type=genai.protos.Type.INTEGER,
                        description="Número máximo de registros (padrão: 100)"
                    )
                },
                required=["time_range"]
            )
        )

        # Criar Tool com todas as funções
        tool = genai.protos.Tool(
            function_declarations=[
                get_system_status,
                query_logs,
                get_log_count,
                get_top_sources,
                get_top_threats,      # NOVA - Para ataques/ameaças
                get_logs,             # NOVA - Para logs detalhados com usuários
                get_devices,
                get_adoms,
                # Mantendo funções legadas temporariamente
                get_blocked_traffic,
                get_blocked_websites,
                get_allowed_websites,
                get_blocked_applications,
                get_allowed_applications
            ]
        )

        return [tool]

    def process_question(self, question: str) -> Dict[str, Any]:
        """
        Processa pergunta do usuário e identifica função a chamar

        Args:
            question: Pergunta em linguagem natural

        Returns:
            Dict com função e parâmetros extraídos
        """
        try:
            # Adicionar contexto ao prompt
            enhanced_prompt = f"""
Você é um assistente especializado em FortiAnalyzer que ajuda usuários a consultar
logs e dados de segurança usando linguagem natural.

Analise a pergunta abaixo e determine qual função chamar e com quais parâmetros.

Pergunta do usuário: {question}

Regras importantes:
- Se o usuário perguntar "quantos logs", "total de logs", use get_log_count
- Se pedir "mostre logs", "exiba logs", "liste logs", use query_logs
- Se pedir "top IPs", "principais IPs", "IPs com mais tráfego", use get_top_sources
- CRÍTICO: Se perguntar sobre "ataques", "ataques bloqueados", "ataques detectados", "tentativas de ataque", "ameaças", "exploits", "IPS", "IDS", "eventos de segurança", use SEMPRE get_security_events
- Se perguntar sobre "bloqueios" de tráfego genérico, "tráfego bloqueado", "conexões negadas", use get_blocked_traffic
- Se perguntar sobre "status", "versão", "informações do sistema", use get_system_status
- Se perguntar sobre "dispositivos", "equipamentos", "FortiGates", "devices", "lista de equipamentos", use get_devices
- Se perguntar sobre "ADOMs", "domínios administrativos", "lista de ADOMs", "quais ADOMs", use get_adoms
- IMPORTANTE: Se perguntar sobre "sites bloqueados", "URLs bloqueadas", "websites bloqueados", "domínios bloqueados", use get_blocked_websites
- IMPORTANTE: Se perguntar sobre "sites permitidos", "URLs permitidas", "sites acessados", use get_allowed_websites
- IMPORTANTE: Se perguntar sobre "aplicações bloqueadas" (Facebook, Teams, WhatsApp), "apps bloqueados", "serviços bloqueados", use get_blocked_applications (NÃO confundir com ataques!)
- IMPORTANTE: Se perguntar sobre "aplicações permitidas", "apps permitidos", "aplicações acessadas", use get_allowed_applications
- NOTA: "Ataques" são eventos IPS/IDS (use get_security_events), "Aplicações" são apps específicos como Facebook (use get_blocked_applications)
- Interprete expressões de tempo em português (ex: "hoje", "última hora", "últimas 24 horas", "últimos 6 dias", "últimos 15 dias", "últimos 30 dias")
- Se o usuário mencionar um ADOM ou "ambiente" específico (ex: "ambiente cofema", "no cofema"), inclua o parâmetro "adom" com esse nome
- Se o usuário mencionar um device específico, inclua o parâmetro "device"; se pedir por todos, omita o parâmetro
"""

            response = self.chat.send_message(enhanced_prompt)

            # Verificar se Gemini retornou function call
            if response.candidates[0].content.parts:
                for part in response.candidates[0].content.parts:
                    if hasattr(part, 'function_call') and part.function_call:
                        fc = part.function_call
                        return {
                            "function_name": fc.name,
                            "parameters": dict(fc.args),
                            "success": True
                        }

            # Se não retornou function call, gerar pergunta de esclarecimento útil
            try:
                clarify_prompt = f"""
Crie uma pergunta de esclarecimento curta e objetiva em português para um usuário de FortiAnalyzer.
A pergunta original foi: "{question}"

Quando faltar informações essenciais (ex: qual função consultar, período de tempo, tipo de log, severidade ou ADOM), pergunte exatamente o que falta.
Sugira opções comuns quando fizer sentido, por exemplo:
- Tipo de consulta: status do sistema, logs, eventos de segurança, tráfego bloqueado, top IPs
- Período: última 1 hora, últimas 24 horas, hoje, últimos 7 dias
- Tipo de log: traffic, event, security, webfilter, app-ctrl
- ADOM: informe o nome do ADOM (padrão: root)

Saída: uma única pergunta curta (sem explicação adicional).
"""
                clarifier = self.model.generate_content(clarify_prompt)
                clarification = clarifier.text.strip() if hasattr(clarifier, 'text') and clarifier.text else "Pode especificar o que deseja consultar (ex.: eventos de segurança, período e ADOM)?"
            except Exception:
                clarification = "Pode especificar o que deseja consultar (ex.: eventos de segurança, período e ADOM)?"

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
            prompt = f"""
Você é um assistente de FortiAnalyzer. O usuário fez a seguinte pergunta:
"{question}"

Você executou a função: {function_name}

E obteve o seguinte resultado:
{json.dumps(function_result, indent=2, default=str)}

Agora, gere uma resposta clara e útil em português brasileiro para o usuário.

Regras:
- Seja conciso e objetivo
- Use linguagem clara e profissional
- Se houver muitos dados, resuma os principais pontos
- Se for uma lista, mostre os itens mais relevantes
- Inclua números e estatísticas quando relevante
- Se não houver dados, explique de forma amigável
"""

            response = self.model.generate_content(prompt)
            return response.text

        except Exception as e:
            logger.error(f"Error formatting response: {e}")
            return f"Obtive os dados, mas tive dificuldade em formatá-los. Resultado: {function_result}"

    def chat_message(self, message: str) -> str:
        """
        Envia mensagem simples ao chat (sem function calling)

        Args:
            message: Mensagem do usuário

        Returns:
            Resposta do Gemini
        """
        try:
            response = self.chat.send_message(message)
            return response.text
        except Exception as e:
            logger.error(f"Error in chat: {e}")
            return f"Erro ao processar mensagem: {str(e)}"

    def reset_chat(self):
        """Reinicia a conversa"""
        self.chat = self.model.start_chat()
        logger.info("Chat reset")
