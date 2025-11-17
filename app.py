#!/usr/bin/env python3
"""
VIVA-HUNTING-AI - FastAPI Backend
Backend REST API para o chatbot com integração Gemini + FortiAnalyzer
Desenvolvido por stormcrow94
"""

from fastapi import FastAPI, HTTPException, Request, Depends, Form, Response, Cookie
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any
import os
import logging
from dotenv import load_dotenv
from datetime import datetime, timedelta
import asyncio

from fortianalyzer_connector import FortiAnalyzerConnector
from openai_handler import OpenAIHandler
from auth import (
    authenticate_user,
    create_access_token,
    get_current_user_from_cookie,
    get_current_user_from_bearer,
    is_saml_enabled,
    get_saml_login_url,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    require_admin,
    get_all_users,
    create_user,
    update_user,
    delete_user,
    get_user_allowed_adoms,
    user_can_access_adom
)
from new_functions import (
    # get_top_sources, # DESABILITADO: FortiView não disponível via API
    get_top_destinations, get_top_threats, 
    get_top_applications, get_top_countries, get_policy_hits, 
    get_alerts, get_alert_count
)

# Carregar variáveis de ambiente
load_dotenv()

# Configurar logging
logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO")),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Inicializar FastAPI
app = FastAPI(
    title="VIVA-HUNTING-AI",
    description="Chatbot inteligente para consultas ao FortiAnalyzer usando OpenAI GPT-4o-mini",
    version="2.1.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configurações
FAZ_HOST = os.getenv("FAZ_HOST")
FAZ_USERNAME = os.getenv("FAZ_USERNAME")
FAZ_PASSWORD = os.getenv("FAZ_PASSWORD")
FAZ_VERIFY_SSL = os.getenv("FAZ_VERIFY_SSL", "false").lower() == "true"
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

# Validar configurações
if not all([FAZ_HOST, FAZ_USERNAME, FAZ_PASSWORD, OPENAI_API_KEY]):
    logger.error("Missing required environment variables!")
    raise ValueError("Please configure .env file with all required variables")

# Inicializar handlers (singleton para reuso de sessão)
faz_connector: Optional[FortiAnalyzerConnector] = None
openai_handler: Optional[OpenAIHandler] = None


def get_faz_connector() -> FortiAnalyzerConnector:
    """Obtém ou cria conexão FortiAnalyzer"""
    global faz_connector
    if faz_connector is None or faz_connector.session_id is None:
        faz_connector = FortiAnalyzerConnector(
            host=FAZ_HOST,
            username=FAZ_USERNAME,
            password=FAZ_PASSWORD,
            verify_ssl=FAZ_VERIFY_SSL
        )
        if not faz_connector.login():
            raise HTTPException(status_code=500, detail="Failed to connect to FortiAnalyzer")
    return faz_connector


def get_openai_handler() -> OpenAIHandler:
    """Obtém ou cria handler OpenAI"""
    global openai_handler
    if openai_handler is None:
        openai_handler = OpenAIHandler(
            api_key=OPENAI_API_KEY,
            model_name=OPENAI_MODEL
        )
    return openai_handler


# Modelos Pydantic
class ChatRequest(BaseModel):
    message: str
    adom: Optional[str] = "root"  # ADOM selecionado pelo usuário


class ChatResponse(BaseModel):
    response: str
    function_called: Optional[str] = None
    timestamp: str


# ============================================================
# Authentication Endpoints
# ============================================================

@app.post("/api/auth/login")
async def login(
    response: Response,
    username: str = Form(...),
    password: str = Form(...)
):
    """Login endpoint - retorna token JWT"""
    user = authenticate_user(username, password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password"
        )
    
    # Criar token
    access_token = create_access_token(
        data={"sub": user["username"], "roles": user["roles"]}
    )
    
    # Set cookie
    response.set_cookie(
        key="session_token",
        value=access_token,
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax"
    )
    
    logger.info(f"User {username} logged in successfully")
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "username": user["username"],
            "full_name": user["full_name"],
            "email": user["email"],
            "roles": user["roles"]
        }
    }


@app.post("/api/auth/logout")
async def logout(response: Response):
    """Logout endpoint - remove cookie"""
    response.delete_cookie(key="session_token")
    return {"message": "Logged out successfully"}


@app.get("/api/auth/me")
async def get_current_user(current_user: Dict = Depends(get_current_user_from_cookie)):
    """Retorna informações do usuário atual"""
    from auth import has_role
    return {
        "username": current_user["username"],
        "full_name": current_user["full_name"],
        "email": current_user["email"],
        "roles": current_user["roles"],
        "is_admin": has_role(current_user, "admin")
    }


@app.get("/api/auth/saml/enabled")
async def saml_status():
    """Verifica se SAML está habilitado"""
    return {
        "enabled": is_saml_enabled(),
        "sso_url": get_saml_login_url() if is_saml_enabled() else None
    }


@app.get("/api/auth/saml/login")
async def saml_login(provider: str = "azure"):
    """Inicia login SAML (preparado para integração futura)"""
    if not is_saml_enabled():
        raise HTTPException(
            status_code=501,
            detail="SAML authentication is not configured. Please configure SAML settings in .env file."
        )
    
    # TODO: Implementar redirect para IdP SAML
    # Por enquanto, retornar mensagem informativa
    return {
        "message": "SAML integration ready for configuration",
        "provider": provider,
        "next_steps": [
            "1. Configure SAML_ENABLED=true in .env",
            "2. Set SAML_IDP_ENTITY_ID (Azure AD Entity ID)",
            "3. Set SAML_SSO_URL (Azure AD SSO URL)",
            "4. Set SAML_X509_CERT (Azure AD Certificate)",
            "5. Configure Azure AD application with ACS URL"
        ]
    }


# ============================================================
# Main Endpoints (Protected)
# ============================================================

@app.get("/", response_class=HTMLResponse)
async def root(session_token: Optional[str] = Cookie(None)):
    """Serve a interface web (protegida)"""
    # Verificar se há token de sessão
    if not session_token:
        # Redirecionar para login
        return RedirectResponse(url="/login", status_code=302)
    
    # Verificar se token é válido
    try:
        from auth import decode_token
        payload = decode_token(session_token)
        if not payload:
            return RedirectResponse(url="/login", status_code=302)
    except:
        return RedirectResponse(url="/login", status_code=302)
    
    # Token válido, servir aplicação
    try:
        with open("static/index.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return """
        <html>
            <body>
                <h1>VIVA-HUNTING-AI API</h1>
                <p>API is running! Access the web interface at <code>/static/index.html</code></p>
                <p>Or use the API directly at <code>/api/chat</code></p>
            </body>
        </html>
        """


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    """Serve a página de login"""
    try:
        with open("static/login.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return """
        <html>
            <body>
                <h1>Login</h1>
                <p>Login page not found</p>
            </body>
        </html>
        """


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(session_token: Optional[str] = Cookie(None)):
    """Serve o painel administrativo (somente para admins)"""
    # Verificar se há token de sessão
    if not session_token:
        return RedirectResponse(url="/login", status_code=302)
    
    # Verificar se token é válido e se usuário é admin
    try:
        from auth import decode_token, get_user, has_role
        payload = decode_token(session_token)
        if not payload:
            return RedirectResponse(url="/login", status_code=302)
        
        username = payload.get("sub")
        user = get_user(username)
        if not user or not has_role(user, "admin"):
            raise HTTPException(status_code=403, detail="Admin access required")
    except:
        return RedirectResponse(url="/login", status_code=302)
    
    # Usuário é admin, servir painel
    try:
        with open("static/admin.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return """
        <html>
            <body>
                <h1>Admin Panel</h1>
                <p>Admin panel not found</p>
            </body>
        </html>
        """


@app.get("/api/health")
async def health_check(current_user: Dict = Depends(get_current_user_from_cookie)):
    """Health check endpoint"""
    try:
        faz = get_faz_connector()
        status = faz.get_system_status()

        return {
            "status": "healthy",
            "fortianalyzer": {
                "connected": status is not None,
                "hostname": status.get("Hostname") if status else None,
                "version": status.get("Version") if status else None
            },
            "openai": {
                "configured": OPENAI_API_KEY is not None,
                "model": OPENAI_MODEL
            },
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "error": str(e)}
        )


@app.post("/api/chat", response_model=ChatResponse)
async def chat(
    request: ChatRequest,
    current_user: Dict = Depends(get_current_user_from_cookie)
):
    """
    Endpoint principal do chatbot

    Recebe pergunta do usuário, processa com OpenAI e executa no FortiAnalyzer
    """
    try:
        logger.info(f"Received question: {request.message} (ADOM: {request.adom})")

        # Obter handlers
        faz = get_faz_connector()
        ai = get_openai_handler()

        # Processar pergunta com OpenAI
        ai_response = ai.process_question(request.message)

        if not ai_response.get("success"):
            return ChatResponse(
                response=ai_response.get("message", "Não consegui entender a pergunta."),
                timestamp=datetime.now().isoformat()
            )

        function_name = ai_response["function_name"]
        parameters = ai_response["parameters"]

        # SEMPRE usar o ADOM selecionado pelo usuário na interface
        # Sobrescrever qualquer ADOM que a IA tenha sugerido do contexto
        parameters["adom"] = request.adom
        
        logger.info(f"OpenAI identified function: {function_name} with params: {parameters}")

        # Executar função correspondente no FortiAnalyzer
        result = execute_function(faz, function_name, parameters)
        
        # Atualizar contexto da sessão
        ai.update_context(function_name, parameters, result)

        # Formatar resposta com OpenAI
        formatted_response = ai.format_response(
            question=request.message,
            function_result=result,
            function_name=function_name
        )

        return ChatResponse(
            response=formatted_response,
            function_called=function_name,
            timestamp=datetime.now().isoformat()
        )

    except Exception as e:
        logger.error(f"Error processing chat: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error processing request: {str(e)}")


def execute_function(faz: FortiAnalyzerConnector, function_name: str, params: Dict) -> Any:
    """
    Executa função no FortiAnalyzer baseado no que Gemini identificou

    Args:
        faz: Conector FortiAnalyzer
        function_name: Nome da função a executar
        params: Parâmetros da função

    Returns:
        Resultado da execução
    """
    # Converter float para int se necessário (Gemini às vezes retorna floats)
    if 'limit' in params and isinstance(params['limit'], float):
        params['limit'] = int(params['limit'])
    
    # Normalizar ADOM para uppercase (API do FortiAnalyzer é case-sensitive)
    if 'adom' in params and params['adom']:
        params['adom'] = params['adom'].upper()
        logger.info(f"Normalized ADOM to uppercase: {params['adom']}")

    # Converter time_range se necessário
    if 'time_range' not in params and 'time-range' in params:
        params['time_range'] = params.pop('time-range')
    
    # Mapear funções
    function_map = {
        "get_system_status": lambda: faz.get_system_status(),
        "query_logs": lambda: faz.query_logs(**params),
        "get_log_count": lambda: faz.get_log_count(**params),
        "get_logs": lambda: faz.query_logs(**params),  # query_logs é o método correto no connector
        "get_devices": lambda: faz.get_devices(**params),
        "get_adoms": lambda: faz.get_adoms(),
        # FortiView functions (NOVAS)
        # "get_top_sources": lambda: get_top_sources(**params),  # DESABILITADO: FortiView não disponível
        "get_top_destinations": lambda: get_top_destinations(**params),
        "get_top_threats": lambda: get_top_threats(**params),
        "get_top_applications": lambda: get_top_applications(**params),
        "get_top_countries": lambda: get_top_countries(**params),
        "get_policy_hits": lambda: get_policy_hits(**params),
        # Event Management functions (NOVAS)
        "get_alerts": lambda: get_alerts(**params),
        "get_alert_count": lambda: get_alert_count(**params),
        # Legacy functions (redirecionadas para as novas)
        "get_security_events": lambda: get_top_threats(**params),  # Redirecionar para get_top_threats
        # "get_blocked_traffic": lambda: get_top_sources(**params),  # DESABILITADO: FortiView não disponível
        "get_blocked_websites": lambda: faz.get_blocked_websites(**params) if hasattr(faz, 'get_blocked_websites') else {"error": "Função não disponível"},
        "get_allowed_websites": lambda: faz.get_allowed_websites(**params) if hasattr(faz, 'get_allowed_websites') else {"error": "Função não disponível"},
        "get_blocked_applications": lambda: get_top_applications(**params),  # Redirecionar para get_top_applications
        "get_allowed_applications": lambda: get_top_applications(**params),  # Redirecionar para get_top_applications
    }

    if function_name not in function_map:
        raise ValueError(f"Unknown function: {function_name}")

    result = function_map[function_name]()
    logger.info(f"Function {function_name} returned: {result}")
    return result


@app.get("/api/adoms")
async def get_adoms(current_user: Dict = Depends(get_current_user_from_cookie)):
    """Retorna lista de ADOMs disponíveis (filtrados por permissões do usuário)"""
    try:
        faz = get_faz_connector()
        adoms = faz.get_adoms()
        
        if adoms is None:
            return {"adoms": [], "error": "Não foi possível buscar ADOMs"}
        
        # Formatar resposta com informações úteis
        adoms_list = []
        for adom in adoms:
            adom_name = adom.get("name", "")
            
            # Filtrar ADOMs baseado nas permissões do usuário
            if user_can_access_adom(current_user, adom_name):
                adoms_list.append({
                    "name": adom_name,
                    "desc": adom.get("desc", ""),
                    "os_ver": adom.get("os_ver", "")
                })
        
        return {"adoms": adoms_list}
    except Exception as e:
        logger.error(f"Error getting ADOMs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/reset")
async def reset_chat(current_user: Dict = Depends(get_current_user_from_cookie)):
    """Reinicia a conversa com OpenAI"""
    try:
        ai = get_openai_handler()
        ai.reset_chat()
        return {"status": "success", "message": "Chat reset successfully"}
    except Exception as e:
        logger.error(f"Error resetting chat: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# User Management Endpoints (Admin Only)
# ============================================================

@app.get("/api/admin/users")
async def list_users(admin_user: Dict = Depends(require_admin)):
    """Lista todos os usuários (somente admin)"""
    try:
        users = get_all_users()
        return {"users": list(users.values())}
    except Exception as e:
        logger.error(f"Error listing users: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/admin/users")
async def create_new_user(
    admin_user: Dict = Depends(require_admin),
    username: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(...),
    email: str = Form(...),
    roles: str = Form(...),  # Comma-separated
    allowed_adoms: str = Form(...)  # Comma-separated or "*"
):
    """Cria novo usuário (somente admin)"""
    try:
        # Parse roles e ADOMs
        roles_list = [r.strip() for r in roles.split(",") if r.strip()]
        
        if allowed_adoms.strip() == "*":
            adoms_list = ["*"]
        else:
            adoms_list = [a.strip() for a in allowed_adoms.split(",") if a.strip()]
        
        # Validações
        if not username or len(username) < 3:
            raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
        
        if not password or len(password) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
        
        if not roles_list:
            raise HTTPException(status_code=400, detail="At least one role is required")
        
        # Criar usuário
        try:
            user = create_user(
                username=username,
                password=password,
                full_name=full_name,
                email=email,
                roles=roles_list,
                allowed_adoms=adoms_list
            )
        except ValueError as e:
            # Erro de validação (ex: senha muito longa)
            raise HTTPException(status_code=400, detail=str(e))
        
        if user is None:
            raise HTTPException(status_code=400, detail="User already exists or creation failed")
        
        logger.info(f"User {username} created by {admin_user['username']}")
        return {"status": "success", "user": user}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/api/admin/users/{username}")
async def update_existing_user(
    username: str,
    admin_user: Dict = Depends(require_admin),
    full_name: Optional[str] = Form(None),
    email: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
    roles: Optional[str] = Form(None),
    allowed_adoms: Optional[str] = Form(None),
    disabled: Optional[bool] = Form(None)
):
    """Atualiza usuário existente (somente admin)"""
    try:
        # Parse roles e ADOMs se fornecidos
        roles_list = None
        if roles is not None:
            roles_list = [r.strip() for r in roles.split(",") if r.strip()]
        
        adoms_list = None
        if allowed_adoms is not None:
            if allowed_adoms.strip() == "*":
                adoms_list = ["*"]
            else:
                adoms_list = [a.strip() for a in allowed_adoms.split(",") if a.strip()]
        
        # Validações
        if password is not None and len(password) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
        
        # Atualizar usuário
        try:
            user = update_user(
                username=username,
                full_name=full_name,
                email=email,
                password=password,
                roles=roles_list,
                allowed_adoms=adoms_list,
                disabled=disabled
            )
        except ValueError as e:
            # Erro de validação (ex: senha muito longa)
            raise HTTPException(status_code=400, detail=str(e))
        
        if user is None:
            raise HTTPException(status_code=404, detail="User not found or update failed")
        
        logger.info(f"User {username} updated by {admin_user['username']}")
        return {"status": "success", "user": user}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating user: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/admin/users/{username}")
async def delete_existing_user(
    username: str,
    admin_user: Dict = Depends(require_admin)
):
    """Remove usuário (somente admin)"""
    try:
        # Não permitir admin deletar a si mesmo
        if username == admin_user["username"]:
            raise HTTPException(status_code=400, detail="Cannot delete your own account")
        
        success = delete_user(username)
        
        if not success:
            raise HTTPException(status_code=404, detail="User not found or cannot be deleted (last admin)")
        
        logger.info(f"User {username} deleted by {admin_user['username']}")
        return {"status": "success", "message": f"User {username} deleted"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def session_renewal_task():
    """Task em background para renovar sessão do FortiAnalyzer a cada 4 minutos"""
    while True:
        try:
            await asyncio.sleep(240)  # 4 minutos (renovar antes de expirar aos 5 minutos)
            global faz_connector
            if faz_connector and faz_connector.session_id:
                logger.info("Background task: Checking and renewing FortiAnalyzer session...")
                if faz_connector._check_and_renew_session():
                    logger.info("Background task: Session renewed successfully")
                else:
                    logger.warning("Background task: Failed to renew session")
        except Exception as e:
            logger.error(f"Background task error: {e}")


@app.on_event("startup")
async def startup_event():
    """Evento executado no startup da aplicação"""
    logger.info("=" * 60)
    logger.info("VIVA-HUNTING-AI starting...")
    logger.info(f"FortiAnalyzer Host: {FAZ_HOST}")
    logger.info(f"OpenAI Model: {OPENAI_MODEL}")
    logger.info("=" * 60)

    # Testar conexão inicial
    try:
        faz = get_faz_connector()
        status = faz.get_system_status()
        if status:
            logger.info(f"✓ Connected to FortiAnalyzer: {status.get('Hostname')} v{status.get('Version')}")
        else:
            logger.warning("⚠ Connected but couldn't get system status")
    except Exception as e:
        logger.error(f"✗ Failed to connect to FortiAnalyzer: {e}")

    # Iniciar task de renovação de sessão em background
    asyncio.create_task(session_renewal_task())
    logger.info("✓ Session renewal background task started")


@app.on_event("shutdown")
async def shutdown_event():
    """Evento executado no shutdown da aplicação"""
    logger.info("Shutting down...")
    global faz_connector
    if faz_connector:
        faz_connector.logout()
    logger.info("Shutdown complete")


# Servir arquivos estáticos
try:
    app.mount("/static", StaticFiles(directory="static"), name="static")
except Exception:
    logger.warning("Static directory not found, skipping static file serving")


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("API_PORT", 8000))
    host = os.getenv("API_HOST", "0.0.0.0")

    uvicorn.run(
        "app:app",
        host=host,
        port=port,
        reload=os.getenv("DEBUG", "true").lower() == "true"
    )
