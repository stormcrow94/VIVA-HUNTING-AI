#!/usr/bin/env python3
"""
Authentication Module
Gerencia autenticação JWT e integração com SAML
Inclui sistema de gestão de usuários com controle de acesso por ADOM
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, List
from jose import JWTError, jwt
import bcrypt
from fastapi import HTTPException, status, Depends, Cookie
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import os
import json
import logging

logger = logging.getLogger(__name__)

# Configurações
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production-please-make-it-very-long-and-random")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 horas

# Security
security = HTTPBearer(auto_error=False)

# Caminho do arquivo de usuários
USERS_DB_FILE = "users_db.json"

# Cache em memória dos usuários (recarrega do arquivo quando necessário)
_users_cache = None
_users_cache_mtime = None


def load_users_db() -> Dict:
    """Carrega usuários do arquivo JSON"""
    global _users_cache, _users_cache_mtime
    
    try:
        # Verificar se arquivo existe
        if not os.path.exists(USERS_DB_FILE):
            logger.warning(f"Users DB file not found: {USERS_DB_FILE}, creating default")
            # Criar arquivo padrão
            default_users = {
                "admin": {
                    "username": "admin",
                    "full_name": "Administrator",
                    "email": "admin@example.com",
                    "hashed_password": "$2b$12$v6PEfvOV8keyaaHrlajHCO8gTtBy.spabZK1SkgGD9XmsgBCcXa8G",
                    "disabled": False,
                    "roles": ["admin", "analyst"],
                    "allowed_adoms": ["*"],
                    "created_at": datetime.now().isoformat(),
                    "last_login": None
                }
            }
            save_users_db(default_users)
            return default_users
        
        # Verificar se cache precisa ser atualizado
        current_mtime = os.path.getmtime(USERS_DB_FILE)
        if _users_cache is not None and _users_cache_mtime == current_mtime:
            return _users_cache
        
        # Carregar do arquivo
        with open(USERS_DB_FILE, 'r', encoding='utf-8') as f:
            users = json.load(f)
        
        _users_cache = users
        _users_cache_mtime = current_mtime
        return users
    
    except Exception as e:
        logger.error(f"Error loading users DB: {e}")
        return {}


def save_users_db(users: Dict) -> bool:
    """Salva usuários no arquivo JSON"""
    global _users_cache, _users_cache_mtime
    
    try:
        with open(USERS_DB_FILE, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=2, ensure_ascii=False)
        
        # Atualizar cache
        _users_cache = users
        _users_cache_mtime = os.path.getmtime(USERS_DB_FILE)
        return True
    
    except Exception as e:
        logger.error(f"Error saving users DB: {e}")
        return False


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica se a senha está correta
    
    Security Note:
        Bcrypt tem limite de 72 bytes. Senhas mais longas são rejeitadas
        silenciosamente (retorna False) para não revelar informações sobre
        o formato da senha durante tentativas de login.
    """
    try:
        # Converter para bytes se necessário
        if isinstance(plain_password, str):
            password_bytes = plain_password.encode('utf-8')
        else:
            password_bytes = plain_password
        
        if isinstance(hashed_password, str):
            hashed_bytes = hashed_password.encode('utf-8')
        else:
            hashed_bytes = hashed_password
        
        # Bcrypt tem limite de 72 bytes - rejeitar senhas muito longas por segurança
        # Isso previne vulnerabilidades onde senhas diferentes seriam truncadas igualmente
        # Retornamos False silenciosamente para não revelar informações durante login
        if len(password_bytes) > 72:
            logger.warning(
                f"Password verification rejected: password exceeds bcrypt's 72 byte limit "
                f"({len(password_bytes)} bytes). This may indicate a security issue or incorrect password entry."
            )
            return False
        
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    except Exception as e:
        logger.error(f"Error verifying password: {e}")
        return False


def get_password_hash(password: str) -> str:
    """Gera hash da senha
    
    Args:
        password: Senha em string
        
    Returns:
        Hash da senha em string
        
    Raises:
        ValueError: Se a senha exceder 72 bytes (limite do bcrypt)
        
    Security Note:
        Bcrypt tem limite de 72 bytes. Senhas mais longas são rejeitadas
        para prevenir vulnerabilidades onde senhas diferentes seriam truncadas
        e hashadas de forma idêntica.
    """
    try:
        # Converter para bytes se necessário
        if isinstance(password, str):
            password_bytes = password.encode('utf-8')
        else:
            password_bytes = password
        
        # Bcrypt tem limite de 72 bytes - rejeitar senhas muito longas por segurança
        # Isso previne vulnerabilidades onde senhas diferentes seriam truncadas igualmente
        if len(password_bytes) > 72:
            logger.error(f"Password exceeds bcrypt's 72 byte limit ({len(password_bytes)} bytes). Password rejected for security.")
            raise ValueError(
                f"Password is too long (exceeds bcrypt's 72 byte limit). "
                f"Maximum password length is approximately 72 ASCII characters or fewer Unicode characters. "
                f"Please use a shorter password."
            )
        
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password_bytes, salt)
        
        # Retornar como string
        return hashed.decode('utf-8')
    except ValueError:
        # Re-raise ValueError (password too long)
        raise
    except Exception as e:
        logger.error(f"Error hashing password: {e}")
        raise


def get_user(username: str) -> Optional[Dict]:
    """Busca usuário no banco de dados"""
    users_db = load_users_db()
    if username in users_db:
        return users_db[username]
    return None


def get_all_users() -> Dict:
    """Retorna todos os usuários (sem senhas)"""
    users_db = load_users_db()
    safe_users = {}
    for username, user in users_db.items():
        safe_user = user.copy()
        safe_user.pop("hashed_password", None)
        safe_users[username] = safe_user
    return safe_users


def authenticate_user(username: str, password: str) -> Optional[Dict]:
    """Autentica usuário e atualiza last_login"""
    user = get_user(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    if user.get("disabled"):
        return None
    
    # Atualizar last_login
    users_db = load_users_db()
    if username in users_db:
        users_db[username]["last_login"] = datetime.now().isoformat()
        save_users_db(users_db)
    
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Cria token JWT"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access"
    })
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> Optional[Dict]:
    """Decodifica e valida token JWT"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        return payload
    except JWTError as e:
        logger.error(f"JWT decode error: {e}")
        return None


async def get_current_user_from_cookie(
    session_token: Optional[str] = Cookie(None, alias="session_token")
) -> Dict:
    """Obtém usuário atual do cookie de sessão"""
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated - no session token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    payload = decode_token(session_token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    username: str = payload.get("sub")
    user = get_user(username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    if user.get("disabled"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )
    
    return user


async def get_current_user_from_bearer(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Dict:
    """Obtém usuário atual do Bearer token (para API)"""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated - no bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    payload = decode_token(credentials.credentials)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    username: str = payload.get("sub")
    user = get_user(username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    if user.get("disabled"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )
    
    return user


# SAML Configuration (preparado para integração futura)
SAML_SETTINGS = {
    "enabled": os.getenv("SAML_ENABLED", "false").lower() == "true",
    "sp": {
        "entityId": os.getenv("SAML_SP_ENTITY_ID", "https://fortianalyzer-chatbot.local/saml/metadata"),
        "assertionConsumerService": {
            "url": os.getenv("SAML_ACS_URL", "https://fortianalyzer-chatbot.local/saml/acs"),
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        },
        "singleLogoutService": {
            "url": os.getenv("SAML_SLS_URL", "https://fortianalyzer-chatbot.local/saml/sls"),
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        }
    },
    "idp": {
        # Azure AD
        "entityId": os.getenv("SAML_IDP_ENTITY_ID", ""),
        "singleSignOnService": {
            "url": os.getenv("SAML_SSO_URL", ""),
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "singleLogoutService": {
            "url": os.getenv("SAML_SLO_URL", ""),
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "x509cert": os.getenv("SAML_X509_CERT", "")
    }
}


def is_saml_enabled() -> bool:
    """Verifica se SAML está habilitado"""
    return SAML_SETTINGS["enabled"]


def get_saml_login_url() -> Optional[str]:
    """Retorna URL de login SAML (Azure AD)"""
    if not is_saml_enabled():
        return None
    return SAML_SETTINGS["idp"]["singleSignOnService"]["url"]


def create_user(username: str, password: str, full_name: str, email: str, 
                roles: List[str], allowed_adoms: List[str] = None) -> Optional[Dict]:
    """Cria novo usuário"""
    users_db = load_users_db()
    
    # Verificar se usuário já existe
    if username in users_db:
        logger.warning(f"User {username} already exists")
        return None
    
    # Criar usuário
    user = {
        "username": username,
        "full_name": full_name,
        "email": email,
        "hashed_password": get_password_hash(password),
        "disabled": False,
        "roles": roles,
        "allowed_adoms": allowed_adoms if allowed_adoms else ["*"],
        "created_at": datetime.now().isoformat(),
        "last_login": None
    }
    
    users_db[username] = user
    if save_users_db(users_db):
        # Retornar sem a senha
        safe_user = user.copy()
        safe_user.pop("hashed_password")
        return safe_user
    
    return None


def update_user(username: str, full_name: str = None, email: str = None, 
                roles: List[str] = None, allowed_adoms: List[str] = None,
                disabled: bool = None, password: str = None) -> Optional[Dict]:
    """Atualiza usuário existente"""
    users_db = load_users_db()
    
    if username not in users_db:
        logger.warning(f"User {username} not found")
        return None
    
    user = users_db[username]
    
    # Atualizar campos fornecidos
    if full_name is not None:
        user["full_name"] = full_name
    if email is not None:
        user["email"] = email
    if roles is not None:
        user["roles"] = roles
    if allowed_adoms is not None:
        user["allowed_adoms"] = allowed_adoms
    if disabled is not None:
        user["disabled"] = disabled
    if password is not None:
        user["hashed_password"] = get_password_hash(password)
    
    if save_users_db(users_db):
        # Retornar sem a senha
        safe_user = user.copy()
        safe_user.pop("hashed_password")
        return safe_user
    
    return None


def delete_user(username: str) -> bool:
    """Remove usuário"""
    users_db = load_users_db()
    
    if username not in users_db:
        logger.warning(f"User {username} not found")
        return False
    
    # Não permitir deletar o último admin
    if "admin" in users_db[username].get("roles", []):
        admin_count = sum(1 for u in users_db.values() if "admin" in u.get("roles", []) and not u.get("disabled"))
        if admin_count <= 1:
            logger.warning("Cannot delete the last admin user")
            return False
    
    del users_db[username]
    return save_users_db(users_db)


def has_role(user: Dict, role: str) -> bool:
    """Verifica se usuário tem determinada role"""
    return role in user.get("roles", [])


def get_user_allowed_adoms(user: Dict) -> List[str]:
    """Retorna lista de ADOMs permitidos para o usuário"""
    allowed = user.get("allowed_adoms", ["*"])
    # Se tem asterisco, permite todos
    if "*" in allowed:
        return ["*"]
    return allowed


def user_can_access_adom(user: Dict, adom: str) -> bool:
    """Verifica se usuário tem acesso ao ADOM especificado"""
    allowed = get_user_allowed_adoms(user)
    # Se tem asterisco, permite tudo
    if "*" in allowed:
        return True
    # Normalizar para uppercase e verificar
    adom_upper = adom.upper()
    allowed_upper = [a.upper() for a in allowed]
    return adom_upper in allowed_upper


async def require_admin(current_user: Dict = Depends(get_current_user_from_cookie)) -> Dict:
    """Dependency que requer role de admin"""
    if not has_role(current_user, "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user

