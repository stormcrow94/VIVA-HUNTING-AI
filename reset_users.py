#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reset user passwords - VIVA-HUNTING-AI
Regenera os hashes de senha com a versao correta do bcrypt
"""

import json
import sys
import bcrypt

# Configurar encoding para Windows
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

print("=" * 60)
print("  Reset de Senhas - VIVA-HUNTING-AI")
print("=" * 60)
print()

# Usuarios padrao
default_users = {
    "admin": {
        "username": "admin",
        "full_name": "Administrator",
        "email": "admin@example.com",
        "password": "admin123",  # Senha padrao
        "disabled": False,
        "roles": ["admin", "analyst"],
        "allowed_adoms": ["*"],
        "created_at": "2025-10-08T00:00:00",
        "last_login": None
    },
    "analyst": {
        "username": "analyst",
        "full_name": "Security Analyst",
        "email": "analyst@example.com",
        "password": "admin123",  # Senha padrao
        "disabled": False,
        "roles": ["analyst"],
        "allowed_adoms": ["*"],
        "created_at": "2025-10-08T00:00:00",
        "last_login": None
    },
    "viewer": {
        "username": "viewer",
        "full_name": "Security Viewer",
        "email": "viewer@example.com",
        "password": "admin123",  # Senha padrao
        "disabled": False,
        "roles": ["viewer"],
        "allowed_adoms": ["*"],
        "created_at": "2025-10-08T00:00:00",
        "last_login": None
    }
}

print("Gerando novos hashes de senha...")
print()

users_db = {}
for username, user_data in default_users.items():
    password = user_data.pop("password")
    
    # Gerar hash
    print(f"Usuario: {username}")
    print(f"  Senha: {password}")
    
    # Converter para bytes
    password_bytes = password.encode('utf-8')
    
    # Truncar senha se necessario (bcrypt limit = 72 bytes)
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
        print(f"  [AVISO] Senha truncada para 72 bytes")
    
    # Gerar salt e hash
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    hashed_str = hashed.decode('utf-8')
    
    print(f"  Hash: {hashed_str[:30]}...")
    
    # Testar hash
    if bcrypt.checkpw(password_bytes, hashed):
        print(f"  [OK] Hash validado")
    else:
        print(f"  [ERRO] Hash invalido!")
        sys.exit(1)
    
    user_data["hashed_password"] = hashed_str
    users_db[username] = user_data
    print()

# Fazer backup
try:
    with open('users_db.json', 'r') as f:
        old_db = f.read()
    with open('users_db.json.backup', 'w') as f:
        f.write(old_db)
    print("[OK] Backup salvo em users_db.json.backup")
except FileNotFoundError:
    print("[INFO] Nao ha backup anterior")

# Salvar novo arquivo
try:
    with open('users_db.json', 'w', encoding='utf-8') as f:
        json.dump(users_db, f, indent=2, ensure_ascii=False)
    print("[OK] Arquivo users_db.json atualizado")
    print()
except Exception as e:
    print(f"[ERRO] Nao foi possivel salvar: {e}")
    sys.exit(1)

print("=" * 60)
print("  [OK] USUARIOS RESETADOS COM SUCESSO!")
print()
print("  Usuarios disponiveis:")
print("  - admin   / admin123 (Administrator)")
print("  - analyst / admin123 (Security Analyst)")
print("  - viewer  / admin123 (Security Viewer)")
print("=" * 60)
print()
print("Agora inicie a aplicacao:")
print("  python app.py")
print()

