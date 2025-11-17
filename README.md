# VIVA-HUNTING-AI

Copiloto de hunting para FortiAnalyzer. Perguntas em português viram consultas precisas na API JSON-RPC do appliance, com respostas resumidas pela OpenAI.

## Visão rápida

- Conversa natural que cobre logs, FortiView e inventário multi-ADOM.
- Integração nativa com OpenAI `gpt-4o-mini`, usando function-calling e memória de sessão.
- Backend FastAPI com autenticação JWT (cookies httpOnly) e pronto para SAML/SSO.
- UI web responsiva (login estilo terminal + console cyberpunk) e endpoints REST.
- Conector FortiAnalyzer com renovo automático de sessão e fallback entre logtypes.

Todo o conteúdo técnico profundo (arquitetura, endpoints, troubleshooting, regras de segurança e roteiro) agora está em [`wiki.md`](wiki.md).

## Comece em 5 minutos

1. **Instale dependências**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # ou venv\Scripts\activate no Windows
   pip install -r requirements.txt
   ```
2. **Configure o `.env` mínimo**
   ```bash
   FAZ_HOST=192.168.1.100
   FAZ_USERNAME=admin
   FAZ_PASSWORD=sua_senha
   FAZ_VERIFY_SSL=false

   OPENAI_API_KEY=sk-proj-...
   OPENAI_MODEL=gpt-4o-mini

   SECRET_KEY=sua_chave_muito_forte
   ACCESS_TOKEN_EXPIRE_MINUTES=480
   ```
3. **Suba o backend**
   ```bash
   ./start.sh        # ou python app.py
   ```

Abra `http://localhost:8000/login` (credenciais padrão `admin` / `admin123`) e comece a perguntar: “Mostre aplicações bloqueadas hoje”, “Top 10 IPs por tráfego”, “Quais ADOMs existem?”, etc.

## Interaja via UI ou API

- UI autenticada em `/` com histórico e sugestões.
- Painel `/admin` para gerenciar usuários e ADOMs (restrito a role `admin`).
- REST:
  - `POST /api/chat` → `{ "message": "Eventos críticos nas últimas 6h" }`
  - `GET /api/health` → status FortiAnalyzer + modelo IA
  - `POST /api/auth/login|logout`, `GET /api/auth/me`

## O que há no repositório

- `app.py` – FastAPI, rotas protegidas, chat pipeline.
- `fortianalyzer_connector.py` – JSON-RPC (logview + fortiview) com renovação de sessão e parsing de timers.
- `openai_handler.py` – function calling + formatação das respostas.
- `auth.py`, `static/`, `tests/`, `new_functions.py` – autenticação, UI e bibliotecas auxiliares.
- `wiki.md` – arquitetura detalhada, fluxos, testes, troubleshooting e roadmap.

## Dicas rápidas

- Use `FAZ_VERIFY_SSL=true` e configure proxy reverso + HTTPS para produção.
- Ajuste `OPENAI_MODEL` se precisar de mais contexto (ex.: `gpt-4o`).
- Logs de execução em `logs/app.log`; scripts de validação em `tests/`.
- Licença MIT. Issues e contribuições são bem-vindas.

---

Consulte o [`wiki.md`](wiki.md) para qualquer detalhe aprofundado e mantenha o repositório limpo apenas com estes dois documentos principais.
