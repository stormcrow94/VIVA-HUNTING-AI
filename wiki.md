# VIVA-HUNTING-AI • Wiki Técnica

Este documento concentra tudo o que antes estava espalhado em vários `.md`. Ele serve como referência única para arquitetura, operação, segurança e roadmap do copiloto FortiAnalyzer.

---

## 1. Visão Geral

- **Objetivo**: permitir consultas em linguagem natural aos dados do FortiAnalyzer, com respostas contextualizadas pelo modelo OpenAI escolhido (`gpt-4o-mini` por padrão).
- **Público**: times de SecOps que precisam acelerar hunting e troubleshooting sem navegar diretamente pela GUI do FortiAnalyzer.
- **Fluxo resumido**:
  1. Usuário envia pergunta via UI ou REST.
  2. `openai_handler.py` interpreta com function calling, selecionando uma função específica.
  3. `fortianalyzer_connector.py` executa a chamada JSON-RPC (logview/fortiview, duas etapas).
  4. Resultado é formatado novamente pela OpenAI e devolvido ao usuário.

---

## 2. Arquitetura

### 2.1 Componentes

| Camada | Arquivos principais | Responsabilidades |
|--------|---------------------|-------------------|
| UI | `static/login.html`, `static/index.html`, `static/admin.html` | Autenticação estilo terminal, chat web, painel admin |
| API | `app.py` | FastAPI, rotas protegidas, background tasks, integração AI/FortiAnalyzer |
| IA | `openai_handler.py` | Function-calling, memória contextual, formatação de respostas |
| FortiAnalyzer | `fortianalyzer_connector.py`, `new_functions.py` | Autenticação JSON-RPC, logview/fortiview, agregações, fallback |
| Segurança | `auth.py` | JWT, cookies httpOnly, roles, SAML-ready |

### 2.2 Fluxo de requisição

1. **Autenticação** (cookies httpOnly + Bearer opcional).
2. **Processamento** (`/api/chat`): OpenAI escolhe a função (ex.: `get_blocked_websites`).
3. **Execução**: conector dispara `add` → `get` (ou `/fortiview/.../run` → `/run/<tid>`).
4. **Resposta**: IA resume números-chave, adiciona alertas quando não há dados.

### 2.3 Considerações de arquitetura

- Multi-ADOM em toda a pilha (upper-case antes de chamar a API).
- Sessões FortiAnalyzer renovadas a cada 5 minutos (`session_timeout = 300`).
- Fallback entre logtypes correlatos (ex.: `webfilter` → `dns`, `app-ctrl` → `ips/attack`).
- Logs com `INFO`/`DEBUG` controlados por `LOG_LEVEL`.

---

## 3. Stack e Requisitos

- Python 3.13+, FastAPI, Uvicorn.
- OpenAI SDK oficial (`openai>=1.12.0`).
- `python-dotenv`, `python-jose[cryptography]`, `passlib[bcrypt]`, `requests`.
- FortiAnalyzer 7.4.x (testado e compatível com 7.4.5–7.4.8) com API JSON-RPC habilitada e usuário dedicado.
- Frontend puro HTML/CSS/JS.

---

## 4. Setup Detalhado

1. **Clonar e criar venv**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # ou venv\Scripts\activate
   pip install -r requirements.txt
   ```
2. **Configurar `.env`**
   - FortiAnalyzer: `FAZ_HOST`, `FAZ_USERNAME`, `FAZ_PASSWORD`, `FAZ_VERIFY_SSL`.
   - OpenAI: `OPENAI_API_KEY`, `OPENAI_MODEL`.
   - App: `API_HOST`, `API_PORT`, `LOG_LEVEL`, `DEBUG`.
   - Autenticação: `SECRET_KEY`, `ACCESS_TOKEN_EXPIRE_MINUTES`.
   - SAML (opcional): `SAML_ENABLED`, `SAML_IDP_ENTITY_ID`, `SAML_SSO_URL`, `SAML_X509_CERT`, `SAML_SP_*`.
3. **Inicializar**
   ```bash
   ./start.sh         # usa uvicorn com variáveis padronizadas
   # ou
   uvicorn app:app --host 0.0.0.0 --port 8000 --reload
   ```
4. **Acessar**
   - Login: `http://localhost:8000/login`
   - UI: `http://localhost:8000/`
   - Admin: `http://localhost:8000/admin`
   - API: `http://localhost:8000/docs` (docs interativas)

---

## 5. Configuração do Ambiente

| Bloco | Variáveis | Observações |
|-------|-----------|-------------|
| FortiAnalyzer | `FAZ_*` | `FAZ_VERIFY_SSL=true` em produção; usuário dedicado com permissões mínimas |
| OpenAI | `OPENAI_API_KEY`, `OPENAI_MODEL` | Modelos testados: `gpt-4o-mini` (recomendado), `gpt-4o`, `gpt-4.1` |
| App | `API_HOST`, `API_PORT`, `LOG_LEVEL`, `DEBUG` | Defina `LOG_LEVEL=DEBUG` apenas para troubleshooting |
| Auth | `SECRET_KEY`, `ACCESS_TOKEN_EXPIRE_MINUTES`, `COOKIE_DOMAIN` (se necessário) | `SECRET_KEY` >= 32 chars |
| SAML | `SAML_ENABLED`, `SAML_*` | Integração preparada; requer libs `python3-saml`/`pysaml2` |

---

## 6. Autenticação e Controle de Acesso

- **JWT** emitidos em `/api/auth/login`, armazenados em cookie `session_token` httpOnly + SameSite=Lax.
- **Roles**: `admin`, `analyst`, `viewer`. Guard-rails implementados via `require_admin` e `user_can_access_adom`.
- **Default users** definidos em `auth.py` (usuarios `admin`, `analyst`, `viewer`, senha `admin123`).
- **SAML-ready**: endpoints `/api/auth/saml/enabled` e `/api/auth/saml/login`; basta habilitar no `.env`, configurar IdP (Azure AD/Okta) e instalar dependências SAML.
- **UI**: login estilo Matrix com botões de SSO já posicionados; páginas raiz e `/admin` exigem cookie válido (redirecionamento automático).

---

## 7. Orquestração IA (OpenAI)

- `openai_handler.py` define um conjunto de ferramentas (function calling) cobrindo:
  - `get_system_status`, `get_devices`, `get_adoms`
  - `query_logs`, `get_logs`, `get_log_count`
  - `get_top_sources`, `get_top_destinations`, `get_top_threats`
  - `get_blocked_traffic`, `get_blocked/allowed_websites`, `get_blocked/allowed_applications`
- Contexto de sessão: ADOM atual, último tipo de query, período, resumo de resultados e devices mencionados, permitindo follow-ups (“e no mesmo ADOM?”).
- Regras rígidas no prompt:
  - Palavras-chave (“top”, “bloqueado”, “detalhes”, “eventos críticos”) mapeiam para funções específicas.
  - Tradução de expressões de tempo em PT-BR (últimas 2h, ontem, etc).
- Resposta final também passa pelo modelo para transformar JSON em narrativa curta.

---

## 8. Conector FortiAnalyzer

### 8.1 Sessão e segurança

- Login via `exec /sys/login/user`, logout automático quando `session_timeout` expira.
- `_check_and_renew_session()` executa login proativo após 5 minutos.
- Possibilidade de desativar verificação SSL (default `false` para labs).

### 8.2 LogView (2 etapas)

1. `add /logview/adom/<ADOM>/logsearch` (`apiver: 3`) com `logtype`, `time-range`, `filter` e, opcionalmente, `device`.
2. `get /logview/adom/<ADOM>/logsearch/<tid>` com `offset`/`limit`.

### 8.3 FortiView

- Mesma lógica assíncrona (`add` → `get`) para endpoints como `/fortiview/adom/<ADOM>/top-sources/run`.
- Ordenação padrão por bytes desc; limite configurável.

### 8.4 Logtypes suportados

**Oficiais (documentação 7.4.8)**: `traffic`, `app-ctrl`, `webfilter`, `attack`, `event`, `virus`, `content`, `dlp`, `emailfilter`, `history`, `voip`, `netscan`, `fct-event`, `fct-traffic`, `waf`, `gtp`, `ztna`, `security`.

**Usados ativamente**: `traffic`, `app-ctrl`, `webfilter`, `attack`, `event`, `virus`, `content`, `dlp`, `emailfilter`.

**Fallback não oficial**: `dns` (webfilter alternativo), `ips` (equivalente a `attack`), `utm` (legado). Filtros padronizados para block/pass/deny.

### 8.5 Estratégias especiais

- **Application Control**: se `app-ctrl` vazio, tenta `ips` e depois `attack`.
- **Webfilter**: fallback para `dns` com `action==redirect`.
- **Eventos críticos**: agrega múltiplos logtypes até atingir o limite pedido.
- **Top dados**: endpoints FortiView mapeados em `new_functions.py`.

---

## 9. Catálogo de Funcionalidades

| Categoria | Funções chave | Observações |
|-----------|---------------|-------------|
| Inventário | `get_devices`, `get_adoms`, `get_system_status` | Exige role `viewer` ou superior |
| Logs | `query_logs`, `get_logs`, `get_log_count`, `get_blocked_traffic` | Time ranges semânticos: `last-1-hour` ... `last-30-days` |
| Application Control | `get_blocked_applications`, `get_allowed_applications` | Campos relevantes: `app`, `appcat`, `apprisk`, `policyid` |
| Webfilter/DNS | `get_blocked_websites`, `get_allowed_websites` | Inclui `hostname`, `catdesc`, `profile` |
| FortiView Insights | `get_top_sources`, `get_top_destinations`, `get_top_threats`, `get_top_applications`, `get_top_countries`, `get_policy_hits` | Baseados em agregações JSON-RPC com fallback |
| Alertas | `get_alerts`, `get_alert_count` | Complementam consultas do chat com contexto de incidentes |

> **Cobertura oficial**: a análise do pacote HTML do FortiAnalyzer 7.4.4 mapeou 8 módulos principais (FortiView, Event Management, LogView, UEBA, IOC, Incident Management, Reports e System/Device) e 67 funcionalidades implementáveis. As funções expostas para a IA representam o subconjunto já codificado e testado, enquanto o restante serve de backlog priorizado para expansão futura.

---

## 10. Testes e Validação

- Scripts em `tests/` (executar com `python <arquivo>.py`):
  - `test_connection.py` – login + status.
  - `test_application_control_webfilter.py` – fluxo completo de app/webfilter.
  - `test_devices.py`, `test_adoms.py`, `test_logtypes.py`, `test_webfilter.py`, `test_chatbot_integration.py`.
  - `discover_faz_endpoints.py` para mapear endpoints suportados pelo appliance alvo.
- Validação manual recomendada:
  1. Rodar `test_connection.py`.
  2. Rodar `test_application_control_webfilter.py`.
  3. Executar perguntas na UI e comparar com FortiAnalyzer oficial.
  4. Monitorar `logs/app.log` (grep ERROR/WARNING).

---

## 11. Operação & Troubleshooting

| Sintoma | Diagnóstico | Ação |
|---------|-------------|------|
| `Failed to connect to FortiAnalyzer` | Rede ou credenciais inválidas | `ping <FAZ_HOST>`, revisar `.env`, testar `FAZ_VERIFY_SSL=false` |
| `401 Unauthorized` | Token expirado ou cookie ausente | Fazer login novamente, ajustar `ACCESS_TOKEN_EXPIRE_MINUTES`, limpar cookies |
| Sem dados retornados | Filtros muito estreitos ou ADOM errado | Testar `last-24-hours`, confirmar ADOM selecionado, verificar se existem logs |
| `Error processing request with OpenAI` | API key inválida ou cota excedida | Confirmar `OPENAI_API_KEY`, checar fatura OpenAI, reduzir paralelismo |
| Sessão FortiAnalyzer expira | Long running tasks | Ver `logs/app.log`, garantir conectividade estável, reduzir consultas simultâneas |

Logs úteis:
```bash
tail -f logs/app.log
grep ERROR logs/app.log
```

---

## 12. Segurança e Hardening

1. **Credenciais**: nunca versionar `.env`; rotacionar `SECRET_KEY` e senhas FortiAnalyzer.
2. **Cookies**: manter `httponly`, `samesite=lax`; adicionar `secure=true` em produção.
3. **CORS**: restringir `allow_origins` em `app.py`.
4. **TLS**: usar proxy reverso (nginx/Apache) com certificados válidos.
5. **Least privilege**: usuário FortiAnalyzer exclusivo para consultas read-only.
6. **Auditoria**: registrar logins e ações (ver `LOG_LEVEL=INFO`), considerar envio para SIEM.
7. **Rate limiting**: adicionar limitador para `/api/auth/login` em ambientes expostos.

---

## 13. Roadmap Sugerido

- Implementar SAML completo (Azure AD/Okta) e MFA.
- Dashboards com gráficos (ex.: FastAPI + HTMX ou front externo).
- Exportação de relatórios (CSV/PDF) e notificações proativas.
- Histórico de conversas persistente e pesquisa contextual.
- Cache Redis para queries repetidas e filas (Celery/RQ) para buscas longas.
- Suporte mobile/lightweight e internacionalização.

---

## 14. Referências

- Código-fonte: ver arquivos mencionados ao longo do documento.
- Documentação oficial FortiAnalyzer: pasta `html/` (não modificar) + pacote externo `FortiAnalyzer-7.4.5-JSON-API-Reference/`.
- Testes automatizados: diretório `tests/`.
- Logs e operações: `logs/app.log`.

---

## 15. Seleção de ADOM ponta a ponta

- **Backend** (`app.py`):
  - Endpoint `GET /api/adoms` lista todos os ADOMs e é consumido diretamente pela UI.
  - `ChatRequest` recebe `adom` e o `execute_function()` injeta automaticamente o domínio escolhido quando o modelo não especifica.
- **Frontend** (`static/index.html`):
  - Dropdown fixo no header, tema Matrix com glassmorphism e persistência em `sessionStorage`.
  - Funções `loadAdoms`, `saveSelectedAdom`, `getSelectedAdom` garantem recarregamento instantâneo e envio transparente a cada pergunta.
- **Conector**:
  - Todas as funções normalizam `adom` para uppercase antes de montar a URL (`/logview/adom/<ADOM>/...`), evitando erros case-sensitive.
- **Testes**: validações cobriram listagem de 25 ADOMs, devices por domínio e queries no ADOM selecionado, incluindo conversões `casio` → `CASIO`.
- **Próximos passos documentados**: controle de acesso por ADOM (em sincronia com roles), favoritos e busca para ambientes com dezenas de domínios.

---

## 16. Memória de conversação e follow-ups

- **Session context** (em `openai_handler.py`):
  ```python
  {
      "current_adom": "...",
      "last_query_type": "...",
      "last_time_range": "...",
      "last_results_summary": "...",
      "mentioned_devices": [...],
      "conversation_topics": [...]
  }
  ```
- `_build_context_string()` insere ADOM, último período e resumo dos resultados no prompt, enquanto `conversation_history` limita o replay às 10 últimas mensagens para controlar custo.
- `update_context()` registra automaticamente ADOM, tipo e quantidade de registros retornados, permitindo perguntas como “E os usuários?” sem precisar repetir parâmetros.
- **Regras especiais para ataques/usuários**:
  - “Ataques” → `get_top_threats` (FortiView) para estatísticas agregadas.
  - “Usuários envolvidos”, “detalhes dos ataques” ou menção a usuários → `get_logs` com `logtype="attack"` para trazer `srcuser`, `destination`, etc.
  - Perguntas combinadas (“… e quais usuários?”) pulam direto para `get_logs`.
- **Exemplos cobertos**:
  - Investigação multi-etapas (ADOM específico → origem → severidade).
  - Análise de tráfego (top sources → bloqueios do primeiro IP → sites bloqueados).
  - Contexto é resetável via `reset_chat()` ou reiniciando a aplicação.

---

## 17. Gestão de usuários e painel administrativo

- **Persistência**: `users_db.json` mantém `username`, `full_name`, `roles`, hash bcrypt, status (`disabled`), ADOMs permitidos (`["*"]` ou lista) e timestamps (`created_at`, `last_login`).
- **Roles suportadas**:
  - `admin`: acesso total + painel `/admin`.
  - `analyst`: consultas e hunting completo.
  - `viewer`: uso somente leitura (restrições adicionais prontas para ativação).
- **Painel `/admin`**:
  - Dashboard com contadores (total, ativos, admins) e CRUD completo.
  - Restrições: não permite remover o último admin ou excluir a própria conta.
- **API**:
  - `GET /api/admin/users`, `POST /api/admin/users`, `PUT /api/admin/users/{username}`, `DELETE /api/admin/users/{username}`, todos protegidos por `require_admin`.
  - Payloads aceitam múltiplas roles e ADOMs (separados por vírgula) ou `*`.
- **Segurança**:
  - Cookies httpOnly, validação mínima para username/senha/email, logs de auditoria e enforcement de ADOMs em todas as queries via `user_can_access_adom`.
  - Guia recomenda migração futura para banco relacional, MFA, grupos e notificações.

---

## 18. Interface web e UX

- **Tema**: cyberpunk refinado com glassmorphism (`backdrop-filter: blur(24px)`), opacidade de 75–85% e paleta `#00ff88 / #00ff66` + tons cinza `#e0e0e0`.
- **Tipografia**: Inter para textos, Courier apenas para terminal/Matrix; tamanhos entre 13–14px e espaçamentos generosos (padding 24–36px, radius 10–20px).
- **Páginas**:
  - `index.html`: cards com sombra suave, scrollbars customizadas, botões com gradientes e animações `cubic-bezier`.
  - `login.html`: terminal estilizado com Matrix rain em canvas, sequência de boot atualizada e botões de SSO discretos.
  - `admin.html`: tabelas com hover sutil, badges pastel (admin laranja, analyst ciano) e cards de estatística responsivos.
- **Matrix background** ajustado para opacidade 3–5% e animação leve para manter performance (GPU accelerated).
- **Próximas melhorias sugeridas**: toggle de tema claro/escuro, animações de loading customizadas, tooltips e componentes reutilizáveis.

---

## 19. Migração Gemini → OpenAI e histórico de versões

- **Motivação**:
  - GPT-4o-mini custa $0.15/$0.60 por 1M tokens (input/output), latência ~1–2s e janela de 128K tokens (4x maior que o Gemini Pro).
  - Documentação, suporte e tooling superiores, com function calling robusto.
- **Passos principais**:
  1. Adicionar `openai>=1.12.0` e remover `google-generativeai`.
  2. Criar `openai_handler.py` (function calling + memória).
  3. Atualizar `app.py`, variáveis `.env` (`OPENAI_API_KEY`, `OPENAI_MODEL`) e health check.
  4. Documentar em `MIGRATION_GUIDE.md`, `CHANGELOG.md`, `REFATORACAO_CONCLUIDA.md` e `RESUMO_FINAL_REFATORACAO.md`.
- **Release notes**:
  - v2.0.0 (16/11/2025) – migração para OpenAI, custos transparentes, health check ampliado e depreciação do handler Gemini.
  - v1.0.0 – release inicial (Gemini, arquitetura base, autenticação JWT, multi-ADOM).
  - Planejamento para v2.1.0 inclui dashboards, exportações e cache.
- **Snippet “About” sugerido para GitHub**:
  > 🤖 Chatbot inteligente para FortiAnalyzer usando OpenAI. Consulte logs, eventos e políticas em linguagem natural. Suporta Application Control, Webfilter, análise de tráfego, multi-ADOM, interface moderna e autenticação JWT.
  - Tags recomendadas: `fortianalyzer`, `chatbot`, `openai`, `security-automation`, `threat-hunting`, `fastapi`, `python`, `siem`, `jwt-authentication`.
- **Custos estimados**: ~US$6/mês para 1k consultas/dia (500 tokens input + 200 tokens output por interação).

---

## 20. Fallbacks, resiliência e limpeza do acervo

- **Fallback FortiView → LogView**:
  - `new_functions.py` tenta sempre endpoints FortiView; se receber "No eligible device(s)" ou timeouts, faz `query_logs`, agrega manualmente e mantém limites (ex.: `get_top_sources` → `traffic` logs).
  - Aplicado também a Application Control e WebFilter (reprocessando `app-ctrl`, `ips`, `attack`, `dns`).
  - Mensagens claras quando nenhum dado é encontrado (período sem logs ou ADOM incorreto).
- **Correções críticas registradas**:
  - Remoção de chamadas ao método inexistente `_normalize_adom`.
  - Ajuste do mapa `function_map` para usar `query_logs` ao responder `get_logs`.
  - Inclusão das funções novas (`get_top_threats`, `get_logs`) nos toolsets e prompts, eliminando respostas incompletas para perguntas sobre ataques + usuários.
- **Limpeza documental**:
  - O arquivo `CLEANUP_SUMMARY.txt` registrou a consolidação anterior (DOCUMENTATION.md, PROJECT_STRUCTURE.md e docs/). Agora toda a base técnica migrou definitivamente para `wiki.md`, viabilizando a remoção dos demais `.md`.
  - `tests/README.md`, `docs/README.md`, resumos e relatórios especiais passaram a ser seções dedicadas neste wiki.
- **Recomendações finais**:
  - Replicar a lógica de fallback nos demais endpoints FortiView (`destinations`, `applications`, `countries`, `policy_hits`).
  - Validar periodicamente ADOMs com dados reais antes de auditorias.
  - Manter apenas `README.md` e `wiki.md` como fontes oficiais, deletando arquivos redundantes após confirmar que as informações foram absorvidas aqui.

---

## 21. Compatibilidade com FortiAnalyzer 7.4.8

- **Status**: ✅ 100% compatível, sem breaking changes.
- **Logtypes atualizados**:
  - Removidos enums não oficiais (`utm`, `ips`, `dns`) das declarações OpenAI, mantidos apenas como fallback documentado no conector.
  - Adicionados novos tipos oficiais: `content` (DLP Archive), `dlp`, `emailfilter`.
  - Disponíveis mas não usados ativamente: `history`, `voip`, `netscan`, `fct-event`, `fct-traffic`, `waf`, `gtp`, `ztna` (ZTNA novo na 7.4.8), `security` (consolidado, novo na 7.4.8).
- **APIs validadas**:
  - LogView, FortiView, DVMDB (devices/ADOMs), System, Event Management — todas sem mudanças estruturais.
  - FortiView pode estar desabilitado por permissões (`parser` sem acesso) ou configuração do appliance; não é problema de versão.
- **Testes executados**: `query_logs` para todos os tipos, `get_devices`, `get_adoms`, `login`/`logout`, `get_system_status` — todos passando.
- **Próximas expansões sugeridas**: suporte a `ztna` e `security` logs (novidades da 7.4.8), investigar reativação do FortiView se aplicável.

---

Com isso, toda a documentação do projeto fica concentrada em `README.md` (visão básica) e `wiki.md` (manual técnico). Qualquer acréscimo futuro deve ser feito aqui para manter o repositório enxuto. 

