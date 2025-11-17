# 🧪 Testes - VIVA-HUNTING-AI

Scripts de teste e validação para o sistema VIVA-HUNTING-AI.

---

## 📋 Scripts de Teste Disponíveis

### Teste Completo de Validação

```bash
python test_application_control_webfilter.py
```

**O que testa:**
- ✅ Application Control (bloqueado/permitido)
- ✅ Webfilter (sites bloqueados/permitidos)
- ✅ Processo assíncrono em 2 etapas
- ✅ Suporte a ADOM
- ✅ Validação de campos retornados

**Saída esperada:**
```
🎉 TODOS OS TESTES PASSARAM!
✅ A implementação está conforme a documentação da API do FortiAnalyzer
```

---

### Teste de Conexão Básica

```bash
python test_connection.py
```

**O que testa:**
- Conectividade com FortiAnalyzer
- Autenticação e login
- Status do sistema
- Renovação de sessão

---

### Teste de Dispositivos

```bash
python test_devices.py
```

**O que testa:**
- Listagem de dispositivos
- Dados retornados (nome, IP, versão)
- Integração com ADOM

---

### Teste de ADOMs

```bash
python test_adoms.py
```

**O que testa:**
- Listagem de ADOMs disponíveis
- Informações de cada ADOM
- Acesso a diferentes ADOMs

---

### Teste de Tipos de Log

```bash
python test_logtypes.py
```

**O que testa:**
- Diferentes tipos de log (traffic, event, attack, etc)
- Retorno de dados para cada tipo
- Validação de estrutura

---

### Teste de Webfilter

```bash
python test_webfilter.py
```

**O que testa:**
- Logs de webfilter
- Sites bloqueados e permitidos
- Validação de campos (hostname, url, catdesc)

---

### Teste de Integração

```bash
python test_chatbot_integration.py
```

**O que testa:**
- Integração Gemini AI
- Processamento de perguntas
- Execução de funções
- Formatação de respostas

---

### Teste de Nova API

```bash
python test_new_api.py
```

**O que testa:**
- Novos endpoints da API
- Compatibilidade com versões recentes
- Funcionalidades experimentais

---

### Teste de API Raw

```bash
python test_raw_api.py
```

**O que testa:**
- Chamadas diretas à API FortiAnalyzer
- Formato JSON-RPC
- Tratamento de respostas

---

### Descoberta de Endpoints

```bash
python discover_faz_endpoints.py
```

**O que faz:**
- Descobre endpoints disponíveis no FortiAnalyzer
- Lista métodos suportados
- Útil para exploração da API

---

## 🚀 Como Executar

### Preparar Ambiente

```bash
# 1. Ativar ambiente virtual
cd /home/osboxes/Desktop/fortianalyzer-chatbot
source venv/bin/activate

# 2. Configurar .env (se ainda não configurou)
cp .env.example .env
nano .env

# 3. Navegar para pasta de testes
cd tests/
```

### Executar Teste Individual

```bash
python test_connection.py
```

### Executar Todos os Testes

```bash
# Executar um por um
for test in test_*.py; do
    echo "=== Executando $test ==="
    python "$test"
    echo ""
done
```

---

## 📊 Resultados Esperados

### Teste com Sucesso ✅

```
✅ Conectado ao FortiAnalyzer
✅ Sistema: FAZ-PRIMARY v7.4.2
✅ Encontrados 15 registros
✅ Validação: Todos os logs têm action de bloqueio
🎉 TESTE PASSOU!
```

### Teste com Aviso ⚠️

```
✅ Conectado ao FortiAnalyzer
⚠️  Nenhum dado encontrado (pode ser normal se não houver bloqueios)
✅ TESTE PASSOU (sem dados)
```

### Teste com Falha ❌

```
❌ Erro ao conectar: Connection refused
❌ TESTE FALHOU
```

---

## 🔧 Configuração

Os testes usam as configurações do arquivo `.env` na raiz do projeto:

```bash
FAZ_HOST=192.168.1.100
FAZ_USERNAME=admin
FAZ_PASSWORD=sua_senha
TEST_ADOM=root  # ADOM para testes
```

### Variável TEST_ADOM

Alguns testes permitem especificar um ADOM diferente:

```bash
# No .env
TEST_ADOM=PRODUCTION

# Ou via linha de comando
TEST_ADOM=PRODUCTION python test_devices.py
```

---

## 📝 Logs de Teste

Logs detalhados são salvos em:

```bash
../logs/test_*.log
```

Visualizar logs:

```bash
# Ver últimos logs
tail -f ../logs/app.log

# Buscar erros
grep ERROR ../logs/app.log

# Buscar teste específico
grep "test_application_control" ../logs/app.log
```

---

## 🐛 Debug

### Aumentar Nível de Log

```python
# No início do script de teste
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Modo Verbose

```bash
# Executar com saída detalhada
python -v test_connection.py
```

### Ver Requisições HTTP

```python
# Adicionar no teste
import http.client as http_client
http_client.HTTPConnection.debuglevel = 1
```

---

## ✅ Checklist de Validação

Antes de considerar os testes completos, verifique:

- [ ] `test_connection.py` - Conexão básica funciona
- [ ] `test_devices.py` - Lista dispositivos corretamente
- [ ] `test_adoms.py` - Lista ADOMs corretamente
- [ ] `test_logtypes.py` - Todos os logtypes funcionam
- [ ] `test_webfilter.py` - Webfilter retorna dados
- [ ] `test_application_control_webfilter.py` - Validação completa passa
- [ ] `test_chatbot_integration.py` - Integração Gemini funciona

---

## 🎯 Testes Automatizados no CI/CD

Para integração contínua, crie:

```bash
#!/bin/bash
# run_tests.sh

set -e

echo "🧪 Executando testes..."

python test_connection.py
python test_devices.py
python test_adoms.py
python test_application_control_webfilter.py

echo "✅ Todos os testes passaram!"
```

---

## 📚 Documentação Relacionada

- **Documentação principal**: [`../DOCUMENTATION.md`](../DOCUMENTATION.md)
- **Validação API**: [`../docs/ANALISE_API_APPLICATION_CONTROL_WEBFILTER.md`](../docs/ANALISE_API_APPLICATION_CONTROL_WEBFILTER.md)
- **Guia rápido**: [`../docs/GUIA_RAPIDO.md`](../docs/GUIA_RAPIDO.md)

---

## 🆘 Solução de Problemas

### Erro: ModuleNotFoundError

```bash
# Ativar ambiente virtual
source ../venv/bin/activate

# Instalar dependências
pip install -r ../requirements.txt
```

### Erro: Connection refused

```bash
# Verificar se FortiAnalyzer está acessível
ping <FAZ_HOST>

# Verificar configuração no .env
cat ../.env
```

### Erro: Nenhum dado retornado

```bash
# Normal se não houver logs no período
# Testar com período maior no código:
time_range="last-7-days"
```

---

## 📞 Suporte

Se os testes falharem:

1. Verifique logs: `tail -f ../logs/app.log`
2. Consulte documentação: [`../DOCUMENTATION.md`](../DOCUMENTATION.md)
3. Revise configuração: `.env`

---

**Desenvolvido por stormcrow94**  
Sistema: VIVA-HUNTING-AI  
Versão: 1.0.0

