# 📚 Guia de Sincronização da Wiki

## 🎯 Visão Geral

Este repositório possui um sistema automatizado de sincronização da documentação técnica (`wiki.md`) para a Wiki do GitHub.

---

## 🔄 Como Funciona

### Fluxo Automático

1. **Você edita** `wiki.md` ou `README.md` no repositório principal
2. **Faz commit** e push para a branch `main`
3. **GitHub Actions detecta** a mudança
4. **Workflow executa** automaticamente:
   - Clona o repositório da wiki
   - Copia `wiki.md` → `Home.md`
   - Copia `README.md` → `Quick-Start.md`
   - Cria sidebar de navegação
   - Cria footer padronizado
   - Commit e push para a wiki
5. **Wiki atualizada** em ~30 segundos! ✅

---

## 📝 Estrutura da Wiki

Após a sincronização, a wiki terá:

```
📁 Wiki do Repositório
├── Home.md                    # Conteúdo completo do wiki.md
├── Quick-Start.md             # Conteúdo do README.md
├── _Sidebar.md                # Navegação lateral (gerada automaticamente)
└── _Footer.md                 # Footer com links (gerado automaticamente)
```

---

## 🚀 Como Atualizar a Wiki

### Método 1: Automático (Recomendado)

1. **Edite** `wiki.md` diretamente no repositório
2. **Commit** as mudanças:
   ```bash
   git add wiki.md
   git commit -m "docs: atualiza seção X da wiki"
   git push origin main
   ```
3. **Aguarde** ~30 segundos
4. **Acesse** a wiki: ela estará atualizada automaticamente!

### Método 2: Trigger Manual

Se você editou a wiki mas o workflow não rodou:

1. Vá para **Actions** no GitHub
2. Selecione **"Sync Wiki"**
3. Clique em **"Run workflow"**
4. Escolha a branch `main`
5. Clique em **"Run workflow"**

---

## 📐 Boas Práticas

### ✅ Faça

- ✅ Edite sempre `wiki.md` no repositório principal
- ✅ Use títulos Markdown (`##`, `###`) para estruturar seções
- ✅ Adicione links internos com âncoras: `[Seção](Home#titulo-da-seção)`
- ✅ Teste localmente antes de commitar
- ✅ Commits descritivos: `docs: adiciona seção sobre X`

### ❌ Evite

- ❌ Editar diretamente na wiki do GitHub (será sobrescrito)
- ❌ Links absolutos para outras páginas da wiki
- ❌ Imagens hospedadas externamente (prefira assets no repo)
- ❌ Commits sem mensagem clara

---

## 🔗 Estrutura de Links

### Links para Seções Internas

Use âncoras para linkar seções dentro do `wiki.md`:

```markdown
[Ver Arquitetura](Home#2-arquitetura)
[Setup Detalhado](Home#4-setup-detalhado)
```

### Links para Outras Páginas

```markdown
[Quick Start](Quick-Start)
[Voltar ao Início](Home)
```

### Links para Código

```markdown
[Ver app.py](../blob/main/app.py)
[Ver tests/](../tree/main/tests)
```

---

## 🎨 Sidebar Automática

A sidebar é gerada automaticamente e inclui:

- 🏠 **Início**: Home e Quick Start
- 🎯 **Principais Seções**: Links para seções principais
- 🔧 **Operação**: Funcionalidades, testes, troubleshooting
- 📖 **Recursos Avançados**: ADOM, memória contextual, gestão de usuários
- 🚀 **Roadmap**: Próximos passos e compatibilidade

**Atualizar sidebar**:
Edite o template em `.github/workflows/sync-wiki.yml` na seção:
```yaml
cat > wiki/_Sidebar.md << 'EOF'
```

---

## 🐛 Troubleshooting

### Problema: Workflow não executou

**Causa**: Mudança não foi em `wiki.md` ou `README.md`

**Solução**: Execute manualmente (Método 2 acima)

### Problema: Wiki não atualizou

**Causa**: Possível erro no workflow

**Solução**:
1. Vá para **Actions** → **Sync Wiki**
2. Veja o último run
3. Verifique os logs
4. Corrija o erro e execute novamente

### Problema: Erro de permissão

**Causa**: Token sem permissão para escrever na wiki

**Solução**:
1. Vá para **Settings** → **Actions** → **General**
2. Em "Workflow permissions", selecione:
   - ✅ "Read and write permissions"
3. Salve e execute o workflow novamente

### Problema: Wiki não existe

**Causa**: Wiki não foi criada no repositório

**Solução**:
1. Vá para **Settings** → **Features**
2. Marque ✅ **Wikis**
3. Vá para a aba **Wiki**
4. Clique em **Create the first page**
5. Salve qualquer conteúdo (será sobrescrito)
6. Execute o workflow

---

## 📊 Monitoramento

### Ver Status do Workflow

1. Acesse **Actions** no GitHub
2. Selecione **Sync Wiki** na lista
3. Veja o histórico de execuções:
   - ✅ Verde = Sucesso
   - ❌ Vermelho = Falha
   - 🟡 Amarelo = Em execução

### Ver Logs Detalhados

1. Clique em uma execução
2. Clique em `sync-wiki` no job
3. Expanda os steps para ver logs

---

## 🎓 Exemplo Completo

### 1. Adicionar Nova Seção

Edite `wiki.md`:
```markdown
## 22. Nova Funcionalidade

Descrição da nova funcionalidade...
```

### 2. Commit

```bash
git add wiki.md
git commit -m "docs: adiciona seção sobre nova funcionalidade"
git push origin main
```

### 3. Aguardar

- Workflow executa automaticamente
- Verifica status em **Actions**
- Wiki atualizada em ~30 segundos

### 4. Verificar

Acesse: `https://github.com/SEU_USUARIO/VIVA-HUNTING-AI/wiki`

---

## 🔐 Segurança

- ✅ Usa `GITHUB_TOKEN` padrão (sem secrets adicionais)
- ✅ Permissões limitadas ao repositório
- ✅ Commits auditáveis (via github-actions[bot])
- ✅ Rollback possível via histórico git

---

## 📞 Suporte

**Problemas com a sincronização?**

1. Verifique os logs do workflow
2. Consulte este guia
3. Abra uma issue se necessário

---

## 🔮 Melhorias Futuras

Possíveis melhorias no workflow:

- [ ] Validação de Markdown antes do sync
- [ ] Geração automática de índice
- [ ] Notificações no Slack/Discord
- [ ] Versionamento da wiki
- [ ] Preview antes do merge

---

**Desenvolvido por**: stormcrow94  
**Projeto**: VIVA-HUNTING-AI  
**Versão do Workflow**: 1.0.0

