# GitHub Actions Workflows

## 📋 Workflows Disponíveis

### 1. `sync-wiki.yml` - Sincronização Automática da Wiki

**Descrição**: Sincroniza automaticamente o conteúdo do `wiki.md` para a wiki do GitHub.

**Triggers**:
- Push para `main` que modifique `wiki.md` ou `README.md`
- Dispatch manual via interface do GitHub

**O que faz**:
1. ✅ Copia `wiki.md` → `Home.md` (página principal da wiki)
2. ✅ Copia `README.md` → `Quick-Start.md` 
3. ✅ Cria `_Sidebar.md` com navegação estruturada
4. ✅ Cria `_Footer.md` com informações do projeto
5. ✅ Commit e push automático para o repositório da wiki

**Como usar manualmente**:
1. Acesse a aba "Actions" no GitHub
2. Selecione "Sync Wiki" na lista de workflows
3. Clique em "Run workflow"
4. Escolha a branch `main`
5. Clique em "Run workflow"

**Resultado**:
- Wiki sempre atualizada com a última versão do `wiki.md`
- Navegação lateral automática com links para todas as seções
- Footer padronizado com informações do projeto

**Notas**:
- Requer que a wiki esteja habilitada no repositório
- Usa `GITHUB_TOKEN` automaticamente (sem configuração adicional)
- Commits são feitos como `github-actions[bot]`

---

## 🔧 Adicionar Novos Workflows

Para adicionar um novo workflow:

1. Crie um arquivo `.yml` neste diretório
2. Defina os triggers apropriados (`on:`)
3. Configure os jobs e steps necessários
4. Documente aqui no README

**Exemplo de estrutura**:
```yaml
name: Meu Workflow
on:
  push:
    branches: [main]
jobs:
  meu-job:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "Hello World"
```

---

## 📚 Recursos

- [Documentação GitHub Actions](https://docs.github.com/actions)
- [Marketplace de Actions](https://github.com/marketplace?type=actions)
- [Sintaxe de Workflow](https://docs.github.com/actions/using-workflows/workflow-syntax-for-github-actions)

---

**Desenvolvido por**: stormcrow94  
**Projeto**: VIVA-HUNTING-AI

