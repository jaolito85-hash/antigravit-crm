# Node Data — CRM — Instruções para o Claude Code

## Sobre o Projeto

Node Data CRM é uma plataforma de prospecção B2G (Business-to-Government) para gerenciar leads e contatos de prefeituras e órgãos públicos.

Stack: Flask (Python), Supabase (REST API direto), Coolify/Docker.

**Porta:** 5010

## Estrutura do Repositório

```
server.py          — App Flask principal (usa REST client customizado para Supabase)
Dockerfile         — Container (python server.py direto, sem Gunicorn)
requirements.txt   — Dependências Python (flask, python-dotenv, werkzeug, requests)
.env.example       — Template de variáveis de ambiente
templates/         — Interface CRM (crm.html), login.html
PRODUCTION_CHECKLIST.md — Regras de qualidade e segurança
```

## Atenção: Diferenças desta Vertical

1. **Sem Gunicorn** — Dockerfile usa `python server.py` direto (não está em formato de produção padrão)
2. **Sem supabase SDK** — usa cliente REST customizado (`SupabaseTable`, `SupabaseREST`)
3. **Sem directives/** e **execution/** — vertical em desenvolvimento
4. **Rate limiting** — Flask-Limiter (60 req/min) já configurado
5. **Hashing de senhas** — werkzeug para autenticação

## Próximas Melhorias Necessárias (quando for mexer)

- Adicionar Gunicorn ao Dockerfile para produção
- Adicionar `directives/` com SOP do CRM
- Adicionar `execution/` com seed.sql e scripts de dados
- Considerar migrar para supabase SDK

## Regras de Produção

Sempre siga as regras de qualidade e segurança descritas em `PRODUCTION_CHECKLIST.md` ao:
- Analisar código existente
- Sugerir mudanças
- Criar código novo
- Revisar antes de deploy

## Regras que Valem Sempre

### Segurança
- Nunca coloque chaves, tokens ou senhas no código — sempre em `.env`
- Dados de prospecção B2G podem ser sensíveis — nunca exponha em logs

### Código
- Sempre use try/except em chamadas externas (Supabase REST)
- Sempre configure timeout nas requisições HTTP (mínimo 10s)
- Sempre valide inputs antes de processar
- Sempre adicione logs nos pontos críticos
- Rate limiting já está configurado — não remover

### Estilo
- Python com type hints quando possível
- Docstrings em português
- Nomes de variáveis descritivos em português ou inglês
- Comentários explicando o "porquê", não o "o quê"
