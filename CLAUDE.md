# CLAUDE.md — Node Data CRM

## 🎯 Sobre o Projeto

- **O que é:** CRM interno da **Node Data** — empresa que desenvolve software de inteligência para **prefeituras** e **campanhas políticas**. Centraliza prospecção B2G, leads, contratos, tarefas, documentos, despesas, metas e Health Monitor dos sistemas em produção dos clientes.
- **Stack:** Flask 3 (Python 3.11) + Supabase (cliente REST customizado, sem SDK) + Coolify/Docker em VPS Hostinger.
- **Status:** **Produção** — usado no dia-a-dia pelos sócios. Mexer com cuidado.
- **Sócios:** João (dono) + sócio + possível investidor entrando com participação minoritária.
- **Porta:** `5010`

### Empresa em uma linha
A Node Data entrega plataformas SaaS que coletam feedback de cidadãos/clientes via WhatsApp, com análise de sentimento por IA e dashboards em tempo real — vendidas para prefeituras e, agora, para campanhas políticas.

---

## 📜 REGRAS INVIOLÁVEIS

1. **Arquivos `.md` são código.** Versionados, revisados, enxutos. Este arquivo é o manual de operação do projeto.
2. **Nunca passar de 60% da janela de contexto.** Aos 60%, pare. Salve estado em `claude-progress.md` antes de qualquer `/compact` ou `/clear`.
3. **Seja obsessivo em instrução e acesso.** Sem ambiguidade no escopo. Princípio do menor privilégio sempre — esta vertical lida com dados sensíveis (LGPD).

---

## 🏗️ Arquitetura Atual (estado real do código)

### Estrutura do repositório
```
server.py                  Flask app único (1.3k linhas) com REST client customizado p/ Supabase
templates/crm.html         SPA do CRM (~2k linhas, vanilla JS + Remix Icons)
templates/login.html       Tela de login
Dockerfile                 python:3.11-slim, roda `python server.py` direto (sem Gunicorn)
requirements.txt           flask, python-dotenv, werkzeug, requests
.env.example               Template de variáveis (Supabase, Evolution API, Health Monitor)
PRODUCTION_CHECKLIST.md    Regras de segurança/LGPD pré-deploy
```

### Tabelas Supabase em uso
`crm_users`, `leads`, `verticais`, `tarefas`, `contratos`, `documentos`, `historico_acoes`, `contatos`, `despesas`, `metas`, `health_logs`, `audit_log`.

### Módulos da UI (sidebar do CRM)
Dashboard · Leads/Clientes · Tarefas · Contratos · Documentos · Despesas · Docs Empresa · Health Monitor · Usuários · Audit Log.

### O que já funciona
- Auth com sessão Flask (4h) + roles `admin` / `editor` / `viewer` + audit log de tudo que é escrita.
- Rate limiting (60 req/min, in-memory).
- Health Monitor central: bate em `/api/health` dos clientes (Prefeitura Ivaté, Atacaforte) a cada 5 min, registra em `health_logs` e dispara alerta WhatsApp via Evolution API com cooldown de 15 min.
- CRUD completo das 12 tabelas via `/api/*`.
- Headers de segurança (X-Frame, X-Content-Type, HSTS em prod).

### Tipos de lead suportados hoje
`empresa`, `governo`, `politico` — a vertical de campanha política **já está modelada na UI**, falta acoplar fluxo dedicado.

---

## 🚀 Visão Estratégica (para o que o CRM ainda precisa virar)

> Esta seção registra o que João pediu como dono: o panorama de para onde o CRM deve evoluir. **Não é backlog imediato** — é norte. Antes de implementar qualquer item, abra Plan Mode (`Shift+Tab`) e valide o escopo.

### Visão de produto
O CRM precisa ser o **cérebro operacional dos 3 sócios** (João + sócio + investidor). Tudo que rolar com clientes, ideias, decisões e tarefas tem que cair aqui automaticamente — sem ninguém ter que abrir o sistema pra digitar.

### Pilares que faltam construir

1. **Canal único de captura via WhatsApp (e/ou Telegram)**
   - Um número de WhatsApp compartilhado entre os 3 sócios.
   - Cada mensagem mandada nesse canal (sugestão, tarefa, anotação de conversa com cliente, ideia) é capturada e classificada.
   - Decidir Evolution API (já em uso) vs Telegram Bot — propor trade-offs antes de codar.

2. **Agente IA especialista no negócio Node Data**
   - System prompt que conhece: o que a empresa faz, clientes ativos, propostas em andamento, contratos, documentação interna.
   - Recebe o stream do canal WhatsApp/Telegram e decide para onde a mensagem vai: tarefa em Kanban, nota em lead, lembrete, documento.
   - Lê e escreve nas tabelas do Supabase via API do próprio CRM (não direto no banco — passar pela camada de auth/audit).
   - Modelo recomendado: **Claude (Sonnet ou Haiku) com prompt caching** — sócios mandam muita mensagem curta, cache do contexto da empresa derruba custo drasticamente.

3. **Kanban dos sócios no dashboard**
   - Colunas mínimas: `Inbox` (caiu do WhatsApp, ainda não triado) → `A fazer` → `Em andamento` → `Aguardando cliente` → `Feito`.
   - Cada card carrega: origem (qual sócio mandou), cliente associado (se houver), prazo, anexos.
   - Drag-and-drop. Hoje a tabela `tarefas` existe mas não tem UI de Kanban.

4. **Base de conhecimento centralizada acessível ao agente**
   - A vertical já tem `documentos` (CRUD pronto). Falta:
     - Indexar (embeddings) para que o agente consulte.
     - Garantir que SOPs, propostas-modelo, valores praticados, scripts de venda estejam ali.

5. **Integração com os sistemas dos clientes (URLs no Coolify)**
   - Health Monitor já bate em `HEALTH_URL_PREFEITURA` e `HEALTH_URL_ATACAFORTE`. Padronizar:
     - Toda nova vertical/cliente entrega rota `/api/health` no formato consumido por `check_project_health()`.
     - Cada cliente novo → adicionar em `MONITORED_PROJECTS` (server.py:1006) + variáveis no Coolify.

### URLs e infra em produção
- VPS: Hostinger
- Orquestração: Coolify
- Bancos: Supabase (1 projeto por vertical)
- WhatsApp: Evolution API (instância dos sócios)
- Domínios: `*.nodedata.com.br` (`prefeitura`, `atacaforte`, etc.)

### Roadmap sugerido (ordem de impacto x esforço)
1. Webhook Evolution API → endpoint `/webhook/sociedade` que grava mensagem bruta em uma nova tabela `mensagens_socios`.
2. UI de Kanban consumindo a tabela `tarefas` (a tabela já existe — é só frontend).
3. Agente IA classificando `mensagens_socios` → criando `tarefas` / atualizando `historico_acoes` / anexando em `leads`.
4. Indexação de `documentos` + tool de busca no agente.
5. Vertical "Campanha Política" com pipeline próprio (já tem `tipo=politico` em `contatos`).

---

## 🛠️ Comandos do projeto

- **Rodar dev local:** `python server.py` (sobe em `http://localhost:5010`)
- **Instalar deps:** `pip install -r requirements.txt`
- **Build Docker:** `docker build -t nodedata-crm .`
- **Rodar Docker local:** `docker run --env-file .env -p 5010:5010 nodedata-crm`
- **Smoke test (antes de declarar feature pronta):**
  - `curl http://localhost:5010/health` → status 200
  - Login com admin → criar lead de teste → ver no dashboard → arquivar
- **Deploy:** push na branch principal → Coolify pega automático. **Nunca subir arquivo por FTP/SSH direto.**

---

## ⚠️ NÃO TOCAR (sem aprovação explícita)

- `.env` e `.env.*` (qualquer arquivo de credencial)
- `SUPABASE_KEY`, `EVOLUTION_API_KEY`, `SECRET_KEY`, `FERNET_KEY` — só leitura via `os.getenv`
- Schema das 12 tabelas em produção — sempre **criar migração nova**, nunca alterar coluna existente sem coordenar
- Configuração do Health Monitor de clientes ativos (`MONITORED_PROJECTS` em `server.py:1006`) — derrubar isso silencia alertas reais
- Rate limiter — não remover
- `audit_log` — não desligar, é exigência LGPD

---

## 🧠 Workflow Obrigatório

1. **Antes de começar:** leia `claude-progress.md` (se existir) para saber onde paramos.
2. **Tarefa > 30 linhas:** ative Plan Mode (`Shift+Tab`). Apresente o plano. Aguarde aprovação.
3. **Antes de qualquer mudança no Flask:** rode os checks do `PRODUCTION_CHECKLIST.md` — é a régua oficial de qualidade desta vertical.
4. **Ao cometer um erro:** escreva a regra preventiva na seção "🐛 Lições aprendidas" deste arquivo, formulada como diretiva ("Sempre X", "Nunca Y").
5. **Antes de declarar feature pronta:** smoke test real (curl ou clique no CRM em browser). "Compilou" ≠ "funciona".
6. **Ao terminar sessão:** atualize `claude-progress.md` com o que foi feito, próximos passos, bloqueios e decisões.

---

## 📋 Regras de Produção (resumo — referência completa em `PRODUCTION_CHECKLIST.md`)

### Segurança e LGPD
- Nada de chave/token/senha hardcoded — sempre `os.getenv`.
- Telefone/CPF/nome completo **nunca** em logs (mascarar com `***`).
- RLS do Supabase ativo em tabelas com dados de cliente.
- Toda rota de webhook valida origem por header secret.
- CORS restrito em produção, nunca wildcard.

### Código
- Toda chamada externa (`requests.*`, Supabase REST, OpenAI, Evolution) dentro de `try/except` com mensagem específica.
- `timeout=15` mínimo em qualquer HTTP — sem exceção.
- Fallback explícito quando o serviço externo falha (ex.: salvar bruto e processar depois).
- Validar input antes de processar — webhooks com a mesma rigidez de formulários.
- Sem query dentro de loop (N+1) — usar join do PostgREST.
- Webhooks idempotentes (chave por `event_id`).
- Logs nos pontos críticos: webhook recebido, WhatsApp enviado, OpenAI chamado, audit gravado.

### Estilo
- Python com type hints quando ajuda.
- Docstrings curtas em português.
- Comentários explicam o **porquê**, não o **o quê**.
- Não criar abstração para hipotético — 3 linhas parecidas é melhor que abstração prematura.

---

## 🔧 Melhorias técnicas pendentes (dívida conhecida)

- [ ] **Gunicorn no Dockerfile** — hoje sobe `python server.py` direto, sem worker manager.
- [ ] **Health check** — rota `/health` documentada existe? Validar antes do próximo deploy.
- [ ] **Migrar para SDK supabase-py** ou consolidar o REST client em arquivo separado (hoje vive dentro de `server.py`).
- [ ] **Quebrar `server.py`** (1.3k linhas) em blueprints Flask por domínio: `auth`, `leads`, `tarefas`, `health_monitor`, `webhooks`.
- [ ] **`directives/` e `execution/`** — outras verticais Node Data têm, esta não. Trazer SOP + seed.sql.
- [ ] **Storage de rate limiter** — hoje é `memory://`. Em multi-instância vira inconsistente. Migrar para Redis quando escalar.

---

## 📝 Convenções

- **Idioma do código e comentários:** português (PT-BR).
- **Idioma de commits:** português, formato `tipo: descrição` (ex.: `fix: corrige timeout no Health Monitor`, `feat: adiciona webhook sociedade`).
- **Nomenclatura:** `snake_case` em Python e nos campos do Supabase. `camelCase` no JS do `crm.html`.
- **Rotas:** prefixo `/api/<recurso>` para JSON, raiz para páginas renderizadas.
- **IDs do Supabase:** UUID — nunca expor sequence numérica.

---

## 🐛 Lições aprendidas (auto-corretivas)

<!-- Toda vez que o Claude errar, adicione a regra preventiva aqui.
     Formule como diretiva ("Sempre X", "Nunca Y"). Máx 15 regras. -->

- Sempre passar pelo `audit()` em qualquer escrita (create/update/delete) em tabela com dados de cliente.
- Sempre validar token de webhook antes de tocar no payload — webhook sem auth é porta aberta.
- Nunca remover o rate limiter do Flask, mesmo "temporariamente para debug".
- Nunca alterar coluna existente do Supabase em produção — criar nova coluna/migração e migrar dados.
