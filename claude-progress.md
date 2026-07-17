# claude-progress.md — Node Data CRM

> Estado da última sessão de trabalho. Atualize ao terminar cada sessão (regra do CLAUDE.md §🧠).

## 🟢 Onde paramos

**Data:** 2026-07-16
**Último em `main`:** `5e05259` — `feat: DEMO_OPENAI_MODEL próprio pro bot de demo`
(antes: `1a67392` agente Marcos, `b3288ed` retema visual do Funil Total)

### 🎬 Agente de IA "Marcos" no WhatsApp — **FUNCIONANDO AO VIVO** ✅

Uma DEMO (a pedido do João, pro sócio) de um agente de IA que responde e AGE
sobre o CRM inteiro pelo WhatsApp. **Testado ao vivo**: o Marcos respondeu
"faturamento do mês R$ 21.700 · 5 leads em negociação" no zap. 🎉

**Peças construídas:**
- **`agente_demo.py`** (novo) — cérebro ISOLADO do agente do Telegram (não mexi
  nele). Loop OpenAI com tool-use próprio. Persona "Marcos". Ferramentas:
  - Leitura: `metricas_negocio` (faturamento/lucro/MRR/pipeline/tarefas), `buscar_cliente`, `listar_leads`, `listar_tarefas` — agrega em Python (volume pequeno).
  - Escrita (auditada): `criar_lead`, `criar_tarefa`, `mudar_etapa_lead`, `registrar_receita`. IDs nascem com o sentinela de demo `d3d3d3d3-0b…` (limpáveis).
- **`server.py`** — webhook `POST /webhook/evolution` (reativo, ignora eco/grupos,
  dedupe em memória, whitelist opcional `DEMO_ALLOWED_PHONES`, responde em thread)
  + `send_whatsapp_text()` usando instância dedicada `DEMO_EVOLUTION_INSTANCE`
  (default `marcos`, reusa `EVOLUTION_API_URL/KEY` dos alertas).
- **`testar_agente.py`** (novo) — testa o cérebro no terminal, SEM Flask (mini
  cliente Supabase REST inline; só precisa de `openai python-dotenv requests`).

**Config de produção (Coolify, app antigravit):**
- `DEMO_OPENAI_MODEL=gpt-5.4-mini` (isolado do `OPENAI_MODEL` do agente Telegram)
- `DEMO_EVOLUTION_INSTANCE=marcos` (instância própria do bot; número 5531 9930-8699)
- `DEMO_WEBHOOK_TOKEN=…` (gerado; guardado só no Coolify — NÃO no repo)
- Reusa `OPENAI_API_KEY`, `EVOLUTION_API_URL`, `EVOLUTION_API_KEY`.
- **Webhook Evolution** da instância `marcos` aponta pra
  `https://crm.nodedata.com.br/webhook/evolution?token=…`, evento `MESSAGES_UPSERT`.

### 📊 Dados fake da demo (no Supabase de PRODUÇÃO `vrnejhzsugrcedzbwbnj`)

~209 linhas fake pra "empresa grande" (32 leads, 11 contratos R$ 21.700/mês,
64 receitas ~R$ 126k/ano, 49 despesas, 17 tarefas, 10 contatos, 12 histórico,
3 metas), inseridas via Supabase MCP. **TODA linha fake tem `id` LIKE
`d3d3d3d3-%`** (o que o agente criar ao vivo também). ⚠️ Aparecem nos dashboards
que os sócios usam (decisão consciente do João; apagar depois).

**Limpeza cirúrgica** (via MCP `execute_sql` no `vrnejhzsugrcedzbwbnj`, nessa ordem):
```sql
delete from historico_acoes where id::text like 'd3d3d3d3-%';
delete from tarefas          where id::text like 'd3d3d3d3-%';
delete from contatos         where id::text like 'd3d3d3d3-%';
delete from receitas         where id::text like 'd3d3d3d3-%';
delete from despesas         where id::text like 'd3d3d3d3-%';
delete from contratos        where id::text like 'd3d3d3d3-%';
delete from entidades        where id::text like 'd3d3d3d3-%';
delete from metas            where id::text like 'd3d3d3d3-%';
delete from leads            where id::text like 'd3d3d3d3-%';
```
(verticais/categorias/contas reaproveitadas são REAIS — não apagar.)

## ⏭️ Próximos passos / ideias
- Evoluir o Marcos: mais ferramentas (relatórios por vertical, comparativo de
  meses), memória de conversa, confirmação antes de ações destrutivas.
- Depois da demo: rodar o SQL de limpeza acima.
- Passo 2 do roadmap original (parado): UI de Kanban dos sócios (`mensagens_socios` + `tarefas`).

## ⚠️ Caveats desta feature
- As **ferramentas de ESCRITA do Marcos reportam sucesso otimista** — o cliente
  REST engole 4xx (dívida técnica #1 abaixo). Como o agente usa a `service_role`
  key (bypassa RLS), os inserts funcionam; mas se um dia trocar pra anon, falha
  em silêncio. Validado ao vivo que escreve OK.
- O `.env` LOCAL do antigravit foi criado nesta sessão (Supabase `crm-nodedata`
  + OpenAI) só pra testar — gitignored, nunca commitar.

## 🧱 Dívidas técnicas conhecidas (fora de escopo agora)
1. **Cliente REST customizado engole 4xx do PostgREST** (`server.py` `SupabaseTable`) — devia `raise_for_status()`.
2. **RLS é tickbox** — policies `FOR ALL TO public USING (true)`. PR dedicado com cuidado (risco de derrubar o CRM).
3. **`tarefas.status` existe** (aberta/em_andamento/aguardando/concluida/cancelada) — ok pro Kanban.
4. Gunicorn, quebra de `server.py`, Redis pro rate limiter (já no CLAUDE.md §🔧).

## 📋 Convenções confirmadas
- Migrações/seed no Supabase: via MCP (`execute_sql`/`apply_migration`) no projeto `vrnejhzsugrcedzbwbnj`; confirmar com SELECT depois — não confiar só em stdout.
- `.md` são versionados. `.env`/segredos nunca no repo (só Coolify).
