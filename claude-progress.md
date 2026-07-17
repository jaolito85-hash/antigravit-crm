# claude-progress.md — Node Data CRM

> Estado da última sessão de trabalho. Atualize ao terminar cada sessão (regra do CLAUDE.md §🧠).

## 🟢 Onde paramos

**Data:** 2026-07-17
**Último em `main`:** `561647c` — `fix: memória de conversa no Marcos`
(cadeia do dia: `b3288ed` retema visual FT → `1a67392`/`5e05259` agente Marcos →
`a9ee00d` saldo/contratos → `6e70049` proativo → `561647c` memória)

### 🎬 Agente de IA "Marcos" no WhatsApp — **FUNCIONANDO AO VIVO** ✅

DEMO (a pedido do João, pro sócio mostrar a empresários) de um agente que
responde e AGE sobre o CRM inteiro pelo WhatsApp. Persona "Marcos". Isolado do
agente do Telegram (não mexi nele). **Validado ao vivo** (faturamento, gastos,
lucro, MRR, pipeline, saldo, tarefas, criação de tarefa, proatividade).

**Arquivos:** `agente_demo.py` (cérebro, loop OpenAI tool-use), webhook
`POST /webhook/evolution` + `send_whatsapp_text`/`send_whatsapp_media` no
`server.py`, `testar_agente.py` (testa no terminal sem Flask).

**Ferramentas do Marcos:**
- LEITURA: `metricas_negocio` (faturamento/lucro/MRR/pipeline + **top_clientes** +
  **alertas**: tarefas atrasadas e contratos vencendo em 30d), `buscar_cliente`,
  `listar_leads`, `listar_tarefas`, **`saldo_contas`** (contas bancárias:
  saldo_inicial + recebidas − pagas), **`consultar_contratos`** (por status
  ativo/encerrado/negociacao). Agrega em Python (volume pequeno).
- ESCRITA (auditada, id sentinela `d3d3d3d3-0b…`): `criar_lead`, `criar_tarefa`,
  `mudar_etapa_lead`, `registrar_receita`.
- **`gerar_relatorio`** → monta um PDF executivo (reportlab) e envia no WhatsApp
  via `send_whatsapp_media` (Evolution `sendMedia`, base64).

**Proatividade (16-17/07):**
- Prompt: oferece o próximo passo e sinaliza ⚠️ alertas mesmo sem pedir.
- **Memória de conversa**: `_demo_historico` guarda as últimas 4 trocas por número
  e passa em `responder(historico=…)` — entende "quero"/"pode enviar" como
  confirmação (era o bug de perguntar de novo).
- **Job em background** `_marcos_proativo_loop` (start no `__main__`): resumo
  diário no horário + avisos por evento (contrato vencendo/tarefa atrasada,
  dedupe). Envia pra `DEMO_DIGEST_PHONE`. Gatilho manual **`/proativo`** no
  webhook pra demonstrar ao vivo.
- Glossário no prompt: não confundir lead *Fechado* (funil) × contrato
  *encerrado* (status) × *saldo* (conta bancária).

**Config produção (Coolify, app antigravit):**
- `DEMO_OPENAI_MODEL=gpt-5.4-mini` (⚠️ conta do João: gpt-4o-mini/gpt-5.5 dão erro)
- `DEMO_EVOLUTION_INSTANCE=marcos` (bot; nº 5531 9930-8699), `DEMO_WEBHOOK_TOKEN=…`
- **`DEMO_DIGEST_PHONE`** (nº que recebe o resumo/avisos — **setar pra ligar o
  proativo automático**) · `DEMO_DIGEST_HOUR` (default 8)
- Reusa `OPENAI_API_KEY`, `EVOLUTION_API_URL/KEY`. `reportlab` no requirements.
- Webhook Evolution (instância `marcos`) → `crm.nodedata.com.br/webhook/evolution?token=…`, evento `MESSAGES_UPSERT`.

### 📊 Dados fake da demo (Supabase de PRODUÇÃO `vrnejhzsugrcedzbwbnj`)

~209 linhas fake "empresa grande" (32 leads, 11 contratos R$ 21.700/mês, 64
receitas ~R$126k/ano, 49 despesas, 17 tarefas, 10 contatos, 12 histórico, 3
metas), via Supabase MCP. **TODA linha fake tem `id` LIKE `d3d3d3d3-%`** (o que o
agente cria ao vivo também). ⚠️ Aparecem nos dashboards dos sócios (decisão do
João; apagar depois). Ajuste 17/07: 2 contratos (Loja Moda Center 27/07,
Condomínio 08/08) com `data_fim` <30d pro alerta de "contrato vencendo" ter o que mostrar.

**Limpeza cirúrgica** (MCP `execute_sql`, nessa ordem por causa das FKs):
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

## ⏭️ Próximos passos (retomar amanhã)
- **Confirmar o PDF ao vivo**: a geração está validada (2400 bytes, %PDF ok), mas
  o envio pela Evolution (`sendMedia`, base64) só foi testado no código. Se não
  chegar, olhar log `[DEMO] sendMedia falhou …` e ajustar o formato (v1 vs v2).
- **Setar `DEMO_DIGEST_PHONE`** no Coolify pra ligar o resumo diário + avisos
  automáticos (sem ele o proativo automático fica off; `/proativo` e o resto funcionam).
- Ideias: relatório por vertical, comparativo entre meses, confirmação antes de
  ação destrutiva, importar conversa.
- Depois da demo: rodar o SQL de limpeza.
- Passo 2 do roadmap original (parado): UI de Kanban dos sócios.

## ⚠️ Caveats
- **Escrita do Marcos reporta sucesso otimista** — cliente REST engole 4xx (dívida
  #1). Usa `service_role` (bypassa RLS), então inserts funcionam; validado ao vivo.
- O `.env` LOCAL do antigravit foi criado nesta sessão (só pra testar) — gitignored.

## 🧱 Dívidas técnicas conhecidas (fora de escopo agora)
1. **Cliente REST engole 4xx do PostgREST** (`server.py` `SupabaseTable`) — devia `raise_for_status()`.
2. **RLS é tickbox** — policies `FOR ALL TO public USING (true)`. PR dedicado com cuidado.
3. `tarefas.status` existe (aberta/em_andamento/aguardando/concluida/cancelada).
4. Gunicorn, quebra de `server.py`, Redis pro rate limiter (CLAUDE.md §🔧).

## 📋 Convenções confirmadas
- Seed/migração no Supabase: via MCP (`execute_sql`/`apply_migration`) no `vrnejhzsugrcedzbwbnj`; confirmar com SELECT depois.
- `.md` versionados. `.env`/segredos nunca no repo (só Coolify).
