# claude-progress.md — Node Data CRM

> Estado da última sessão de trabalho. Atualize ao terminar cada sessão (regra do CLAUDE.md §🧠).

## 🟢 Onde paramos

**Data:** 2026-05-13
**Branch ativa:** `claude/create-crm-documentation-VEPGc`
**Último commit em `main`:** `769284b` — squash de `feat: webhook Telegram dos sócios + tabela mensagens_socios (#2)`

### Telegram webhook — passo 1 do roadmap: **CONCLUÍDO** ✅

Caminho ponta-a-ponta validado:

1. Webhook registrado em `https://crm.nodedata.com.br/webhook/telegram` com `secret_token`. `getWebhookInfo` retorna `pending_update_count:0`, sem `last_error_message`.
2. Privacy mode do `@nodidata_bot` desligado no BotFather + bot removido e readicionado ao grupo `CRM - Nodi` (chat_id `-5020881160`).
3. Policy de RLS criada na tabela `mensagens_socios` (faltava — RLS estava ON sem nenhuma policy, INSERTs eram rejeitados silenciosamente).
4. Mensagem "teste de integração" do Marcos gravou em `mensagens_socios` com `status=inbox`.

## 🐛 Bug encontrado e corrigido nesta sessão

**Sintoma:** `POST /webhook/telegram` retornava 200 mas nada chegava em `mensagens_socios`. Logs do app não mostravam nem `✅ telegram gravado`, nem `🚫`, nem `erro inserindo`.

**Causa raiz:** tabela `mensagens_socios` foi criada com `rls_enabled=true` mas sem nenhuma policy. PostgREST devolve 401/403, e o cliente REST customizado em `server.py:46-129` **não levanta exception** nesse caso — `result.data` vira `[]`, `inserted_id` vira `None`, e o código imprime `✅ telegram gravado` mentirosamente.

**Fix aplicado:** `CREATE POLICY "Acesso total mensagens_socios" ON public.mensagens_socios FOR ALL TO public USING (true) WITH CHECK (true)` — mesmo padrão de `leads`/`tarefas`. Aplicado via Supabase MCP (`apply_migration` no projeto `vrnejhzsugrcedzbwbnj`). Nenhum commit/deploy de código.

## ⏭️ Próximo passo

**Passo 2 do roadmap:** UI de Kanban dos sócios consumindo `mensagens_socios` + `tarefas`.

Plano ainda a apresentar e aprovar antes de codar.

## 🧱 Dívidas técnicas descobertas (NÃO no escopo agora — abrir PRs separados)

1. **Cliente REST customizado engole 4xx do PostgREST.** `server.py:46-129` (`SupabaseTable`/`SupabaseREST`) precisa `raise` em `status >= 400`. Foi exatamente o que fez este bug ficar invisível por horas. Adicionar `response.raise_for_status()` em `insert/update/delete/select.execute()`.

2. **RLS hardening real.** Todas as policies do projeto são `FOR ALL TO public USING (true)` — RLS ON é tickbox, não defesa. CLAUDE.md exige RLS pra dados sensíveis (LGPD). Vale um PR exclusivo: policies por role, RLS efetivo no anon, service_role só pra o webhook. Risco se feito errado: derruba o CRM inteiro. Tem que ser feito com cuidado, branch separada do Supabase e migração reversível.

3. **`tarefas` não tem coluna `status`.** Só `concluida boolean`. Pro Kanban "real" (A fazer / Em andamento / Aguardando cliente / Feito) vai precisar `ALTER TABLE` ou um campo derivado. Decisão fica pro plano do passo 2.

4. **Outras dívidas já no CLAUDE.md §🔧** (Gunicorn, quebra de `server.py`, Redis pro rate limiter) — sem novidade.

## 📋 Convenções confirmadas nesta sessão

- Branch de desenvolvimento atual: `claude/create-crm-documentation-VEPGc` (definida pelo harness, não alterar sem instrução).
- Migrações de schema/RLS no Supabase: usar `apply_migration` do MCP com nome em `snake_case`, sempre confirmar com `pg_policies` ou `list_tables` depois.
- Sempre confirmar e2e via SELECT direto no Supabase MCP antes de declarar feature pronta — não confiar só em logs de stdout.
