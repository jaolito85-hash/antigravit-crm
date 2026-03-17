# Regras de Revisão de Produção — Node Data

> Este arquivo deve ser referenciado no `CLAUDE.md` da raiz do projeto.
> O Claude Code vai usar essas regras para analisar o código antes de cada deploy.

---

## Contexto do Projeto

O Node Data é uma plataforma SaaS que coleta feedback de cidadãos e clientes via WhatsApp, com análise de sentimento por IA e dashboards em tempo real. O stack principal é:

- **Backend:** Flask (Python)
- **Banco de dados:** Supabase (PostgreSQL)
- **WhatsApp:** Evolution API
- **IA:** OpenAI API (análise de sentimento)
- **Webhooks:** Rotas Flask recebendo callbacks da Evolution API e outros serviços
- **Deploy:** Coolify + Docker no Hostinger VPS
- **Frontend:** HTML/JS ou frameworks conforme vertical

O sistema lida com **dados sensíveis de cidadãos (LGPD)** e roda em produção para prefeituras, escolas, academias e outros clientes.

---

## 1. Tratamento de Erros

Ao analisar o código, verifique:

- [ ] **Toda chamada a API externa** (Supabase, Evolution API, OpenAI, qualquer `requests.post/get`) **deve estar dentro de `try/except`**
- [ ] Cada `except` deve ter uma **mensagem de erro específica** (nunca genérica como "Erro")
- [ ] Todas as requisições HTTP devem ter **timeout configurado** (recomendado: 10-15 segundos)
  ```python
  # ❌ ERRADO - sem timeout
  response = requests.post(url, json=data)
  
  # ✅ CERTO - com timeout
  response = requests.post(url, json=data, timeout=15)
  ```
- [ ] Deve existir um **fallback** quando serviços externos falham (ex: salvar feedback mesmo se a análise de sentimento falhar)
- [ ] Nunca usar `except Exception` genérico sem pelo menos logar o erro com detalhes

### Padrão recomendado:
```python
try:
    response = requests.post(EVOLUTION_API_URL, json=payload, timeout=15)
    response.raise_for_status()
except requests.exceptions.Timeout:
    logger.error(f"Timeout ao enviar WhatsApp para {telefone_mascarado}")
    # fallback: salvar na fila para reenvio
except requests.exceptions.RequestException as e:
    logger.error(f"Erro Evolution API: {str(e)} | telefone: {telefone_mascarado}")
    # fallback: salvar na fila para reenvio
```

---

## 2. Validação de Dados de Entrada

- [ ] **Todos os campos obrigatórios** são verificados antes de qualquer processamento
- [ ] **Números de telefone** são validados (formato brasileiro, 10-11 dígitos após DDD)
- [ ] **Textos de entrada** são sanitizados contra SQL injection e XSS
- [ ] **Campos de texto têm limite de tamanho** (ex: feedback máximo de 5000 caracteres)
- [ ] **Tipos de dados** são verificados (número é número, texto é texto)
- [ ] Inputs vindos de webhooks são **validados da mesma forma** que inputs de formulário

### Padrão recomendado:
```python
def validate_feedback(data):
    errors = []
    
    if not data.get('telefone'):
        errors.append("Telefone é obrigatório")
    elif not re.match(r'^\d{10,13}$', data['telefone']):
        errors.append("Formato de telefone inválido")
    
    if not data.get('feedback'):
        errors.append("Feedback é obrigatório")
    elif len(data['feedback']) > 5000:
        errors.append("Feedback muito longo (máx 5000 caracteres)")
    
    if errors:
        return False, errors
    return True, []
```

---

## 3. Segurança e LGPD

- [ ] **Nenhuma senha, token ou chave de API** está hardcoded no código (deve estar em `.env` ou variáveis de ambiente)
- [ ] O arquivo `.env` está listado no `.gitignore`
- [ ] **RLS (Row Level Security)** do Supabase está ativo em tabelas que contêm dados de clientes
- [ ] **Endpoints da API exigem autenticação** (token, API key, ou session)
- [ ] **Dados pessoais** (CPF, telefone completo, nome) **nunca aparecem em logs**
- [ ] Existe separação de dados entre clientes (multi-tenancy) — Prefeitura A não vê dados da Prefeitura B
- [ ] Headers de segurança estão configurados (CORS restrito, não wildcard em produção)

### Verificação rápida:
```bash
# Procurar por chaves hardcoded no código
grep -rn "sk-" --include="*.py" .          # Chaves OpenAI
grep -rn "Bearer " --include="*.py" .       # Tokens hardcoded
grep -rn "password" --include="*.py" .      # Senhas
grep -rn "supabase_key" --include="*.py" .  # Chaves Supabase
```

---

## 4. Logs e Monitoramento

- [ ] **Pontos críticos** têm logs: recebimento de webhook, envio de WhatsApp, consulta ao banco, chamada à OpenAI
- [ ] Logs incluem **data/hora** e **contexto** suficiente para debug
- [ ] Logs **NÃO expõem dados sensíveis completos** (mascarar telefones, CPFs)
- [ ] Existe **nível de log** configurado (DEBUG em dev, INFO/WARNING em produção)
- [ ] Erros críticos são logados como `logger.error()` ou `logger.critical()`

### Padrão recomendado:
```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def mascarar_telefone(tel):
    """Mostra só os últimos 4 dígitos"""
    if len(tel) > 4:
        return '***' + tel[-4:]
    return '****'
```

---

## 5. Banco de Dados (Supabase)

- [ ] **Queries que retornam muitos registros** usam paginação (`limit`/`offset` ou cursor)
- [ ] **Índices existem** nas colunas usadas em WHERE e ORDER BY frequentes
- [ ] **Não existem queries dentro de loops** (N+1 problem)
- [ ] Conexões com o banco são **gerenciadas corretamente** (não abrem sem fechar)
- [ ] **Inserções em massa** usam batch/bulk insert, não inserção um a um

### Problema N+1 (muito comum):
```python
# ❌ ERRADO - 1 query para feedbacks + 1 query POR feedback para buscar prefeitura
feedbacks = supabase.table('feedbacks').select('*').execute()
for f in feedbacks.data:
    prefeitura = supabase.table('prefeituras').select('*').eq('id', f['prefeitura_id']).execute()

# ✅ CERTO - 1 query só, com join
feedbacks = supabase.table('feedbacks').select('*, prefeituras(nome)').execute()
```

---

## 6. Deploy e Infraestrutura

- [ ] Deploy é feito via **Coolify/GitHub** (nunca manual por FTP/SSH direto)
- [ ] **Variáveis de ambiente** do `.env` local existem também no Coolify
- [ ] Container tem **restart policy** configurado (restart: always)
- [ ] Existe rota `/health` que retorna status 200
- [ ] **Dockerfile** está otimizado (multi-stage build, .dockerignore configurado)
- [ ] É possível fazer **rollback** para versão anterior rapidamente

### Rota de health check:
```python
@app.route('/health')
def health():
    return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat()}), 200
```

---

## 7. Testes Manuais Obrigatórios (Antes de Deploy)

- [ ] Fluxo completo: enviar feedback via WhatsApp → aparece no dashboard
- [ ] Enviar dados inválidos (campo vazio, texto gigante, emojis, caracteres especiais)
- [ ] Simular serviço externo fora do ar (desconectar WiFi e testar)
- [ ] Testar dashboard em Chrome, Safari e celular
- [ ] Testar com mais de um cliente/prefeitura simultâneo (verificar isolamento de dados)

---

## 8. Webhooks (Rotas Flask que Recebem Dados Externos)

- [ ] Toda rota de webhook **valida a origem da requisição** (secret/token no header ou query param)
  ```python
  # ❌ ERRADO - aceita qualquer requisição
  @app.route('/webhook/evolution', methods=['POST'])
  def webhook():
      data = request.json
      processar(data)

  # ✅ CERTO - verifica se quem mandou é confiável
  @app.route('/webhook/evolution', methods=['POST'])
  def webhook():
      token = request.headers.get('Authorization')
      if token != os.getenv('WEBHOOK_SECRET'):
          logger.warning(f"Webhook rejeitado - token inválido: {request.remote_addr}")
          return jsonify({"error": "Não autorizado"}), 401
      data = request.json
      processar(data)
  ```
- [ ] O **payload do webhook é validado** antes de processar (campos obrigatórios, tipos corretos)
- [ ] Webhooks retornam **200 rapidamente** e processam dados em background quando possível (evita timeout do serviço que chamou)
  ```python
  # 💡 Dica: se o processamento é pesado (ex: chamar OpenAI pra análise de sentimento),
  # responda 200 primeiro e processe depois com threading ou fila
  import threading

  @app.route('/webhook/feedback', methods=['POST'])
  def webhook_feedback():
      data = request.json
      # Valida rápido
      if not data.get('message'):
          return jsonify({"error": "Mensagem vazia"}), 400
      # Salva o básico no banco imediatamente
      salvar_feedback_bruto(data)
      # Processa análise de sentimento em background
      threading.Thread(target=analisar_sentimento, args=(data,)).start()
      return jsonify({"status": "recebido"}), 200
  ```
- [ ] **Webhooks idempotentes** — se o mesmo evento chegar duas vezes, não duplica dados
  ```python
  # 💡 Use um ID único do evento pra evitar duplicatas
  event_id = data.get('event_id')
  if event_id and ja_processado(event_id):
      return jsonify({"status": "já processado"}), 200
  ```
- [ ] Falhas em webhooks críticos **enviam notificação** (email ou WhatsApp pro admin)

---

## Comandos de Análise

Quando solicitado a analisar o código, execute estas verificações:

### Análise Completa
```
Analise todo o projeto usando as regras do arquivo PRODUCTION_CHECKLIST.md. 
Para cada regra, indique: ✅ OK, ⚠️ Atenção, ou ❌ Problema.
Mostre o arquivo e linha específica de cada problema encontrado.
```

### Análise Rápida (pré-deploy)
```
Faça uma análise rápida focando em: 
1. Chamadas HTTP sem try/except ou sem timeout
2. Chaves/tokens hardcoded
3. Inputs não validados
4. Logs faltando nos pontos críticos
```

### Análise de Segurança
```
Analise apenas os pontos de segurança e LGPD do PRODUCTION_CHECKLIST.md.
Foque em: dados expostos, falta de autenticação, RLS desativado, e chaves no código.
```

---

## Prioridade de Correção

Quando encontrar problemas, classifique por prioridade:

| Prioridade | Tipo | Exemplo |
|-----------|------|---------|
| 🔴 Crítico | Segurança / Perda de dados | Chave de API no código, sem RLS, sem auth |
| 🟠 Alto | App pode quebrar | Sem try/except em chamada externa, sem timeout |
| 🟡 Médio | Performance / UX | Sem paginação, query N+1, sem logs |
| 🟢 Baixo | Boas práticas | Sem health check, sem .dockerignore |
