"""
Agente de IA de DEMONSTRAÇÃO — responde (e age) sobre o CRM pelo WhatsApp.

Objetivo: mostrar o poder de um agente que "conhece" o CRM inteiro. O sócio
pergunta qualquer coisa ("quanto faturei esse mês?", "quais meus maiores
clientes?", "o que tá atrasado?", "cria uma tarefa pra ligar pro cliente X")
e o agente consulta/atualiza o Supabase e responde em linguagem natural.

Arquitetura: isolado do agente do Telegram (produção). Reusa o cliente OpenAI e
o Supabase do server.py, recebidos no construtor (sem import circular). Loop de
tool-use próprio: LEITURA ampla (agrega em Python — volume pequeno) + ESCRITA
auditada. Ferramentas de escrita marcam o id com o sentinela de demo pra a
limpeza continuar cirúrgica.
"""
import json
import uuid
from datetime import datetime, timedelta, timezone

BR_TZ = timezone(timedelta(hours=-3))

# Prefixo sentinela: TUDO que o agente cria na demo nasce com este prefixo de id,
# então a limpeza (DELETE ... WHERE id LIKE 'd3d3d3d3-%') também apaga o que o
# agente gerou ao vivo. Nada de real é tocado.
_SENTINELA = "d3d3d3d3-0b00-4000-8000-"


def _novo_id() -> str:
    """UUID válido com o prefixo sentinela de demo (12 hex aleatórios no fim)."""
    return _SENTINELA + uuid.uuid4().hex[:12]


def _hoje():
    return datetime.now(BR_TZ)


def _num(v) -> float:
    try:
        return float(v or 0)
    except (TypeError, ValueError):
        return 0.0


def _reais(v) -> str:
    """Formata em Real brasileiro: 21700 -> 'R$ 21.700,00'."""
    s = f"{_num(v):,.2f}"
    return "R$ " + s.replace(",", "X").replace(".", ",").replace("X", ".")


# ============================================================
# TOOLS (function calling)
# ============================================================
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "metricas_negocio",
            "description": "Panorama financeiro e comercial da empresa AGORA: faturamento do mês e do ano, receita/despesa/lucro do mês, MRR (receita recorrente), nº de leads por etapa do funil, valor em negociação, contratos ativos, novos leads no mês, tarefas pendentes/atrasadas e top 5 clientes. USE isto para qualquer pergunta de 'quanto', 'total', 'faturamento', 'lucro', 'pipeline', 'como estamos'.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "buscar_cliente",
            "description": "Busca leads/clientes por nome, cidade ou vertical e retorna os detalhes (etapa, valores, responsável, contato principal, contrato e últimas interações). Use para 'me fala do cliente X', 'quais clientes em Maringá', 'clientes da vertical governo'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "termo": {"type": "string", "description": "Nome, cidade ou vertical a procurar. Vazio = lista os mais recentes."}
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "listar_leads",
            "description": "Lista leads filtrando por etapa (status) e/ou responsável. Use para 'quais leads em negociação', 'o que o Eduardo está tocando', 'leads fechados'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "status": {"type": ["string", "null"], "description": "Etapa: Novo, Qualificado, Em Prospecção, Em Negociação, Proposta, Fechado, Perdido, Pausado. null = todos."},
                    "responsavel": {"type": ["string", "null"], "description": "Nome do responsável (ex: 'Eduardo', 'João'). null = todos."},
                    "limite": {"type": ["integer", "null"], "description": "Máx. de itens (default 15)."},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "listar_tarefas",
            "description": "Lista tarefas/follow-ups. Use para 'o que tá atrasado', 'minhas tarefas de hoje', 'o que preciso fazer essa semana'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "filtro": {"type": "string", "enum": ["atrasadas", "hoje", "abertas", "todas"], "description": "atrasadas = venceram e não concluídas; hoje = vencem hoje; abertas = pendentes; todas."},
                    "responsavel": {"type": ["string", "null"], "description": "Filtra por responsável. null = todos."},
                },
                "required": ["filtro"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "saldo_contas",
            "description": "Saldo atual de cada CONTA BANCÁRIA (ex: Itaú, ASAAS): saldo inicial + receitas recebidas − despesas pagas daquela conta. Use para 'qual o saldo do Itaú', 'quanto tem no banco', 'saldo das contas'. É sobre CONTA BANCÁRIA, não sobre faturamento.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "consultar_contratos",
            "description": "Lista e conta CONTRATOS por status: 'ativo' (vigente), 'encerrado' (terminado/finalizado) ou 'negociacao'. Use para 'contratos encerrados', 'quantos contratos ativos', 'contratos em negociação'. ATENÇÃO: 'contrato encerrado' NÃO é a mesma coisa que lead na etapa 'Fechado' do funil — não responda sobre contratos usando contagem de leads.",
            "parameters": {
                "type": "object",
                "properties": {
                    "status": {"type": ["string", "null"], "enum": ["ativo", "encerrado", "negociacao", None], "description": "Filtra por status do contrato. null = todos."}
                },
            },
        },
    },
    # ===== ESCRITA (ações reais no CRM, auditadas) =====
    {
        "type": "function",
        "function": {
            "name": "criar_lead",
            "description": "Cria um novo lead/cliente no CRM. Use quando pedirem 'cadastra a empresa X', 'adiciona a prefeitura de Y'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "nome": {"type": "string"},
                    "cidade": {"type": ["string", "null"]},
                    "estado": {"type": ["string", "null"], "description": "Sigla UF (default PR)."},
                    "tipo": {"type": ["string", "null"], "enum": ["empresa", "governo", "politico", None]},
                    "valor_mensal": {"type": ["number", "null"], "description": "Mensalidade estimada, se citada."},
                    "notas": {"type": ["string", "null"]},
                },
                "required": ["nome"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "criar_tarefa",
            "description": "Cria uma tarefa/follow-up. Use para 'lembra de ligar pro cliente X amanhã', 'agenda uma demo pra sexta'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "titulo": {"type": "string"},
                    "data_vencimento": {"type": "string", "description": "Data ISO YYYY-MM-DD. Calcule a partir de HOJE para termos relativos (amanhã, sexta, semana que vem)."},
                    "responsavel": {"type": ["string", "null"], "description": "Default: quem mandou a mensagem."},
                    "prioridade": {"type": ["string", "null"], "enum": ["alta", "media", "baixa", None]},
                    "tipo": {"type": ["string", "null"], "enum": ["ligacao", "email", "reuniao", "visita", "demo", "proposta", "outro", None]},
                    "cliente": {"type": ["string", "null"], "description": "Nome do cliente/lead a vincular, se citado."},
                },
                "required": ["titulo", "data_vencimento"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "mudar_etapa_lead",
            "description": "Move um lead para outra etapa do funil. Use para 'marca a Prefeitura de X como fechado', 'joga o lead Y pra negociação'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cliente": {"type": "string", "description": "Nome do lead/cliente."},
                    "status": {"type": "string", "enum": ["Novo", "Qualificado", "Em Prospecção", "Em Negociação", "Proposta", "Fechado", "Perdido", "Pausado"]},
                },
                "required": ["cliente", "status"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "registrar_receita",
            "description": "Lança uma receita/entrada no financeiro. Use para 'registra que recebi R$ X do cliente Y'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "descricao": {"type": "string"},
                    "valor": {"type": "number"},
                    "cliente": {"type": ["string", "null"], "description": "Nome do cliente/lead, se citado."},
                },
                "required": ["descricao", "valor"],
            },
        },
    },
]


class AgenteDemoCRM:
    """Cérebro do agente de demo. Uma instância, reusada por todas as mensagens."""

    def __init__(self, supabase, openai_client, model):
        self.sb = supabase
        self.ai = openai_client
        self.model = model

    # ---------- infra ----------
    def _fetch(self, tabela, select="*", ativos=True, limite=1000):
        """Lê uma tabela (opcionalmente só não-arquivados). Volume da demo é
        pequeno, então buscar e agregar em Python é simples e robusto."""
        q = self.sb.table(tabela).select(select)
        if ativos:
            # só tabelas com soft-delete têm deleted_at; nas outras é no-op inofensivo
            q = q.is_null("deleted_at")
        try:
            return q.limit(limite).execute().data or []
        except Exception as e:
            print(f"[AGENTE-DEMO] fetch {tabela} erro: {e}")
            return []

    def _audit(self, action, tabela, target_id, details, remetente):
        try:
            self.sb.table("audit_log").insert({
                "user_id": None,
                "username": f"Agente IA (WhatsApp{': ' + remetente if remetente else ''})",
                "action": action,
                "target_table": tabela,
                "target_id": str(target_id) if target_id else None,
                "details": details,
                "ip_address": "agente-demo",
            }).execute()
        except Exception as e:
            print(f"[AGENTE-DEMO] audit erro: {e}")

    def _achar_lead(self, termo):
        """Acha 1 lead pelo nome (case-insensitive, match parcial)."""
        if not termo:
            return None
        t = termo.strip().lower()
        leads = self._fetch("leads", "id, nome, cidade, status, responsavel")
        exatos = [l for l in leads if (l.get("nome") or "").lower() == t]
        if exatos:
            return exatos[0]
        parciais = [l for l in leads if t in (l.get("nome") or "").lower()]
        return parciais[0] if parciais else None

    # ---------- ferramentas de leitura ----------
    def metricas_negocio(self, args, remetente):
        leads = self._fetch("leads", "id, nome, status, valor_mensal, valor_proposta, valor_fechado, created_at")
        contratos = self._fetch("contratos", "status, valor", ativos=False)
        receitas = self._fetch("receitas", "valor, data, status")
        despesas = self._fetch("despesas", "valor, data, status")
        tarefas = self._fetch("tarefas", "concluida, data_vencimento")

        hoje = _hoje()
        mes = hoje.strftime("%Y-%m")
        ano = hoje.strftime("%Y")
        hoje_iso = hoje.strftime("%Y-%m-%d")

        por_etapa = {}
        mrr = valor_negociacao = total_fechado = novos_mes = 0.0
        for l in leads:
            s = l.get("status") or "Novo"
            por_etapa[s] = por_etapa.get(s, 0) + 1
            mrr += _num(l.get("valor_mensal"))
            total_fechado += _num(l.get("valor_fechado"))
            if s in ("Em Negociação", "Proposta"):
                valor_negociacao += _num(l.get("valor_proposta"))
            if (l.get("created_at") or "")[:7] == mes:
                novos_mes += 1

        contratos_ativos = [c for c in contratos if c.get("status") == "ativo"]
        receita_recorrente = sum(_num(c.get("valor")) for c in contratos_ativos)

        def _soma(rows, periodo):
            return sum(
                _num(r.get("valor")) for r in rows
                if r.get("status") != "cancelado" and (r.get("data") or "").startswith(periodo)
            )

        fat_mes = _soma(receitas, mes)
        fat_ano = _soma(receitas, ano)
        desp_mes = _soma(despesas, mes)

        pend = [t for t in tarefas if not t.get("concluida")]
        atrasadas = [t for t in pend if (t.get("data_vencimento") or "") < hoje_iso]

        top = sorted(contratos_ativos, key=lambda c: _num(c.get("valor")), reverse=True)

        return {
            "faturamento_mes": _reais(fat_mes),
            "faturamento_ano": _reais(fat_ano),
            "despesas_mes": _reais(desp_mes),
            "lucro_mes": _reais(fat_mes - desp_mes),
            "mrr_receita_recorrente_ativa": _reais(receita_recorrente),
            "mrr_potencial_leads": _reais(mrr),
            "leads_total": len(leads),
            "leads_por_etapa": por_etapa,
            "valor_em_negociacao": _reais(valor_negociacao),
            "contratos_ativos": len(contratos_ativos),
            "novos_leads_no_mes": int(novos_mes),
            "total_ja_fechado": _reais(total_fechado),
            "tarefas_pendentes": len(pend),
            "tarefas_atrasadas": len(atrasadas),
            "mes_referencia": mes,
        }

    def buscar_cliente(self, args, remetente):
        termo = (args.get("termo") or "").strip().lower()
        leads = self._fetch(
            "leads",
            "id, nome, cidade, estado, status, temperatura, valor_mensal, valor_proposta, valor_fechado, responsavel, verticais(nome), created_at",
        )
        if termo:
            leads = [
                l for l in leads
                if termo in (l.get("nome") or "").lower()
                or termo in (l.get("cidade") or "").lower()
                or termo in ((l.get("verticais") or {}).get("nome") or "").lower()
            ]
        leads = leads[:8]
        contatos = self._fetch("contatos", "lead_id, nome, cargo, telefone, email", ativos=False)
        hist = self._fetch("historico_acoes", "lead_id, tipo, descricao, created_at", ativos=False)
        out = []
        for l in leads:
            lid = l.get("id")
            ct = next((c for c in contatos if c.get("lead_id") == lid), None)
            ints = sorted(
                [h for h in hist if h.get("lead_id") == lid],
                key=lambda h: h.get("created_at") or "", reverse=True,
            )[:2]
            out.append({
                "nome": l.get("nome"),
                "cidade": l.get("cidade"),
                "vertical": (l.get("verticais") or {}).get("nome"),
                "etapa": l.get("status"),
                "temperatura": l.get("temperatura"),
                "responsavel": l.get("responsavel"),
                "valor_mensal": _reais(l.get("valor_mensal")) if _num(l.get("valor_mensal")) else None,
                "valor_proposta": _reais(l.get("valor_proposta")) if _num(l.get("valor_proposta")) else None,
                "valor_fechado": _reais(l.get("valor_fechado")) if _num(l.get("valor_fechado")) else None,
                "contato": (f"{ct.get('nome')} ({ct.get('cargo')}) {ct.get('telefone') or ''}".strip() if ct else None),
                "ultimas_interacoes": [f"{h.get('tipo')}: {h.get('descricao')}" for h in ints],
            })
        return {"encontrados": len(out), "clientes": out}

    def listar_leads(self, args, remetente):
        status = args.get("status")
        resp = (args.get("responsavel") or "").strip().lower()
        limite = args.get("limite") or 15
        leads = self._fetch("leads", "nome, cidade, status, valor_mensal, valor_proposta, responsavel, verticais(nome)")
        if status:
            leads = [l for l in leads if (l.get("status") or "") == status]
        if resp:
            leads = [l for l in leads if resp in (l.get("responsavel") or "").lower()]
        leads = leads[:limite]
        return {
            "total": len(leads),
            "leads": [
                {
                    "nome": l.get("nome"), "cidade": l.get("cidade"), "etapa": l.get("status"),
                    "vertical": (l.get("verticais") or {}).get("nome"),
                    "responsavel": l.get("responsavel"),
                    "valor": _reais(l.get("valor_mensal") or l.get("valor_proposta")),
                }
                for l in leads
            ],
        }

    def listar_tarefas(self, args, remetente):
        filtro = args.get("filtro") or "abertas"
        resp = (args.get("responsavel") or "").strip().lower()
        tarefas = self._fetch("tarefas", "titulo, data_vencimento, status, concluida, prioridade, responsavel, leads(nome)")
        hoje_iso = _hoje().strftime("%Y-%m-%d")
        pend = [t for t in tarefas if not t.get("concluida")]
        if filtro == "atrasadas":
            sel = [t for t in pend if (t.get("data_vencimento") or "") < hoje_iso]
        elif filtro == "hoje":
            sel = [t for t in pend if (t.get("data_vencimento") or "") == hoje_iso]
        elif filtro == "todas":
            sel = tarefas
        else:
            sel = pend
        if resp:
            sel = [t for t in sel if resp in (t.get("responsavel") or "").lower()]
        sel = sorted(sel, key=lambda t: t.get("data_vencimento") or "")[:20]
        return {
            "total": len(sel), "filtro": filtro,
            "tarefas": [
                {
                    "titulo": t.get("titulo"), "vence": t.get("data_vencimento"),
                    "prioridade": t.get("prioridade"), "responsavel": t.get("responsavel"),
                    "cliente": (t.get("leads") or {}).get("nome"),
                    "concluida": t.get("concluida"),
                }
                for t in sel
            ],
        }

    def saldo_contas(self, args, remetente):
        contas = self._fetch("contas_bancarias", "id, nome, banco, saldo_inicial", ativos=False)
        receitas = self._fetch("receitas", "valor, status, conta_id")
        despesas = self._fetch("despesas", "valor, status, conta_id")
        out = []
        for c in contas:
            cid = c.get("id")
            entradas = sum(_num(r.get("valor")) for r in receitas
                           if r.get("conta_id") == cid and r.get("status") == "recebido")
            saidas = sum(_num(d.get("valor")) for d in despesas
                         if d.get("conta_id") == cid and d.get("status") == "pago")
            saldo = _num(c.get("saldo_inicial")) + entradas - saidas
            out.append({
                "conta": c.get("nome"), "banco": c.get("banco"),
                "saldo_atual": _reais(saldo),
                "entradas_recebidas": _reais(entradas),
                "saidas_pagas": _reais(saidas),
            })
        return {"contas": out}

    def consultar_contratos(self, args, remetente):
        status = args.get("status")
        contratos = self._fetch(
            "contratos",
            "nome, tipo, valor, status, data_inicio, data_fim, leads(nome), entidades(razao_social)",
            ativos=False,
        )
        if status:
            contratos = [c for c in contratos if (c.get("status") or "") == status]
        return {
            "total": len(contratos),
            "contratos": [
                {
                    "cliente": (c.get("leads") or {}).get("nome") or (c.get("entidades") or {}).get("razao_social"),
                    "nome": c.get("nome"), "tipo": c.get("tipo"),
                    "valor_mensal": _reais(c.get("valor")), "status": c.get("status"),
                    "inicio": c.get("data_inicio"), "fim": c.get("data_fim"),
                }
                for c in contratos
            ],
        }

    # ---------- ferramentas de escrita ----------
    def criar_lead(self, args, remetente):
        nome = (args.get("nome") or "").strip()
        if not nome:
            return {"ok": False, "erro": "nome é obrigatório"}
        rid = _novo_id()
        payload = {
            "id": rid, "nome": nome,
            "cidade": args.get("cidade"), "estado": args.get("estado") or "PR",
            "tipo": args.get("tipo"), "status": "Novo", "temperatura": "morno",
            "valor_mensal": args.get("valor_mensal"),
            "notas": args.get("notas"), "origem": "Agente IA (WhatsApp)",
            "responsavel": remetente or "Agente IA",
        }
        try:
            self.sb.table("leads").insert({k: v for k, v in payload.items() if v is not None}).execute()
            self._audit("create", "leads", rid, f"Lead criado via WhatsApp: {nome}", remetente)
            return {"ok": True, "nome": nome, "id": rid}
        except Exception as e:
            return {"ok": False, "erro": str(e)[:200]}

    def criar_tarefa(self, args, remetente):
        titulo = (args.get("titulo") or "").strip()
        venc = args.get("data_vencimento")
        if not titulo or not venc:
            return {"ok": False, "erro": "titulo e data_vencimento são obrigatórios"}
        rid = _novo_id()
        lead = self._achar_lead(args.get("cliente")) if args.get("cliente") else None
        payload = {
            "id": rid, "titulo": titulo, "data_vencimento": venc,
            "responsavel": args.get("responsavel") or remetente or "Agente IA",
            "prioridade": args.get("prioridade") or "media",
            "tipo": args.get("tipo") or "outro", "status": "aberta", "concluida": False,
            "lead_id": lead.get("id") if lead else None,
        }
        try:
            self.sb.table("tarefas").insert({k: v for k, v in payload.items() if v is not None}).execute()
            self._audit("create", "tarefas", rid, f"Tarefa criada via WhatsApp: {titulo}", remetente)
            return {"ok": True, "titulo": titulo, "vence": venc, "cliente": lead.get("nome") if lead else None}
        except Exception as e:
            return {"ok": False, "erro": str(e)[:200]}

    def mudar_etapa_lead(self, args, remetente):
        lead = self._achar_lead(args.get("cliente"))
        if not lead:
            return {"ok": False, "erro": f"não encontrei o cliente '{args.get('cliente')}'"}
        novo = args.get("status")
        try:
            self.sb.table("leads").update({
                "status": novo, "updated_at": _hoje().isoformat()
            }).eq("id", lead["id"]).execute()
            self._audit("update", "leads", lead["id"], f"Etapa -> {novo} via WhatsApp", remetente)
            return {"ok": True, "cliente": lead["nome"], "nova_etapa": novo}
        except Exception as e:
            return {"ok": False, "erro": str(e)[:200]}

    def registrar_receita(self, args, remetente):
        valor = _num(args.get("valor"))
        desc = (args.get("descricao") or "").strip()
        if not desc or valor <= 0:
            return {"ok": False, "erro": "descricao e valor (>0) são obrigatórios"}
        rid = _novo_id()
        lead = self._achar_lead(args.get("cliente")) if args.get("cliente") else None
        payload = {
            "id": rid, "descricao": desc, "valor": valor,
            "data": _hoje().strftime("%Y-%m-%d"), "status": "recebido",
            "lead_id": lead.get("id") if lead else None,
        }
        try:
            self.sb.table("receitas").insert({k: v for k, v in payload.items() if v is not None}).execute()
            self._audit("create", "receitas", rid, f"Receita {_reais(valor)} via WhatsApp: {desc}", remetente)
            return {"ok": True, "descricao": desc, "valor": _reais(valor), "cliente": lead.get("nome") if lead else None}
        except Exception as e:
            return {"ok": False, "erro": str(e)[:200]}

    # ---------- dispatcher + loop ----------
    def _dispatch(self, nome, args, remetente):
        fn = {
            "metricas_negocio": self.metricas_negocio,
            "buscar_cliente": self.buscar_cliente,
            "listar_leads": self.listar_leads,
            "listar_tarefas": self.listar_tarefas,
            "saldo_contas": self.saldo_contas,
            "consultar_contratos": self.consultar_contratos,
            "criar_lead": self.criar_lead,
            "criar_tarefa": self.criar_tarefa,
            "mudar_etapa_lead": self.mudar_etapa_lead,
            "registrar_receita": self.registrar_receita,
        }.get(nome)
        if not fn:
            return {"erro": f"ferramenta desconhecida: {nome}"}
        try:
            return fn(args, remetente)
        except Exception as e:
            print(f"[AGENTE-DEMO] tool {nome} erro: {e}")
            return {"erro": str(e)[:200]}

    def _system_prompt(self, remetente):
        hoje = _hoje()
        return (
            "Você é o **Marcos**, o assistente de IA da **Node Data**, com acesso total ao CRM da "
            "empresa. Você atende pelo WhatsApp. Se perguntarem quem é você ou seu nome, responda "
            "que é o Marcos, assistente de IA da Node Data. Seja simpático e direto.\n\n"
            "SOBRE A NODE DATA: empresa que desenvolve plataformas SaaS de feedback de cidadãos/clientes "
            "via WhatsApp, com análise de sentimento por IA e dashboards em tempo real. Vende para "
            "prefeituras (B2G), campanhas políticas e verticais privadas (supermercados, escolas, saúde, "
            "hotéis, condomínios, eventos, varejo, franquias).\n\n"
            f"DATA DE HOJE: {hoje.strftime('%d/%m/%Y (%A)')}. Fuso de Brasília. "
            "Calcule datas relativas (amanhã, sexta, semana que vem) a partir de hoje.\n"
            f"QUEM ESTÁ FALANDO: {remetente or 'um sócio'}.\n\n"
            "GLOSSÁRIO — NÃO confunda estes conceitos (cada um tem SUA ferramenta):\n"
            "- 'lead/negócio Fechado' = ETAPA DO FUNIL (venda ganha) → `metricas_negocio`/`listar_leads`.\n"
            "- 'contrato ativo / encerrado / em negociação' = STATUS DO CONTRATO → `consultar_contratos`. "
            "NUNCA responda sobre contratos usando a contagem de leads 'Fechado' — são coisas diferentes.\n"
            "- 'saldo / conta / banco (Itaú, ASAAS)' = CONTA BANCÁRIA → `saldo_contas`.\n"
            "- 'faturamento / lucro / despesa / MRR / pipeline' → `metricas_negocio`.\n\n"
            "COMO AGIR:\n"
            "- Escolha a ferramenta pelo CONCEITO EXATO que a pessoa perguntou (veja o glossário). Se pediu "
            "contrato, é contrato; se pediu saldo, é conta bancária; não troque um pelo outro.\n"
            "- Para detalhes de um cliente, use `buscar_cliente`. Para listas, `listar_leads`/`listar_tarefas`.\n"
            "- Você PODE executar ações reais (criar lead/tarefa, mudar etapa, lançar receita) quando pedirem. "
            "Após agir, confirme em uma frase o que foi feito.\n"
            "- Baseie-se SOMENTE nos dados das ferramentas. Se não houver ferramenta ou dado pro que pediram, "
            "diga que não tem — NUNCA invente números/clientes/valores e NUNCA troque um conceito por outro.\n\n"
            "ESTILO (WhatsApp): responda em português do Brasil, CURTO e direto. Use no máximo alguns "
            "tópicos com '-' e *negrito* do WhatsApp (um asterisco) para os números importantes. Valores "
            "sempre em R$. Nada de tabelas nem textão."
        )

    def responder(self, pergunta, remetente="", max_iter=6):
        """Recebe a pergunta do WhatsApp, roda o loop de tools e devolve o TEXTO
        da resposta pronto pra enviar."""
        if not self.ai:
            return "⚠️ O agente de IA está sem a OPENAI_API_KEY configurada."
        messages = [
            {"role": "system", "content": self._system_prompt(remetente)},
            {"role": "user", "content": pergunta},
        ]
        kwargs = {"model": self.model, "tools": TOOLS, "tool_choice": "auto", "timeout": 45}
        try:
            for _ in range(max_iter):
                try:
                    completion = self.ai.chat.completions.create(messages=messages, temperature=0.2, **kwargs)
                except Exception as oe:
                    # Alguns modelos reasoning rejeitam temperature — refaz sem.
                    if "temperature" in str(oe).lower():
                        completion = self.ai.chat.completions.create(messages=messages, **kwargs)
                    else:
                        raise
                resp = completion.choices[0].message
                if not resp.tool_calls:
                    return (resp.content or "Não consegui montar a resposta.").strip()
                messages.append({
                    "role": "assistant", "content": resp.content or "",
                    "tool_calls": [
                        {"id": tc.id, "type": "function",
                         "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                        for tc in resp.tool_calls
                    ],
                })
                for tc in resp.tool_calls:
                    try:
                        args = json.loads(tc.function.arguments or "{}")
                    except Exception:
                        args = {}
                    resultado = self._dispatch(tc.function.name, args, remetente)
                    messages.append({
                        "role": "tool", "tool_call_id": tc.id,
                        "content": json.dumps(resultado, default=str, ensure_ascii=False)[:4000],
                    })
            return "Consegui puxar os dados, mas me perdi montando a resposta. Pode reformular a pergunta?"
        except Exception as e:
            print(f"[AGENTE-DEMO] loop erro: {e}")
            return "Tive um erro ao consultar o CRM agora. Tenta de novo em instantes."
