import sys
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

import os
import json
import hmac
import secrets
import requests
import re
import ssl
import threading
import imaplib
import smtplib
from email.header import decode_header, make_header
from email.utils import parseaddr, formataddr, formatdate, make_msgid, parsedate_to_datetime
from email.message import EmailMessage
from email import message_from_bytes
from datetime import datetime, timedelta, timezone
from functools import wraps
from dotenv import load_dotenv

# Fuso do Brasil (UTC-3, sem horário de verão desde 2019). O servidor (Coolify/VPS)
# roda em UTC; usar isto para qualquer DATA que o usuário/agente enxerga, senão à noite
# "hoje" vira o dia seguinte e o agente marca reuniões no dia errado.
BR_TZ = timezone(timedelta(hours=-3))


def hoje_br():
    """Data de hoje (YYYY-MM-DD) no fuso do Brasil."""
    return datetime.now(BR_TZ).strftime("%Y-%m-%d")

from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash, make_response
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

# --- Flask App ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", secrets.token_hex(32))
app.config['SESSION_COOKIE_SECURE'] = os.getenv("FLASK_ENV") == "production"
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=4)
app.config['TEMPLATES_AUTO_RELOAD'] = True

# --- Rate Limiting ---
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["60 per minute"],
        storage_uri="memory://"
    )
except ImportError:
    limiter = None
    print("⚠️ flask-limiter not installed, running without rate limiting")


def login_limit(f):
    """Rate limit estrito só no POST do login (anti força-bruta). No-op se o
    limiter não estiver disponível, pra não quebrar o boot."""
    if not limiter:
        return f
    return limiter.limit("10 per minute", methods=["POST"])(f)

# --- Supabase REST Client (no SDK needed) ---
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

class SupabaseTable:
    def __init__(self, url, key, table_name):
        self.base = f"{url}/rest/v1/{table_name}"
        self.headers = {
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Prefer": "return=representation"
        }
        self._params = {}

    def select(self, columns="*"):
        self._params["select"] = columns
        self._method = "GET"
        return self

    def insert(self, data):
        self._insert_data = data
        self._method = "POST"
        return self

    def update(self, data):
        self._update_data = data
        self._method = "PATCH"
        return self

    def delete(self):
        self._method = "DELETE"
        return self

    def eq(self, col, val):
        self._params[col] = f"eq.{val}"
        return self

    def neq(self, col, val):
        self._params[col] = f"neq.{val}"
        return self

    def is_null(self, col):
        """Filtra col IS NULL (PostgREST is.null). Usado p/ excluir soft-deleted."""
        self._params[col] = "is.null"
        return self

    def not_null(self, col):
        """Filtra col IS NOT NULL (PostgREST not.is.null). Usado p/ listar a Lixeira."""
        self._params[col] = "not.is.null"
        return self

    def gt(self, col, val):
        self._params[col] = f"gt.{val}"
        return self

    def gte(self, col, val):
        self._params[col] = f"gte.{val}"
        return self

    def lt(self, col, val):
        self._params[col] = f"lt.{val}"
        return self

    def lte(self, col, val):
        self._params[col] = f"lte.{val}"
        return self

    def order(self, col, desc=False):
        direction = "desc" if desc else "asc"
        existing = self._params.get("order", "")
        if existing:
            self._params["order"] = f"{existing},{col}.{direction}"
        else:
            self._params["order"] = f"{col}.{direction}"
        return self

    def limit(self, n):
        self.headers["Range"] = f"0-{n-1}"
        return self

    def execute(self):
        method = getattr(self, "_method", "GET")
        try:
            if method == "GET":
                r = requests.get(self.base, headers=self.headers, params=self._params, timeout=15)
            elif method == "POST":
                r = requests.post(self.base, headers=self.headers, params=self._params, json=self._insert_data, timeout=15)
            elif method == "PATCH":
                r = requests.patch(self.base, headers=self.headers, params=self._params, json=self._update_data, timeout=15)
            elif method == "DELETE":
                r = requests.delete(self.base, headers=self.headers, params=self._params, timeout=15)
            else:
                r = requests.get(self.base, headers=self.headers, params=self._params, timeout=15)
            
            if r.status_code >= 400:
                print(f"Supabase error {r.status_code}: {r.text[:200]}")
                return type('Result', (), {'data': []})()
            
            data = r.json() if r.text else []
            return type('Result', (), {'data': data if isinstance(data, list) else [data] if data else []})()
        except Exception as e:
            print(f"Supabase request error: {e}")
            return type('Result', (), {'data': []})()

class SupabaseREST:
    def __init__(self, url, key):
        self.url = url
        self.key = key
        self.connected = bool(url and key)

    def table(self, name):
        return SupabaseTable(self.url, self.key, name)

    def __bool__(self):
        return self.connected

if SUPABASE_URL and SUPABASE_KEY:
    supabase = SupabaseREST(SUPABASE_URL, SUPABASE_KEY)
    print("✅ Supabase connected (REST)")
else:
    supabase = None
    print("⚠️ Supabase not configured")


# ============================================================
# SECURITY: Decorators
# ============================================================

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login_page"))
        # Check session timeout
        last_activity = session.get("last_activity")
        if last_activity:
            last_dt = datetime.fromisoformat(last_activity)
            if datetime.now() - last_dt > timedelta(hours=4):
                session.clear()
                return redirect(url_for("login_page"))
        session["last_activity"] = datetime.now().isoformat()
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login_page"))
        if session.get("role") != "admin":
            return jsonify({"error": "Acesso restrito a administradores"}), 403
        return f(*args, **kwargs)
    return decorated


def role_can_write(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") == "viewer":
            return jsonify({"error": "Você não tem permissão para editar"}), 403
        return f(*args, **kwargs)
    return decorated


# ============================================================
# SECURITY: Headers
# ============================================================

# Origem do Supabase liberada no CSP p/ imagens/links de anexos (URL assinada).
_SUPABASE_ORIGIN = SUPABASE_URL if SUPABASE_URL.startswith("http") else ""
_CSP = (
    "default-src 'self'; "
    # JS e CSS são inline (onclick, <style>, template literals) — 'unsafe-inline' é obrigatório aqui.
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
    "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net data:; "
    f"img-src 'self' data: {_SUPABASE_ORIGIN}; "
    f"connect-src 'self' {_SUPABASE_ORIGIN}; "
    "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
).strip()


@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    # X-XSS-Protection é obsoleto e pode introduzir bugs; recomendação atual é 0 + CSP.
    response.headers['X-XSS-Protection'] = '0'
    response.headers['Content-Security-Policy'] = _CSP
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if os.getenv("FLASK_ENV") == "production":
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # Garante o cookie CSRF (double-submit) — legível pelo JS, comparado no header.
    if not request.cookies.get("csrf_token"):
        response.set_cookie(
            "csrf_token",
            secrets.token_urlsafe(32),
            secure=(os.getenv("FLASK_ENV") == "production"),
            httponly=False,   # precisa ser lido pelo JS p/ reenviar no header
            samesite="Lax",
            max_age=60 * 60 * 24 * 7,
        )
    return response


@app.before_request
def csrf_protect():
    """CSRF double-submit: escrita em /api/* exige header X-CSRF-Token igual ao
    cookie csrf_token. Webhooks (auth própria por secret) e login (form) ficam de fora."""
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    if not request.path.startswith("/api/"):
        return
    cookie = request.cookies.get("csrf_token", "")
    header = request.headers.get("X-CSRF-Token", "")
    if not cookie or not header or not hmac.compare_digest(cookie, header):
        return jsonify({"error": "Token CSRF inválido — recarregue a página"}), 403


def erro_senha_fraca(senha):
    """Retorna mensagem de erro se a senha não atende à política, senão None.
    Política: mínimo 8 caracteres, com pelo menos uma letra e um número."""
    if not senha or len(senha) < 8:
        return "A senha deve ter pelo menos 8 caracteres"
    if not re.search(r"[A-Za-z]", senha) or not re.search(r"\d", senha):
        return "A senha deve conter letras e números"
    return None


# ============================================================
# AUDIT LOG
# ============================================================

def audit(action, target_table=None, target_id=None, details=None):
    if not supabase:
        return
    try:
        supabase.table("audit_log").insert({
            "user_id": session.get("user_id"),
            "username": session.get("display_name", "system"),
            "action": action,
            "target_table": target_table,
            "target_id": str(target_id) if target_id else None,
            "details": details,
            "ip_address": request.remote_addr
        }).execute()
    except Exception as e:
        print(f"Audit log error: {e}")


def _soft_delete(table, row_id):
    """Arquiva o registro (deleted_at/deleted_by) em vez de apagar. Reversível
    via Lixeira. Tabelas suportadas: leads, tarefas, documentos, despesas, receitas."""
    return supabase.table(table).update({
        "deleted_at": datetime.now(BR_TZ).isoformat(),
        "deleted_by": session.get("display_name", "")
    }).eq("id", row_id).execute()


# ============================================================
# AUTH ROUTES
# ============================================================

@app.route("/login", methods=["GET", "POST"])
@login_limit
def login_page():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            error = "Preencha todos os campos."
            return render_template("login.html", error=error)

        if not supabase:
            error = "Sistema indisponível. Tente novamente."
            return render_template("login.html", error=error)

        # Mensagem única pra não revelar se o usuário existe (anti-enumeração).
        generic_err = "Usuário ou senha inválidos."
        try:
            result = supabase.table("crm_users").select("*").eq("username", username).eq("active", True).execute()
            if result.data and len(result.data) == 1:
                user = result.data[0]
                if check_password_hash(user["password_hash"], password):
                    # Rotação de sessão: descarta qualquer sessão anterior antes de autenticar.
                    session.clear()
                    session.permanent = True
                    session["user_id"] = user["id"]
                    session["username"] = user["username"]
                    session["display_name"] = user["display_name"]
                    session["role"] = user["role"]
                    session["last_activity"] = datetime.now().isoformat()

                    # Update last login
                    supabase.table("crm_users").update({
                        "last_login_at": datetime.now().isoformat()
                    }).eq("id", user["id"]).execute()

                    audit("login", details=f"Login bem-sucedido: {username}")
                    return redirect(url_for("index"))
                else:
                    error = generic_err
                    audit("login", details=f"Senha incorreta para: {username}")
            else:
                error = generic_err
                audit("login", details=f"Tentativa com usuário inexistente/inativo: {username}")
        except Exception as e:
            print(f"Login error: {e}")
            error = "Erro ao conectar. Tente novamente."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    audit("logout")
    session.clear()
    return redirect(url_for("login_page"))


# ============================================================
# MAIN ROUTES
# ============================================================

@app.route("/")
@login_required
def index():
    return render_template("crm.html",
        user=session.get("display_name"),
        role=session.get("role")
    )


# ============================================================
# API: DASHBOARD STATS
# ============================================================

@app.route("/api/stats")
@login_required
def api_stats():
    if not supabase:
        return jsonify({"error": "DB offline"}), 503

    try:
        # Leads count by status
        leads = supabase.table("leads").select("id, status, valor_mensal, valor_setup, valor_fechado, created_at, vertical_id").is_null("deleted_at").execute()
        all_leads = leads.data or []

        total = len(all_leads)
        by_status = {}
        mrr = 0
        total_fechado = 0
        new_this_month = 0
        now = datetime.now()

        for l in all_leads:
            s = l.get("status", "Novo")
            by_status[s] = by_status.get(s, 0) + 1
            if l.get("valor_mensal"):
                mrr += float(l["valor_mensal"])
            if l.get("valor_fechado"):
                total_fechado += float(l["valor_fechado"])
            created = l.get("created_at", "")
            if created and created[:7] == now.strftime("%Y-%m"):
                new_this_month += 1

        # Tarefas pendentes
        tarefas = supabase.table("tarefas").select("id, concluida, data_vencimento").is_null("deleted_at").eq("concluida", False).execute()
        pending_tasks = len(tarefas.data or [])
        overdue = 0
        for t in (tarefas.data or []):
            if t.get("data_vencimento") and t["data_vencimento"] < now.strftime("%Y-%m-%d"):
                overdue += 1

        # Contratos ativos
        contratos = supabase.table("contratos").select("id, status, valor").execute()
        contratos_ativos = sum(1 for c in (contratos.data or []) if c.get("status") == "ativo")
        receita_contratos = sum(float(c.get("valor", 0)) for c in (contratos.data or []) if c.get("status") == "ativo")

        # Resultado financeiro do mês corrente (receitas recebidas − despesas pagas)
        mes_atual = now.strftime("%Y-%m")
        receitas = supabase.table("receitas").select("valor, data, status").is_null("deleted_at").execute()
        receitas_mes = sum(
            float(r.get("valor", 0)) for r in (receitas.data or [])
            if r.get("status") != "cancelado" and (r.get("data") or "")[:7] == mes_atual
        )
        despesas = supabase.table("despesas").select("valor, data, status").is_null("deleted_at").execute()
        despesas_mes = sum(
            float(d.get("valor", 0)) for d in (despesas.data or [])
            if d.get("status") != "cancelado" and (d.get("data") or "")[:7] == mes_atual
        )
        lucro_mes = receitas_mes - despesas_mes

        return jsonify({
            "total_leads": total,
            "leads_by_status": by_status,
            "mrr": mrr,
            "total_fechado": total_fechado,
            "new_this_month": new_this_month,
            "pending_tasks": pending_tasks,
            "overdue_tasks": overdue,
            "contratos_ativos": contratos_ativos,
            "receita_contratos": receita_contratos,
            "receitas_mes": receitas_mes,
            "despesas_mes": despesas_mes,
            "lucro_mes": lucro_mes
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# API: LEADS (CRUD)
# ============================================================

@app.route("/api/leads")
@login_required
def api_leads():
    if not supabase:
        return jsonify([])
    try:
        result = supabase.table("leads").select(
            "*, verticais(codigo, nome, icone)"
        ).is_null("deleted_at").order("created_at", desc=True).execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/leads", methods=["POST"])
@login_required
@role_can_write
def api_create_lead():
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    data = request.json
    try:
        result = supabase.table("leads").insert(data).execute()
        audit("create", "leads", result.data[0]["id"] if result.data else None, f"Novo lead: {data.get('nome')}")
        return jsonify(result.data[0] if result.data else {}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/leads/<lead_id>", methods=["PATCH"])
@login_required
@role_can_write
def api_update_lead(lead_id):
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    data = request.json
    data["updated_at"] = datetime.now().isoformat()
    try:
        result = supabase.table("leads").update(data).eq("id", lead_id).execute()
        audit("update", "leads", lead_id, f"Atualizado: {json.dumps(list(data.keys()))}")
        return jsonify(result.data[0] if result.data else {})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/leads/<lead_id>", methods=["DELETE"])
@login_required
@admin_required
def api_delete_lead(lead_id):
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    try:
        # Get lead name for audit
        lead = supabase.table("leads").select("nome").eq("id", lead_id).execute()
        nome = lead.data[0]["nome"] if lead.data else "unknown"
        _soft_delete("leads", lead_id)
        audit("soft_delete", "leads", lead_id, f"Arquivado p/ Lixeira: {nome}")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# API: VERTICAIS
# ============================================================

@app.route("/api/verticais")
@login_required
def api_verticais():
    if not supabase:
        return jsonify([])
    try:
        result = supabase.table("verticais").select("*").eq("ativo", True).order("ordem").execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# API: TAREFAS (CRUD)
# ============================================================

@app.route("/api/tarefas")
@login_required
def api_tarefas():
    if not supabase:
        return jsonify([])
    try:
        result = supabase.table("tarefas").select(
            "*, leads(nome, status, cidade, estado)"
        ).is_null("deleted_at").order("data_vencimento").execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tarefas", methods=["POST"])
@login_required
@role_can_write
def api_create_tarefa():
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    data = request.json
    try:
        result = supabase.table("tarefas").insert(data).execute()
        audit("create", "tarefas", result.data[0]["id"] if result.data else None, f"Nova tarefa: {data.get('titulo')}")
        return jsonify(result.data[0] if result.data else {}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tarefas/<tarefa_id>", methods=["PATCH"])
@login_required
@role_can_write
def api_update_tarefa(tarefa_id):
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    data = request.json
    # Sincroniza status <-> concluida (status e a fonte da verdade; concluida fica
    # por compatibilidade com dashboard e Kanban antigo).
    if "status" in data:
        if data["status"] == "concluida":
            data["concluida"] = True
            data["concluida_em"] = datetime.now().isoformat()
        else:
            data["concluida"] = False
            data["concluida_em"] = None
    elif data.get("concluida"):
        data["concluida_em"] = datetime.now().isoformat()
        data["status"] = "concluida"
    elif "concluida" in data and not data["concluida"]:
        data["concluida_em"] = None
        data["status"] = "aberta"
    try:
        result = supabase.table("tarefas").update(data).eq("id", tarefa_id).execute()
        audit("update", "tarefas", tarefa_id, f"Atualizada: {json.dumps(list(data.keys()))}")
        return jsonify(result.data[0] if result.data else {})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tarefas/<tarefa_id>", methods=["DELETE"])
@login_required
@role_can_write
def api_delete_tarefa(tarefa_id):
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    try:
        _soft_delete("tarefas", tarefa_id)
        audit("soft_delete", "tarefas", tarefa_id)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# API: CONTRATOS
# ============================================================

@app.route("/api/contratos")
@login_required
def api_contratos():
    if not supabase:
        return jsonify([])
    try:
        result = supabase.table("contratos").select(
            "*, leads(nome), entidades(razao_social)"
        ).order("created_at", desc=True).execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/contratos", methods=["POST"])
@login_required
@role_can_write
def api_create_contrato():
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    data = request.json
    try:
        result = supabase.table("contratos").insert(data).execute()
        audit("create", "contratos", result.data[0]["id"] if result.data else None, f"Novo contrato: {data.get('nome')}")
        return jsonify(result.data[0] if result.data else {}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/contratos/<contrato_id>", methods=["PATCH"])
@login_required
@role_can_write
def api_update_contrato(contrato_id):
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    data = request.json
    data["updated_at"] = datetime.now().isoformat()
    try:
        result = supabase.table("contratos").update(data).eq("id", contrato_id).execute()
        audit("update", "contratos", contrato_id)
        return jsonify(result.data[0] if result.data else {})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# API: DOCUMENTOS
# ============================================================

@app.route("/api/documentos")
@login_required
def api_documentos():
    if not supabase:
        return jsonify([])
    try:
        result = supabase.table("documentos").select(
            "*, leads(nome), contratos(nome), entidades(razao_social)"
        ).is_null("deleted_at").order("created_at", desc=True).execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/documentos", methods=["POST"])
@login_required
@role_can_write
def api_create_documento():
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    data = request.json
    try:
        result = supabase.table("documentos").insert(data).execute()
        audit("create", "documentos", result.data[0]["id"] if result.data else None, f"Novo doc: {data.get('titulo')}")
        return jsonify(result.data[0] if result.data else {}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Buckets de storage permitidos (privados — acesso só via /api/file com URL assinada)
ALLOWED_BUCKETS = {"documentos", "comprovantes"}


@app.route("/api/upload", methods=["POST"])
@login_required
@role_can_write
def api_upload_file():
    """Upload para Supabase Storage (bucket privado). Retorna o caminho interno
    e uma URL de proxy protegida (/api/file/...), nunca uma URL pública direta."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        return jsonify({"error": "Storage não configurado"}), 503

    if "file" not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Arquivo sem nome"}), 400

    bucket = (request.form.get("bucket") or "documentos").strip()
    if bucket not in ALLOWED_BUCKETS:
        return jsonify({"error": "Bucket inválido"}), 400

    # Gerar nome único (organizado por ano)
    import uuid
    ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else "bin"
    safe_name = f"{datetime.now().year}/{int(datetime.now().timestamp())}_{uuid.uuid4().hex[:8]}.{ext}"

    try:
        upload_url = f"{SUPABASE_URL}/storage/v1/object/{bucket}/{safe_name}"
        content_type = f.content_type or "application/octet-stream"
        resp = requests.post(
            upload_url,
            headers={
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}",
                "Content-Type": content_type,
            },
            data=f.read(),
            timeout=30,
        )

        if resp.status_code >= 400:
            return jsonify({"error": f"Erro no upload: {resp.text[:200]}"}), 500

        audit("upload", bucket, None, f"Upload: {f.filename} -> {safe_name}")
        # url = rota proxy protegida; path = caminho cru para salvar em colunas dedicadas
        return jsonify({
            "url": f"/api/file/{bucket}/{safe_name}",
            "path": safe_name,
            "bucket": bucket,
            "filename": safe_name,
        }), 201

    except Exception as e:
        return jsonify({"error": f"Falha no upload: {str(e)}"}), 500


@app.route("/api/file/<bucket>/<path:filename>")
@login_required
def api_file_proxy(bucket, filename):
    """Gera uma URL assinada temporária e redireciona. Só usuários logados
    no CRM acessam — os buckets são privados no Supabase."""
    if bucket not in ALLOWED_BUCKETS:
        return jsonify({"error": "Bucket inválido"}), 404
    if not SUPABASE_URL or not SUPABASE_KEY:
        return jsonify({"error": "Storage não configurado"}), 503
    try:
        sign_url = f"{SUPABASE_URL}/storage/v1/object/sign/{bucket}/{filename}"
        resp = requests.post(
            sign_url,
            headers={
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}",
                "Content-Type": "application/json",
            },
            json={"expiresIn": 3600},
            timeout=15,
        )
        if resp.status_code >= 400:
            return jsonify({"error": f"Arquivo não encontrado: {resp.text[:150]}"}), 404
        signed = resp.json().get("signedURL") or resp.json().get("signedUrl")
        if not signed:
            return jsonify({"error": "Falha ao assinar URL"}), 500
        # signedURL vem como caminho relativo a /storage/v1
        return redirect(f"{SUPABASE_URL}/storage/v1{signed}")
    except Exception as e:
        return jsonify({"error": f"Falha ao gerar link: {str(e)}"}), 500


@app.route("/api/documentos/<doc_id>", methods=["PATCH"])
@login_required
@role_can_write
def api_update_documento(doc_id):
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    data = request.json
    try:
        result = supabase.table("documentos").update(data).eq("id", doc_id).execute()
        audit("update", "documentos", doc_id, f"Editou doc: {data.get('titulo', '')}")
        return jsonify(result.data[0] if result.data else {}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/documentos/<doc_id>", methods=["DELETE"])
@login_required
@role_can_write
def api_delete_documento(doc_id):
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    try:
        _soft_delete("documentos", doc_id)
        audit("soft_delete", "documentos", doc_id)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# API: HISTÓRICO DE AÇÕES
# ============================================================

@app.route("/api/historico/<lead_id>")
@login_required
def api_historico(lead_id):
    if not supabase:
        return jsonify([])
    try:
        result = supabase.table("historico_acoes").select(
            "*, contatos(nome)"
        ).eq("lead_id", lead_id).order("created_at", desc=True).execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/historico", methods=["POST"])
@login_required
@role_can_write
def api_create_historico():
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    data = request.json
    try:
        result = supabase.table("historico_acoes").insert(data).execute()
        audit("create", "historico_acoes", result.data[0]["id"] if result.data else None)
        return jsonify(result.data[0] if result.data else {}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# API: CONTATOS
# ============================================================

@app.route("/api/contatos/<lead_id>")
@login_required
def api_contatos(lead_id):
    if not supabase:
        return jsonify([])
    try:
        result = supabase.table("contatos").select("*").eq("lead_id", lead_id).order("created_at", desc=True).execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/contatos", methods=["POST"])
@login_required
@role_can_write
def api_create_contato():
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    data = request.json
    try:
        result = supabase.table("contatos").insert(data).execute()
        audit("create", "contatos", result.data[0]["id"] if result.data else None, f"Novo contato: {data.get('nome')}")
        return jsonify(result.data[0] if result.data else {}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# API: DESPESAS
# ============================================================

@app.route("/api/despesas")
@login_required
def api_despesas():
    if not supabase:
        return jsonify([])
    try:
        result = supabase.table("despesas").select(
            "*, verticais(nome, icone, codigo), categorias_financeiras(nome, cor, icone), fornecedores(nome), contas_bancarias(nome)"
        ).is_null("deleted_at").order("data", desc=True).execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/despesas", methods=["POST"])
@login_required
@role_can_write
def api_create_despesa():
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    data = request.json
    try:
        result = supabase.table("despesas").insert(data).execute()
        audit("create", "despesas", result.data[0]["id"] if result.data else None, f"Despesa: {data.get('descricao')}")
        return jsonify(result.data[0] if result.data else {}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/despesas/<despesa_id>", methods=["PATCH"])
@login_required
@role_can_write
def api_update_despesa(despesa_id):
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    data = request.json
    try:
        result = supabase.table("despesas").update(data).eq("id", despesa_id).execute()
        audit("update", "despesas", despesa_id, f"Editou despesa: {data.get('descricao', '')}")
        return jsonify(result.data[0] if result.data else {}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/despesas/<despesa_id>", methods=["DELETE"])
@login_required
@role_can_write
def api_delete_despesa(despesa_id):
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    try:
        _soft_delete("despesas", despesa_id)
        audit("soft_delete", "despesas", despesa_id)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# API: RECEITAS
# ============================================================

@app.route("/api/receitas")
@login_required
def api_receitas():
    if not supabase:
        return jsonify([])
    try:
        result = supabase.table("receitas").select(
            "*, categorias_financeiras(nome, cor, icone), fornecedores(nome), contas_bancarias(nome), leads(nome)"
        ).is_null("deleted_at").order("data", desc=True).execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/receitas", methods=["POST"])
@login_required
@role_can_write
def api_create_receita():
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    data = request.json
    try:
        result = supabase.table("receitas").insert(data).execute()
        audit("create", "receitas", result.data[0]["id"] if result.data else None, f"Receita: {data.get('descricao')}")
        return jsonify(result.data[0] if result.data else {}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/receitas/<receita_id>", methods=["PATCH"])
@login_required
@role_can_write
def api_update_receita(receita_id):
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    data = request.json
    try:
        result = supabase.table("receitas").update(data).eq("id", receita_id).execute()
        audit("update", "receitas", receita_id, f"Editou receita: {data.get('descricao', '')}")
        return jsonify(result.data[0] if result.data else {}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/receitas/<receita_id>", methods=["DELETE"])
@login_required
@role_can_write
def api_delete_receita(receita_id):
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    try:
        _soft_delete("receitas", receita_id)
        audit("soft_delete", "receitas", receita_id)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# API: FORNECEDORES / CONTAS / CATEGORIAS (cadastros financeiros)
# ============================================================

def _crud_list(table, select="*", order_col="nome", desc=False):
    if not supabase:
        return jsonify([])
    try:
        result = supabase.table(table).select(select).order(order_col, desc=desc).execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _crud_create(table, label_field="nome"):
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    data = request.json
    try:
        result = supabase.table(table).insert(data).execute()
        audit("create", table, result.data[0]["id"] if result.data else None, f"{table}: {data.get(label_field, '')}")
        return jsonify(result.data[0] if result.data else {}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _crud_update(table, row_id):
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    data = request.json
    try:
        result = supabase.table(table).update(data).eq("id", row_id).execute()
        audit("update", table, row_id)
        return jsonify(result.data[0] if result.data else {}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _crud_delete(table, row_id):
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    try:
        supabase.table(table).delete().eq("id", row_id).execute()
        audit("delete", table, row_id)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --- Fornecedores ---
@app.route("/api/fornecedores")
@login_required
def api_fornecedores():
    return _crud_list("fornecedores")

@app.route("/api/fornecedores", methods=["POST"])
@login_required
@role_can_write
def api_create_fornecedor():
    return _crud_create("fornecedores")

@app.route("/api/fornecedores/<row_id>", methods=["PATCH"])
@login_required
@role_can_write
def api_update_fornecedor(row_id):
    return _crud_update("fornecedores", row_id)

@app.route("/api/fornecedores/<row_id>", methods=["DELETE"])
@login_required
@role_can_write
def api_delete_fornecedor(row_id):
    return _crud_delete("fornecedores", row_id)


# --- Contas bancárias ---
@app.route("/api/contas")
@login_required
def api_contas():
    return _crud_list("contas_bancarias")

@app.route("/api/contas", methods=["POST"])
@login_required
@role_can_write
def api_create_conta():
    return _crud_create("contas_bancarias")

@app.route("/api/contas/<row_id>", methods=["PATCH"])
@login_required
@role_can_write
def api_update_conta(row_id):
    return _crud_update("contas_bancarias", row_id)

@app.route("/api/contas/<row_id>", methods=["DELETE"])
@login_required
@role_can_write
def api_delete_conta(row_id):
    return _crud_delete("contas_bancarias", row_id)


# --- Categorias financeiras (plano de contas) ---
@app.route("/api/categorias-financeiras")
@login_required
def api_categorias_fin():
    return _crud_list("categorias_financeiras", order_col="tipo")

@app.route("/api/categorias-financeiras", methods=["POST"])
@login_required
@role_can_write
def api_create_categoria_fin():
    return _crud_create("categorias_financeiras")

@app.route("/api/categorias-financeiras/<row_id>", methods=["PATCH"])
@login_required
@role_can_write
def api_update_categoria_fin(row_id):
    return _crud_update("categorias_financeiras", row_id)

@app.route("/api/categorias-financeiras/<row_id>", methods=["DELETE"])
@login_required
@role_can_write
def api_delete_categoria_fin(row_id):
    return _crud_delete("categorias_financeiras", row_id)


# ============================================================
# API: EMPRÉSTIMOS (dinheiro que a empresa tomou)
# ============================================================

@app.route("/api/emprestimos")
@login_required
def api_emprestimos():
    if not supabase:
        return jsonify([])
    try:
        result = supabase.table("emprestimos").select(
            "*, fornecedores(nome), contas_bancarias(nome)"
        ).order("data_recebimento", desc=True).execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/emprestimos", methods=["POST"])
@login_required
@role_can_write
def api_create_emprestimo():
    return _crud_create("emprestimos", label_field="descricao")

@app.route("/api/emprestimos/<row_id>", methods=["PATCH"])
@login_required
@role_can_write
def api_update_emprestimo(row_id):
    return _crud_update("emprestimos", row_id)

@app.route("/api/emprestimos/<row_id>", methods=["DELETE"])
@login_required
@role_can_write
def api_delete_emprestimo(row_id):
    return _crud_delete("emprestimos", row_id)


# ============================================================
# API: METAS
# ============================================================

@app.route("/api/metas")
@login_required
def api_metas():
    if not supabase:
        return jsonify([])
    try:
        result = supabase.table("metas").select("*, verticais(nome, icone)").order("ano", desc=True).order("mes", desc=True).execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# API: DEPLOY HEALTH
# ============================================================

@app.route("/api/health-check")
@login_required
def api_health_check():
    if not supabase:
        return jsonify([])
    try:
        result = supabase.table("leads").select("id, nome, deploy_url, status, verticais(nome, icone)").is_null("deleted_at").execute()
        leads_with_deploy = [l for l in (result.data or []) if l.get("deploy_url")]
        return jsonify(leads_with_deploy)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/health-check/run", methods=["POST"])
@login_required
@role_can_write
def api_run_health_check():
    """Ping deploy URLs from leads and return status"""
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    try:
        result = supabase.table("leads").select("id, nome, deploy_url").is_null("deleted_at").execute()
        leads_with_deploy = [l for l in (result.data or []) if l.get("deploy_url")]
        results = []
        for lead in leads_with_deploy:
            url = lead["deploy_url"]
            try:
                start = datetime.now()
                resp = requests.get(url, timeout=10, allow_redirects=True)
                elapsed = int((datetime.now() - start).total_seconds() * 1000)
                status = "up" if resp.status_code < 500 else "down"
                results.append({"id": lead["id"], "nome": lead["nome"], "url": url, "status": status, "ms": elapsed, "code": resp.status_code})
            except Exception:
                results.append({"id": lead["id"], "nome": lead["nome"], "url": url, "status": "down", "ms": None, "code": None})

        audit("update", "health_check", details=f"Health check manual: {len(results)} deploys")
        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# API: CLIENT METRICS (pull from deploy APIs)
# ============================================================

@app.route("/api/client-metrics/<lead_id>")
@login_required
def api_client_metrics(lead_id):
    """Query a lead's deploy_url/api/events to get feedback metrics"""
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    try:
        result = supabase.table("leads").select("id, nome, deploy_url, verticais(nome, icone)").eq("id", lead_id).execute()
        if not result.data:
            return jsonify({"error": "Lead not found"}), 404
        lead = result.data[0]
        deploy_url = lead.get("deploy_url")
        if not deploy_url:
            return jsonify({"error": "No deploy URL configured", "lead": lead.get("nome")}), 400

        # Query the deploy's API
        api_url = deploy_url.rstrip("/") + "/api/events"
        try:
            resp = requests.get(api_url, timeout=15)
            if resp.status_code != 200:
                return jsonify({"error": f"Deploy returned {resp.status_code}", "url": api_url}), 502
            feedbacks = resp.json()
        except requests.exceptions.ConnectionError:
            return jsonify({"error": "Deploy offline", "url": api_url}), 502
        except Exception as e:
            return jsonify({"error": f"Request failed: {str(e)}", "url": api_url}), 502

        if not isinstance(feedbacks, list):
            return jsonify({"error": "Invalid response format", "url": api_url}), 502

        # Calculate metrics
        now = datetime.now()
        total = len(feedbacks)

        # Count by time period
        last_7d = 0
        last_30d = 0
        for fb in feedbacks:
            ts = fb.get("timestamp") or fb.get("created_at")
            if ts:
                try:
                    fb_date = datetime.fromisoformat(ts.replace("Z", "+00:00").replace("+00:00", ""))
                    days_ago = (now - fb_date).days
                    if days_ago <= 7:
                        last_7d += 1
                    if days_ago <= 30:
                        last_30d += 1
                except Exception:
                    pass

        # Count by urgency
        urgency_counts = {}
        for fb in feedbacks:
            urg = fb.get("urgency", "Neutro")
            urgency_counts[urg] = urgency_counts.get(urg, 0) + 1

        urgent = urgency_counts.get("Urgente", 0) + urgency_counts.get("Critico", 0) + urgency_counts.get("Crítico", 0)

        # Count by category
        category_counts = {}
        for fb in feedbacks:
            cat = fb.get("category", "Outros")
            category_counts[cat] = category_counts.get(cat, 0) + 1

        # Count by status
        status_counts = {}
        for fb in feedbacks:
            st = fb.get("status", "aberto")
            status_counts[st] = status_counts.get(st, 0) + 1

        # Recent feedbacks (last 5)
        recent = []
        for fb in feedbacks[:5]:
            recent.append({
                "message": (fb.get("message") or "")[:120],
                "category": fb.get("category"),
                "urgency": fb.get("urgency"),
                "timestamp": fb.get("timestamp") or fb.get("created_at"),
                "status": fb.get("status", "aberto")
            })

        return jsonify({
            "lead_id": lead_id,
            "lead_nome": lead.get("nome"),
            "vertical": lead.get("verticais"),
            "deploy_url": deploy_url,
            "total_feedbacks": total,
            "last_7_days": last_7d,
            "last_30_days": last_30d,
            "urgent_count": urgent,
            "urgency_breakdown": urgency_counts,
            "category_breakdown": category_counts,
            "status_breakdown": status_counts,
            "recent_feedbacks": recent,
            "checked_at": now.isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# API: AUDIT LOG (admin only)
# ============================================================

@app.route("/api/audit")
@login_required
@admin_required
def api_audit():
    if not supabase:
        return jsonify([])
    try:
        result = supabase.table("audit_log").select("*").order("created_at", desc=True).limit(200).execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# API: USER MANAGEMENT (admin only)
# ============================================================

@app.route("/api/users")
@login_required
@admin_required
def api_users():
    if not supabase:
        return jsonify([])
    try:
        result = supabase.table("crm_users").select("id, username, display_name, role, active, last_login_at, created_at").execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/equipe")
@login_required
def api_equipe():
    """Nomes da equipe ativa (display_name) — usado p/ popular dropdowns de responsável.
    Acessível a qualquer logado (nomes de exibição não são dado sensível)."""
    if not supabase:
        return jsonify([])
    try:
        r = supabase.table("crm_users").select("display_name").eq("active", True).execute()
        nomes = sorted({u.get("display_name") for u in (r.data or []) if u.get("display_name")})
        return jsonify(nomes)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users", methods=["POST"])
@login_required
@admin_required
def api_create_user():
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    data = request.json
    password = data.pop("password", None)
    erro = erro_senha_fraca(password)
    if erro:
        return jsonify({"error": erro}), 400

    data["password_hash"] = generate_password_hash(password)
    try:
        result = supabase.table("crm_users").insert(data).execute()
        audit("create", "crm_users", details=f"Novo usuário: {data.get('username')}")
        return jsonify({"ok": True, "id": result.data[0]["id"] if result.data else None}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users/<user_id>", methods=["PATCH"])
@login_required
@admin_required
def api_update_user(user_id):
    """Edita usuário (nome, cargo, ativo) e, opcionalmente, redefine a senha.
    Só admin. Protege contra auto-bloqueio e contra ficar sem nenhum admin ativo.
    Nunca aceita password_hash cru do cliente — sempre re-hasheia."""
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    data = request.json or {}

    # Whitelist de campos — impede o cliente de escrever colunas sensíveis direto.
    updates = {}
    for campo in ("display_name", "role", "active"):
        if campo in data:
            updates[campo] = data[campo]

    new_password = data.get("password")
    if new_password:
        erro = erro_senha_fraca(new_password)
        if erro:
            return jsonify({"error": erro}), 400
        updates["password_hash"] = generate_password_hash(new_password)

    if not updates:
        return jsonify({"error": "Nada para atualizar"}), 400

    # Proteção: não deixar o admin travar o próprio acesso.
    if str(user_id) == str(session.get("user_id")):
        if updates.get("active") is False:
            return jsonify({"error": "Você não pode desativar a si mesmo"}), 400
        if "role" in updates and updates["role"] != "admin":
            return jsonify({"error": "Você não pode rebaixar a si mesmo"}), 400

    # Proteção: nunca remover o único admin ativo do sistema.
    desativando = updates.get("active") is False
    rebaixando = "role" in updates and updates["role"] != "admin"
    if desativando or rebaixando:
        try:
            admins = supabase.table("crm_users").select("id").eq("role", "admin").eq("active", True).execute()
            admin_ids = {str(a["id"]) for a in (admins.data or [])}
            if str(user_id) in admin_ids and len(admin_ids) <= 1:
                return jsonify({"error": "Não é possível remover o único admin ativo"}), 400
        except Exception as e:
            print(f"update_user admin-check error: {e}")

    try:
        supabase.table("crm_users").update(updates).eq("id", user_id).execute()
        campos = [c for c in updates if c != "password_hash"]
        if "password_hash" in updates:
            campos.append("senha")
        audit("update", "crm_users", user_id, f"Editou usuário: {', '.join(campos)}")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/me/password", methods=["POST"])
@login_required
def api_change_my_password():
    """Troca a própria senha. Exige a senha atual — qualquer usuário logado
    (inclusive viewer) pode trocar a sua."""
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    data = request.json or {}
    current = data.get("current_password", "")
    nova = data.get("new_password", "")
    erro = erro_senha_fraca(nova)
    if erro:
        return jsonify({"error": erro}), 400

    uid = session.get("user_id")
    try:
        r = supabase.table("crm_users").select("password_hash").eq("id", uid).execute()
        if not r.data:
            return jsonify({"error": "Usuário não encontrado"}), 404
        if not check_password_hash(r.data[0]["password_hash"], current):
            audit("update", "crm_users", uid, "Troca de senha negada (senha atual incorreta)")
            return jsonify({"error": "Senha atual incorreta"}), 403
        supabase.table("crm_users").update({
            "password_hash": generate_password_hash(nova)
        }).eq("id", uid).execute()
        audit("update", "crm_users", uid, "Trocou a própria senha")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# SETUP: Create initial admin user if none exists
# ============================================================

def ensure_admin_exists():
    if not supabase:
        return
    try:
        users = supabase.table("crm_users").select("id").limit(1).execute()
        if not users.data:
            admin_hash = generate_password_hash("nodedata2024")
            supabase.table("crm_users").insert({
                "username": "admin",
                "password_hash": admin_hash,
                "display_name": "Administrador",
                "role": "admin",
                "active": True
            }).execute()
            print("🔐 Admin user created (username: admin / password: nodedata2024)")
            print("⚠️  CHANGE THIS PASSWORD IMMEDIATELY!")
    except Exception as e:
        print(f"Setup error: {e}")


# ============================================================
# HEALTH MONITOR CENTRAL
# ============================================================

# Config: Projetos monitorados
MONITORED_PROJECTS = [
    {
        "id": "prefeitura_ivate",
        "name": "Prefeitura Ivaté (Clara)",
        "health_url": os.getenv("HEALTH_URL_PREFEITURA", "https://prefeitura.nodedata.com.br/api/health"),
        "dashboard_url": os.getenv("DASHBOARD_URL_PREFEITURA", "https://prefeitura.nodedata.com.br"),
        "icon": "🏛️",
        "critical": True
    },
    {
        "id": "atacaforte_supermercado",
        "name": "Atacaforte (Seu Pipico)",
        "health_url": os.getenv("HEALTH_URL_ATACAFORTE", "https://atacaforte.nodedata.com.br/api/health"),
        "dashboard_url": os.getenv("DASHBOARD_URL_ATACAFORTE", "https://atacaforte.nodedata.com.br"),
        "icon": "🛒",
        "critical": True
    },
]

ALERT_PHONE = os.getenv("ALERT_WHATSAPP_PHONE", "")
CRM_EVOLUTION_URL = os.getenv("EVOLUTION_API_URL", "")
CRM_EVOLUTION_KEY = os.getenv("EVOLUTION_API_KEY", "")
CRM_EVOLUTION_INSTANCE = os.getenv("EVOLUTION_INSTANCE_NAME", "")
HEALTH_CHECK_INTERVAL = int(os.getenv("HEALTH_CHECK_INTERVAL", "300"))
_last_alert_sent = {}
ALERT_COOLDOWN_SECONDS = 900  # 15 min entre alertas iguais


def check_project_health(project):
    """Consulta a rota /api/health de um projeto e retorna o resultado."""
    url = project["health_url"]
    try:
        import time as _time
        _start = _time.time()
        resp = requests.get(url, timeout=15)
        _ms = int((_time.time() - _start) * 1000)

        if resp.status_code == 200:
            data = resp.json()
            data["response_ms"] = _ms
            data["reachable"] = True
            return data
        else:
            return {
                "project": project["id"],
                "project_name": project["name"],
                "overall": "down",
                "reachable": True,
                "response_ms": _ms,
                "services": {},
                "error": f"HTTP {resp.status_code}",
                "checked_at": datetime.utcnow().isoformat()
            }
    except requests.exceptions.ConnectionError:
        return {
            "project": project["id"],
            "project_name": project["name"],
            "overall": "down",
            "reachable": False,
            "response_ms": None,
            "services": {},
            "error": "Connection refused — servidor offline ou URL errada",
            "checked_at": datetime.utcnow().isoformat()
        }
    except requests.exceptions.Timeout:
        return {
            "project": project["id"],
            "project_name": project["name"],
            "overall": "down",
            "reachable": False,
            "response_ms": None,
            "services": {},
            "error": "Timeout — servidor não respondeu em 15s",
            "checked_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "project": project["id"],
            "project_name": project["name"],
            "overall": "down",
            "reachable": False,
            "response_ms": None,
            "services": {},
            "error": str(e)[:200],
            "checked_at": datetime.utcnow().isoformat()
        }


def check_all_projects():
    """Consulta todos os projetos monitorados."""
    results = []
    for project in MONITORED_PROJECTS:
        result = check_project_health(project)
        result["icon"] = project.get("icon", "📦")
        result["dashboard_url"] = project.get("dashboard_url", "")
        result["critical"] = project.get("critical", False)
        results.append(result)
    return results


def save_health_log(result):
    """Grava o resultado da checagem no Supabase."""
    if not supabase:
        return
    try:
        supabase.table("health_logs").insert({
            "project": result.get("project"),
            "project_name": result.get("project_name"),
            "overall": result.get("overall"),
            "services": json.dumps(result.get("services", {})),
            "alert_sent": result.get("_alert_sent", False),
            "response_ms": result.get("response_ms"),
            "checked_at": result.get("checked_at", datetime.utcnow().isoformat())
        }).execute()
    except Exception as e:
        print(f"[HEALTH-LOG] Save error: {e}")


def send_whatsapp_alert(message):
    """Envia alerta via WhatsApp usando a Evolution API do CRM."""
    if not all([CRM_EVOLUTION_URL, CRM_EVOLUTION_KEY, CRM_EVOLUTION_INSTANCE, ALERT_PHONE]):
        print(f"[HEALTH-ALERT] WhatsApp not configured. Message: {message[:100]}")
        return False

    url = f"{CRM_EVOLUTION_URL}/message/sendText/{CRM_EVOLUTION_INSTANCE}"
    headers = {"apikey": CRM_EVOLUTION_KEY, "Content-Type": "application/json"}
    payload = {"number": ALERT_PHONE, "text": message}

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=10)
        print(f"[HEALTH-ALERT] WhatsApp sent: {resp.status_code}")
        return resp.status_code in (200, 201)
    except Exception as e:
        print(f"[HEALTH-ALERT] WhatsApp error: {e}")
        return False


def should_send_alert(project_id):
    """Cooldown: não envia o mesmo alerta a cada 5 min."""
    import time as _time
    now = _time.time()
    last = _last_alert_sent.get(project_id, 0)
    if now - last < ALERT_COOLDOWN_SECONDS:
        return False
    _last_alert_sent[project_id] = now
    return True


def process_alerts(results):
    """Analisa resultados e envia alertas se necessário."""
    for result in results:
        overall = result.get("overall", "unknown")
        project_id = result.get("project", "unknown")
        project_name = result.get("project_name", project_id)
        icon = result.get("icon", "📦")

        if overall == "down" and result.get("critical", False):
            if should_send_alert(project_id):
                services = result.get("services", {})
                down_services = [
                    f"  ❌ {svc}: {info.get('detail', 'offline')}"
                    for svc, info in services.items()
                    if info.get("status") == "down"
                ]
                error_msg = result.get("error", "")

                msg_lines = [
                    f"🚨 *ALERTA: {icon} {project_name}*",
                    f"",
                    f"Status: *{overall.upper()}*",
                    f"Horário: {datetime.utcnow().strftime('%H:%M UTC')}",
                ]
                if error_msg:
                    msg_lines.append(f"Erro: {error_msg}")
                if down_services:
                    msg_lines.append(f"")
                    msg_lines.append(f"Serviços com problema:")
                    msg_lines.extend(down_services)
                msg_lines.append(f"")
                msg_lines.append(f"Verifique: {result.get('dashboard_url', 'N/A')}")

                send_whatsapp_alert("\n".join(msg_lines))
                result["_alert_sent"] = True

        elif overall == "degraded":
            services = result.get("services", {})
            warning_services = [
                svc for svc, info in services.items()
                if info.get("status") in ("down", "warning")
            ]
            if warning_services and result.get("critical", False):
                if should_send_alert(f"{project_id}_degraded"):
                    msg = (
                        f"⚠️ *{icon} {project_name} — degradado*\n\n"
                        f"Serviços com problema: {', '.join(warning_services)}\n"
                        f"O sistema está funcionando mas com limitações."
                    )
                    send_whatsapp_alert(msg)
                    result["_alert_sent"] = True

        elif overall == "up":
            recovery_key = f"{project_id}_recovery"
            if project_id in _last_alert_sent:
                if should_send_alert(recovery_key):
                    msg = f"✅ *{icon} {project_name} — voltou ao normal!*\n\nTodos os serviços estão funcionando."
                    send_whatsapp_alert(msg)
                    _last_alert_sent.pop(project_id, None)
                    _last_alert_sent.pop(f"{project_id}_degraded", None)


def _health_check_loop():
    """Loop em background que checa os projetos automaticamente."""
    import time as _time
    _time.sleep(30)  # espera servidor subir
    print(f"🏥 [HEALTH-MONITOR] Auto-check ativo! Intervalo: {HEALTH_CHECK_INTERVAL}s")

    while True:
        try:
            results = check_all_projects()
            process_alerts(results)
            for result in results:
                save_health_log(result)
            statuses = [f"{r.get('icon','')} {r.get('overall','?')}" for r in results]
            print(f"🏥 [HEALTH] {' | '.join(statuses)}")
        except Exception as e:
            print(f"🏥 [HEALTH-ERROR] {e}")
        _time.sleep(HEALTH_CHECK_INTERVAL)


def start_health_monitor():
    """Inicia a thread de monitoramento em background."""
    t = threading.Thread(target=_health_check_loop, daemon=True, name="health-monitor")
    t.start()
    print("🏥 [HEALTH-MONITOR] Thread de monitoramento iniciada")


# --- ROTAS API DO HEALTH MONITOR ---

@app.route("/api/health-monitor")
@login_required
def api_health_monitor():
    """Roda health check em todos os projetos agora e retorna resultado."""
    results = check_all_projects()
    for result in results:
        save_health_log(result)

    return jsonify({
        "projects": results,
        "checked_at": datetime.utcnow().isoformat(),
        "total": len(results),
        "healthy": sum(1 for r in results if r.get("overall") == "up"),
        "degraded": sum(1 for r in results if r.get("overall") == "degraded"),
        "down": sum(1 for r in results if r.get("overall") == "down"),
    })


@app.route("/api/health-monitor/logs")
@login_required
def api_health_monitor_logs():
    """Retorna as últimas 100 checagens de saúde."""
    if not supabase:
        return jsonify([])

    project_filter = request.args.get("project")
    try:
        query = supabase.table("health_logs").select("*").order("checked_at", desc=True).limit(100)
        if project_filter:
            query = query.eq("project", project_filter)
        result = query.execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/health-monitor/test-alert", methods=["POST"])
@login_required
def api_test_health_alert():
    """Envia um alerta de teste no WhatsApp."""
    success = send_whatsapp_alert(
        "🧪 *Teste de Alerta — Node Data Health Monitor*\n\n"
        "Se você recebeu essa mensagem, o sistema de alertas está funcionando!\n"
        f"Projetos monitorados: {len(MONITORED_PROJECTS)}\n"
        f"Intervalo: {HEALTH_CHECK_INTERVAL}s"
    )
    return jsonify({"sent": success, "phone": ALERT_PHONE[:6] + "****" if ALERT_PHONE else "not configured"})


# ============================================================
# TELEGRAM WEBHOOK — Canal interno dos socios (passo 1 do roadmap)
# ============================================================

TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "")
TELEGRAM_ALLOWED_CHAT_ID = os.getenv("TELEGRAM_ALLOWED_CHAT_ID", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")

# ============================================================
# AGENTE IA — passo 3 do roadmap. Classifica mensagens do Telegram
# ============================================================
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1")
# Setado automaticamente quando OpenAI rejeitar temperature pro modelo configurado.
# Evita reincidir o erro nas proximas chamadas dentro da mesma instancia.
_AGENT_TEMP_DISABLED = False
openai_client = None
if OPENAI_API_KEY:
    try:
        from openai import OpenAI
        openai_client = OpenAI(api_key=OPENAI_API_KEY)
        print(f"🤖 OpenAI cliente inicializado ({OPENAI_MODEL})")
    except Exception as _oe:
        print(f"⚠️ OpenAI client falhou ao inicializar: {_oe}")
else:
    print("⚠️ OPENAI_API_KEY ausente — agente IA desligado (CRM segue funcionando)")


# ============================================================
# AGENTE DE DEMO (WhatsApp via Evolution) — ISOLADO do agente do Telegram.
# Responde perguntas e executa ações sobre o CRM. Ver agente_demo.py.
# ============================================================
agente_demo_crm = None
try:
    from agente_demo import AgenteDemoCRM
    agente_demo_crm = AgenteDemoCRM(supabase, openai_client, OPENAI_MODEL)
    print("🎬 Agente de demo (WhatsApp) pronto")
except Exception as _ade:
    print(f"⚠️ Agente de demo não carregou: {_ade}")

DEMO_WEBHOOK_TOKEN = os.getenv("DEMO_WEBHOOK_TOKEN", "")
DEMO_ALLOWED_PHONES = [p.strip() for p in os.getenv("DEMO_ALLOWED_PHONES", "").split(",") if p.strip()]
# Instância Evolution DEDICADA ao bot de demo (o "Marcos"). Por padrão reusa o
# mesmo servidor Evolution dos alertas (URL/KEY), mudando só o nome da instância.
DEMO_EVOLUTION_URL = os.getenv("DEMO_EVOLUTION_URL", CRM_EVOLUTION_URL)
DEMO_EVOLUTION_KEY = os.getenv("DEMO_EVOLUTION_KEY", CRM_EVOLUTION_KEY)
DEMO_EVOLUTION_INSTANCE = os.getenv("DEMO_EVOLUTION_INSTANCE", "marcos")
_demo_msgs_vistas = set()  # dedupe em memória (reinicia no restart — ok pra demo)


def send_whatsapp_text(number, text):
    """Envia um texto a um número pela instância Evolution do bot de demo (Marcos).
    number = só dígitos com DDI."""
    if not all([DEMO_EVOLUTION_URL, DEMO_EVOLUTION_KEY, DEMO_EVOLUTION_INSTANCE]):
        print("[DEMO] Evolution (demo) não configurada; resposta não enviada.")
        return False
    url = f"{DEMO_EVOLUTION_URL}/message/sendText/{DEMO_EVOLUTION_INSTANCE}"
    headers = {"apikey": DEMO_EVOLUTION_KEY, "Content-Type": "application/json"}
    try:
        resp = requests.post(url, json={"number": number, "text": text}, headers=headers, timeout=15)
        return resp.status_code in (200, 201)
    except Exception as e:
        print(f"[DEMO] envio WhatsApp erro: {e}")
        return False


def _extrair_texto_evolution(data):
    """Extrai o texto de uma mensagem no formato Evolution (Baileys)."""
    msg = (data or {}).get("message") or {}
    return (
        msg.get("conversation")
        or (msg.get("extendedTextMessage") or {}).get("text")
        or (msg.get("imageMessage") or {}).get("caption")
        or ""
    ).strip()


def _processar_demo(numero, texto, remetente):
    """Roda o agente e envia a resposta (em thread, fora do ciclo do webhook)."""
    try:
        resposta = agente_demo_crm.responder(texto, remetente=remetente)
        send_whatsapp_text(numero, resposta)
        print(f"[DEMO] respondido {_mascara_id(numero)}: {resposta[:80]}")
    except Exception as e:
        print(f"[DEMO] processamento erro: {e}")


@app.route("/webhook/evolution", methods=["GET", "POST"])
def webhook_evolution():
    """Recebe mensagens do WhatsApp (Evolution API) e responde com o agente de demo.

    Segurança: se DEMO_WEBHOOK_TOKEN estiver setado, exige ?token= igual.
    Opcional: DEMO_ALLOWED_PHONES restringe quem o bot responde (whitelist).
    100% reativo: só responde a mensagens recebidas (ignora fromMe/eco e grupos).
    """
    if request.method == "GET":
        return jsonify({"ok": True, "demo": "webhook evolution ativo"})
    if DEMO_WEBHOOK_TOKEN and request.args.get("token") != DEMO_WEBHOOK_TOKEN:
        return jsonify({"error": "token inválido"}), 403
    if not agente_demo_crm:
        return jsonify({"error": "agente de demo indisponível"}), 503

    body = request.get_json(silent=True) or {}
    data = body.get("data") or {}
    key = data.get("key") or {}
    if key.get("fromMe"):
        return jsonify({"ok": True, "ignored": "fromMe"})
    jid = key.get("remoteJid") or ""
    if jid.endswith("@g.us"):
        return jsonify({"ok": True, "ignored": "grupo"})

    numero = jid.split("@")[0]
    if DEMO_ALLOWED_PHONES and numero not in DEMO_ALLOWED_PHONES:
        return jsonify({"ok": True, "ignored": "fora da whitelist"})

    mid = key.get("id")
    if mid:
        if mid in _demo_msgs_vistas:
            return jsonify({"ok": True, "dup": True})
        _demo_msgs_vistas.add(mid)
        if len(_demo_msgs_vistas) > 2000:
            _demo_msgs_vistas.clear()

    texto = _extrair_texto_evolution(data)
    if not texto:
        return jsonify({"ok": True, "ignored": "sem texto"})

    remetente = data.get("pushName") or ""
    # Responde em background pra dar ack rápido (OpenAI leva alguns segundos).
    threading.Thread(target=_processar_demo, args=(numero, texto, remetente), daemon=True).start()
    return jsonify({"ok": True})


# Tools (function calling). Cada uma exige confidence + reasoning.
AI_TOOLS = [
    # ===== LEITURA =====
    {
        "type": "function",
        "function": {
            "name": "buscar_lead",
            "description": "Busca leads existentes por nome, cidade ou notas. USE SEMPRE antes de criar lead novo pra evitar duplicata. Retorna ate 10 matches.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Termo de busca (nome ou cidade do cliente)"}
                },
                "required": ["query"]
            }
        }
    },
    # ===== ESCRITA — CRIA ENTIDADES =====
    {
        "type": "function",
        "function": {
            "name": "criar_lead",
            "description": "Cria um novo lead/cliente. Use quando a mensagem menciona uma entidade nova (prefeitura, empresa, candidato) que nao apareceu em buscar_lead.",
            "parameters": {
                "type": "object",
                "properties": {
                    "nome": {"type": "string", "description": "Nome do lead. Ex: 'Prefeitura de Maringa', 'Atacaforte', 'Joao Silva (candidato)'"},
                    "tipo": {"type": "string", "enum": ["empresa", "governo", "politico"]},
                    "cidade": {"type": "string"},
                    "estado": {"type": "string", "description": "Sigla UF (PR, SP, RJ, etc). Default PR se nao mencionado."},
                    "vertical_id": {"type": ["string", "null"], "description": "UUID da vertical (use a lista abaixo se aplicavel) ou null"},
                    "telefone": {"type": ["string", "null"]},
                    "email": {"type": ["string", "null"]},
                    "notas": {"type": ["string", "null"], "description": "Contexto inicial extraido da mensagem"}
                },
                "required": ["nome", "tipo", "cidade", "estado"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "atualizar_lead",
            "description": "Atualiza campos de um lead que JA EXISTE (encontrado via buscar_lead). Use quando a mensagem traz info nova de cadastro de um cliente conhecido: telefone novo, email, mudanca de status, cidade, ou proximo passo. NUNCA use pra criar — so pra editar existente. Envie SO os campos que mudaram.",
            "parameters": {
                "type": "object",
                "properties": {
                    "lead_id": {"type": "string", "description": "UUID do lead existente (do buscar_lead). NUNCA invente."},
                    "telefone": {"type": ["string", "null"], "description": "So digitos. Ex: 44991548588"},
                    "email": {"type": ["string", "null"]},
                    "status": {"type": ["string", "null"], "enum": ["Novo", "Em Prospecção", "Qualificado", "Em Negociação", "Proposta", "Fechado", "Perdido", "Pausado", None]},
                    "cidade": {"type": ["string", "null"]},
                    "estado": {"type": ["string", "null"], "description": "Sigla UF"},
                    "proximo_passo": {"type": ["string", "null"], "description": "Proximo passo combinado com o cliente"},
                    "notas": {"type": ["string", "null"], "description": "Observacao a ACRESCENTAR (sera concatenada, nao sobrescreve as notas atuais)"}
                },
                "required": ["lead_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "criar_contato",
            "description": "Cria uma pessoa (contato) dentro de um lead. Use quando a mensagem menciona uma pessoa especifica com nome (e geralmente telefone ou email).",
            "parameters": {
                "type": "object",
                "properties": {
                    "lead_id": {"type": "string", "description": "UUID do lead onde a pessoa trabalha"},
                    "nome": {"type": "string", "description": "Nome completo ou primeiro nome"},
                    "telefone": {"type": ["string", "null"], "description": "So digitos. Ex: 44991548588"},
                    "email": {"type": ["string", "null"]},
                    "cargo": {"type": ["string", "null"]},
                    "decisor": {"type": "boolean", "description": "True se a mensagem indica que e quem decide"},
                    "influenciador": {"type": "boolean"}
                },
                "required": ["lead_id", "nome"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "criar_tarefa",
            "description": "Cria tarefa pra alguem fazer. Use quando a mensagem pede acao futura ('ligar amanha', 'preparar proposta', 'agendar demo'). Default responsavel = quem mandou a mensagem.",
            "parameters": {
                "type": "object",
                "properties": {
                    "titulo": {"type": "string", "description": "Titulo curto e claro. Ex: 'Ligar para Carlos sobre CPSI'. NUNCA copie a mensagem inteira."},
                    "descricao": {"type": ["string", "null"], "description": "Contexto util da mensagem original"},
                    "responsavel": {"type": "string", "description": "Nome de alguem da EQUIPE listada no system prompt. Default = quem mandou a mensagem."},
                    "data_vencimento": {"type": "string", "description": "Data ISO YYYY-MM-DD. Calcule de DATA DE HOJE pra termos relativos (amanha, sexta, semana que vem)."},
                    "hora": {"type": ["string", "null"], "description": "Horario HH:MM (24h) quando a mensagem menciona horario. Ex: reuniao 10h -> '10:00', 14h30 -> '14:30'. null se nao houver."},
                    "prioridade": {"type": "string", "enum": ["alta", "media", "baixa"]},
                    "tipo": {"type": "string", "enum": ["ligacao", "email", "reuniao", "visita", "demo", "proposta", "outro"]},
                    "lead_id": {"type": ["string", "null"], "description": "UUID do lead vinculado ou null"}
                },
                "required": ["titulo", "responsavel", "data_vencimento", "prioridade", "tipo"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "registrar_acao",
            "description": "Registra interacao JA ocorrida no historico do lead (passado, nao futuro). Use quando a msg conta algo que ja aconteceu: 'falei com X', 'mandei a proposta pro Y', 'demo foi otima'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "lead_id": {"type": "string"},
                    "tipo": {"type": "string", "enum": ["ligacao", "email_enviado", "email_recebido", "whatsapp", "reuniao_virtual", "reuniao_presencial", "visita", "demo", "proposta_enviada", "proposta_aceita", "proposta_recusada", "anotacao"]},
                    "descricao": {"type": "string", "description": "Resumo da interacao em PT-BR"},
                    "resultado": {"type": ["string", "null"], "description": "Resultado ou proximo passo combinado, se houver"},
                    "proximo_contato": {"type": ["string", "null"], "description": "Data ISO YYYY-MM-DD do proximo contato planejado"}
                },
                "required": ["lead_id", "tipo", "descricao"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "anexar_msg_a_lead",
            "description": "Vincula a mensagem atual a um lead SEM criar tarefa nem registro. Use quando a mensagem so traz info contextual (foto, link, contato) que vale guardar mas nao precisa virar acao explicita.",
            "parameters": {
                "type": "object",
                "properties": {"lead_id": {"type": "string"}},
                "required": ["lead_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "perguntar_no_telegram",
            "description": "Use quando voce PRECISA de mais info do socio antes de executar acao critica. Envia pergunta como reply no grupo Telegram e ENCERRA o processamento (a mensagem fica em status 'aguardando_resposta'). Quando o socio responder, o agente roda de novo com o historico completo da thread. EXEMPLOS: data/hora de reuniao nao definida, identidade do cliente ambigua, acao destrutiva pedida (apagar lead, mexer em contrato existente). NUNCA pergunte sobre coisa que voce pode inferir (datas relativas claras, valores que estao no texto).",
            "parameters": {
                "type": "object",
                "properties": {
                    "pergunta": {"type": "string", "description": "Pergunta clara e curta em PT-BR (max 300 chars). HTML basico permitido: <b>negrito</b>, <i>italico</i>."}
                },
                "required": ["pergunta"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "responder_no_telegram",
            "description": "OBRIGATORIA antes de finalizar. Envia o resumo final do que voce fez como reply no grupo Telegram, dando visibilidade do trabalho ao socio. Sempre inclua a CATEGORIA da mensagem (ideia, tarefa, reuniao, lead, proposta, follow-up, risco).",
            "parameters": {
                "type": "object",
                "properties": {
                    "resumo": {"type": "string", "description": "Resumo curto e estruturado em PT-BR (max 500 chars). Use HTML: <b>negrito</b>, <i>italico</i>. Comece com a categoria detectada em negrito. Ex: '✅ <b>Lead</b> · Registrei <b>Prefeitura X</b>, criei tarefa de follow-up. <i>Faltou: data da reuniao.</i>'"}
                },
                "required": ["resumo"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "arquivar_msg",
            "description": "Arquiva a mensagem (triviais, brincadeiras, emojis sozinhos, conversa solta sem valor de negocio).",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "rascunhar_email",
            "description": "Gera um RASCUNHO de e-mail e manda no Telegram pro socio revisar e enviar pela aba E-mail do CRM. NUNCA envia e-mail de verdade — so escreve o rascunho. Use quando a mensagem pede pra responder/escrever pra um cliente por e-mail ('responde o prefeito por email', 'escreve um email pro contato da X confirmando a demo').",
            "parameters": {
                "type": "object",
                "properties": {
                    "destinatario": {"type": ["string", "null"], "description": "E-mail ou nome do destinatario, se a mensagem indicar"},
                    "assunto": {"type": "string", "description": "Assunto sugerido, curto e claro"},
                    "corpo": {"type": "string", "description": "Corpo do e-mail em PT-BR, tom profissional, pronto pra enviar (sem placeholders tipo [nome])"}
                },
                "required": ["assunto", "corpo"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "finalizar",
            "description": "OBRIGATORIA NO FIM. Chame depois de executar todas as outras tools necessarias. Encerra o processamento da mensagem.",
            "parameters": {
                "type": "object",
                "properties": {
                    "summary": {"type": "string", "description": "Resumo em PT-BR do que voce fez (max 200 chars)"}
                },
                "required": ["summary"]
            }
        }
    }
]


def send_telegram_message(text, reply_to_message_id=None):
    """Envia mensagem no grupo dos socios via Bot API. Retorna telegram_message_id ou None."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_ALLOWED_CHAT_ID:
        print("⚠️ TELEGRAM_BOT_TOKEN/ALLOWED_CHAT_ID ausentes — bot nao pode responder")
        return None
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": int(TELEGRAM_ALLOWED_CHAT_ID),
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        if reply_to_message_id:
            payload["reply_to_message_id"] = int(reply_to_message_id)
            payload["allow_sending_without_reply"] = True
        r = requests.post(url, json=payload, timeout=15)
        if r.status_code == 200 and r.json().get("ok"):
            return r.json()["result"]["message_id"]
        print(f"⚠️ send_telegram_message status={r.status_code}: {r.text[:200]}")
    except Exception as e:
        print(f"⚠️ send_telegram_message erro: {e}")
    return None


def transcrever_audio_telegram(file_id):
    """Baixa um áudio/voz do Telegram pelo file_id e transcreve via Whisper (OpenAI).
    Retorna o texto transcrito ou None se falhar (CRM segue funcionando sem áudio)."""
    if not (TELEGRAM_BOT_TOKEN and openai_client and file_id):
        return None
    try:
        # 1) Descobre o caminho do arquivo no servidor do Telegram
        get_file = requests.get(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getFile",
            params={"file_id": file_id}, timeout=15
        )
        if get_file.status_code != 200 or not get_file.json().get("ok"):
            print(f"⚠️ getFile falhou: status={get_file.status_code}")
            return None
        file_path = get_file.json()["result"].get("file_path")
        if not file_path:
            return None
        # 2) Baixa os bytes do áudio
        audio_resp = requests.get(
            f"https://api.telegram.org/file/bot{TELEGRAM_BOT_TOKEN}/{file_path}",
            timeout=20
        )
        if audio_resp.status_code != 200:
            print(f"⚠️ download de áudio falhou: status={audio_resp.status_code}")
            return None
        # 3) Transcreve com Whisper (nome de arquivo preserva a extensão p/ o decoder)
        nome = file_path.split("/")[-1] or "audio.ogg"
        transcript = openai_client.audio.transcriptions.create(
            model="whisper-1",
            file=(nome, audio_resp.content),
            language="pt"
        )
        texto = (getattr(transcript, "text", "") or "").strip()
        print(f"🎤 áudio transcrito ({len(texto)} chars)")
        return texto or None
    except Exception as e:
        print(f"⚠️ transcrever_audio_telegram erro: {e}")
        return None


def register_bot_message_in_db(bot_message_id, text, thread_root_telegram_msg_id):
    """Grava mensagem enviada pelo bot na tabela mensagens_socios pra rastrear threads.
    thread_root_telegram_msg_id = telegram_message_id da mensagem ORIGINAL do socio
    que iniciou a conversa. Permite reconstruir o contexto quando o socio responder.
    """
    if not supabase or not bot_message_id:
        return
    try:
        supabase.table("mensagens_socios").insert({
            "telegram_message_id": bot_message_id,
            "telegram_chat_id": int(TELEGRAM_ALLOWED_CHAT_ID) if TELEGRAM_ALLOWED_CHAT_ID else None,
            "sender_name": "Bot Node",
            "from_bot": True,
            "text": text,
            "replied_to_telegram_message_id": thread_root_telegram_msg_id,
            "status": "arquivado",
            "raw_payload": {},
            "ai_status": "skipped"
        }).execute()
    except Exception as e:
        print(f"⚠️ register_bot_message_in_db: {e}")


def _load_thread_history(msg_row):
    """Se a mensagem faz parte de uma thread (replied_to_telegram_message_id setado),
    carrega o historico completo (mensagem-raiz + todas as respostas do bot/socios)
    em ordem cronologica pra o agente ter contexto."""
    if not supabase:
        return []
    replied_to = msg_row.get("replied_to_telegram_message_id")
    if not replied_to:
        return []
    chat_id = msg_row.get("telegram_chat_id")
    if not chat_id:
        return []
    try:
        # Mensagem-raiz (a primeira do socio na thread)
        root = supabase.table("mensagens_socios").select("*") \
            .eq("telegram_chat_id", chat_id) \
            .eq("telegram_message_id", replied_to).limit(1).execute()
        history = []
        if root.data:
            history.append(root.data[0])
        # Mensagens entre a raiz e a atual (replies do bot e do socio)
        between = supabase.table("mensagens_socios").select("*") \
            .eq("telegram_chat_id", chat_id) \
            .gt("telegram_message_id", replied_to) \
            .lt("telegram_message_id", msg_row.get("telegram_message_id") or 0) \
            .order("telegram_message_id").execute()
        history.extend(between.data or [])
        return history
    except Exception as e:
        print(f"_load_thread_history erro: {e}")
        return []


def _build_agent_system_prompt():
    """Prompt do agente — descreve empresa, sociedade, leads existentes, verticais
    e workflow esperado. Como muda pouco entre chamadas, OpenAI usa prompt caching
    automatico (50% off no input cacheado quando >1024 tokens).
    """
    leads_data, verticais_data, equipe_data = [], [], []
    if supabase:
        try:
            r = supabase.table("leads").select("id, nome, status, cidade, estado, verticais(nome)").is_null("deleted_at").limit(500).execute()
            leads_data = r.data or []
        except Exception:
            pass
        try:
            r = supabase.table("verticais").select("id, nome, codigo").execute()
            verticais_data = r.data or []
        except Exception:
            pass
        try:
            r = supabase.table("crm_users").select("display_name").eq("active", True).execute()
            equipe_data = [u.get("display_name") for u in (r.data or []) if u.get("display_name")]
        except Exception:
            pass
    equipe_str = ", ".join(equipe_data) if equipe_data else "Joao, Guilherme, Marcos"

    leads_str = "\n".join(
        f"- {l.get('nome', '?')} (id: {l['id']}, status: {l.get('status', '—')}, cidade: {l.get('cidade', '—')}/{l.get('estado', '—')}, vertical: {(l.get('verticais') or {}).get('nome', '—')})"
        for l in leads_data
    ) or "(nenhum lead cadastrado ainda)"

    verticais_str = "\n".join(
        f"- {v['nome']} (id: {v['id']}, codigo: {v.get('codigo', '—')})"
        for v in verticais_data
    ) or "(nenhuma vertical)"

    hoje = hoje_br()
    return f"""Voce e o AGENTE OPERACIONAL da Node Data — empresa que vende software de inteligencia (analise de sentimento de cidadaos via WhatsApp) para PREFEITURAS e CAMPANHAS POLITICAS.

EQUIPE / RESPONSAVEIS VALIDOS (use exatamente estes nomes ao atribuir tarefas):
{equipe_str}
(Joao e o dono. A equipe inclui socios e vendedoras comissionadas que viajam apresentando o produto.)

Voce e o CEREBRO operacional da equipe. Quando uma mensagem chega no grupo Telegram interno, voce LE, EXECUTA o que e seguro, e PERGUNTA quando falta info critica. SEMPRE da feedback final no Telegram resumindo o que fez.

DATA DE HOJE: {hoje}

LEADS EXISTENTES NO CRM (use o id exato quando referenciar):
{leads_str}

VERTICAIS DISPONIVEIS (use o id em criar_lead quando aplicavel):
{verticais_str}

═══════════════════════════════════════════════════
CATEGORIAS — toda mensagem cai em UMA destas 7:
═══════════════════════════════════════════════════
- IDEIA: pensamento solto, brainstorm, sugestao sem acao imediata
- TAREFA: algo a fazer no futuro pelos socios
- REUNIAO: encontro presencial ou virtual com cliente/fornecedor
- LEAD: novo prospect/cliente a registrar
- PROPOSTA: comercial enviada ou recebida
- FOLLOW-UP: retomar contato com cliente existente
- RISCO: cliente reclamando, prazo vencendo, problema operacional

Sempre INCLUA a categoria detectada no resumo final (em negrito).

═══════════════════════════════════════════════════
TOOLS DE ESCRITA NO TELEGRAM (CRITICAS):
═══════════════════════════════════════════════════
- perguntar_no_telegram(pergunta): use SOMENTE quando faltar info critica e voce nao consegue inferir. Encerra o processamento.
- responder_no_telegram(resumo): OBRIGATORIA antes de finalizar. Sempre da feedback do que voce fez.
- rascunhar_email(assunto, corpo, destinatario): quando o socio pede pra responder/escrever pra um cliente por E-MAIL. Voce SO escreve o rascunho (vai pro grupo interno pro socio revisar e enviar pelo CRM). NUNCA envia e-mail sozinho.

REGRAS DE SEGURANCA (NUNCA QUEBRE):
1. NUNCA marque reuniao sem data E hora claras. Se a mensagem original diz "semana que vem" / "qualquer dia" sem precisao, faca: criar_lead + registrar_acao + perguntar_no_telegram pedindo data+hora. NAO crie tarefa de reuniao ainda. Quando a resposta vier (continuacao de thread), crie a tarefa de reuniao com data/hora exatas.
2. NUNCA execute acao destrutiva (apagar lead, alterar contrato existente, cancelar tarefa de outro socio).
3. NUNCA envie mensagem/e-mail pra cliente externo. So perguntar_no_telegram, responder_no_telegram e rascunhar_email (todas ficam no grupo interno; rascunhar_email APENAS escreve o rascunho, quem envia e o socio).
4. NUNCA invente lead_id. So use IDs que vieram do buscar_lead ou do retorno de criar_lead.
5. Datas relativas CLARAS (amanha, sexta, dia 15, em 3 dias) calcule normalmente — NAO pergunte.
6. Em CONTINUACAO DE THREAD (quando o user_content comecar com "⚠️ ESTA MENSAGEM E CONTINUACAO"), VOCE TEM TODO O CONTEXTO ja resumido. NAO trate como mensagem isolada. NAO pergunte coisa que ja esta listada como "JA executou". Combine a INTENCAO COMPLETA (pedido original + resposta atual) e execute.

═══════════════════════════════════════════════════
WORKFLOW POR TIPO DE MENSAGEM:
═══════════════════════════════════════════════════

A) Mensagem menciona NOVO cliente:
  1. buscar_lead(query=nome do cliente) — SEMPRE primeiro
  2. Se nao existe: criar_lead. Prefeituras=governo, empresas=empresa, candidatos=politico
  3. Pessoas com nome+telefone: criar_contato vinculado ao lead
  4. Acoes JA ocorridas ("falei com", "mandei proposta"): registrar_acao
  5. Acoes FUTURAS ("ligar amanha", "preparar X"): criar_tarefa
  6. Se falta info critica pra reuniao (data/hora) -> perguntar_no_telegram e PULA pro 8
  7. responder_no_telegram com resumo + categoria
  8. finalizar

B) Mensagem menciona cliente EXISTENTE: igual A mas pula passo 2.
   - Se a mensagem traz INFO NOVA DE CADASTRO do cliente (telefone novo, email, mudou de status, nova cidade, proximo passo definido): use atualizar_lead com o lead_id existente e SO os campos que mudaram. Ex: "o telefone do prefeito de Ivate agora e 44 9..." -> atualizar_lead(lead_id=<existente>, telefone="449...").
   - Para fatos/interacoes ocorridas continue usando registrar_acao; atualizar_lead e so pro CADASTRO do lead.

C) Mensagem trivial (bom dia, "ok", "kk", emoji): arquivar_msg + responder_no_telegram opcional + finalizar.

D) Continuacao de thread (voce ja conversou antes — o historico vem no input):
   - Considere TODA a conversa pra entender o que falta
   - Se a resposta do socio fornece a info que voce tinha pedido, execute a acao
   - Se ainda falta, perguntar_no_telegram com nova pergunta especifica
   - responder_no_telegram + finalizar

═══════════════════════════════════════════════════
REGRAS DE QUALIDADE:
═══════════════════════════════════════════════════
- TITULO DE TAREFA curto e acionavel: "Ligar para Carlos sobre CPSI", "Preparar proposta Cianorte". NUNCA copie a mensagem inteira.
- TELEFONE: extraia so digitos. "44 99154-8588" -> "44991548588".
- RESPONSAVEL DEFAULT da tarefa: o socio que MANDOU a mensagem.
- Estado default: PR. Use outro so se mencionado.
- Em duvida entre tarefa e registro: prazo futuro = tarefa, fato passado = registrar_acao.

═══════════════════════════════════════════════════
EXEMPLO 1 (info completa — executa direto):
═══════════════════════════════════════════════════
Mensagem: "falei com prefeitura de Maringa, me passaram contato do carlos 44 991548588, precisa ligar amanha sobre CPSI"

Workflow:
1. buscar_lead(query="Maringa") → []
2. criar_lead(nome="Prefeitura de Maringa", tipo="governo", cidade="Maringa", estado="PR")
3. criar_contato(lead_id=<acima>, nome="Carlos", telefone="44991548588")
4. registrar_acao(lead_id=<acima>, tipo="ligacao", descricao="Conversou com pessoal da prefeitura, conseguiu contato do Carlos")
5. criar_tarefa(titulo="Ligar para Carlos sobre CPSI", lead_id=<acima>, responsavel="Marcos", data_vencimento="<amanha>", prioridade="alta", tipo="ligacao")
6. responder_no_telegram(resumo="✅ <b>Lead</b> · Registrei <b>Prefeitura de Maringa</b>. Contato Carlos (44 99154-8588) criado. Tarefa de ligacao pra amanha criada. ✓ Pronto.")
7. finalizar

═══════════════════════════════════════════════════
EXEMPLO 2 (falta info — pergunta antes):
═══════════════════════════════════════════════════
Mensagem: "Conversei com o prefeito de X, ele quer reuniao semana que vem sobre monitoramento WhatsApp."

Workflow:
1. buscar_lead(query="X") → []
2. criar_lead(nome="Prefeitura de X", tipo="governo", cidade="X", estado="PR", notas="Prefeito interessado em monitoramento WhatsApp")
3. registrar_acao(lead_id=<acima>, tipo="reuniao_virtual", descricao="Conversa inicial. Prefeito mostrou interesse em monitoramento de demandas via WhatsApp.")
4. criar_tarefa(titulo="Follow-up reuniao com prefeito de X", lead_id=<acima>, responsavel=<socio que mandou>, data_vencimento="<+2 dias>", prioridade="alta", tipo="reuniao", descricao="Confirmar data/hora da reuniao apos resposta no Telegram")
5. responder_no_telegram(resumo="✅ <b>Lead/Reuniao</b> · Registrei <b>Prefeitura de X</b> e criei follow-up. <i>Falta definir data e hora da reuniao.</i>")
6. perguntar_no_telegram(pergunta="🤔 Que dia e horario da reuniao com o prefeito? '<i>Semana que vem</i>' inclui 5 dias uteis. Me passa um dia e hora pra eu criar a tarefa de reuniao com prazo certo.")
7. finalizar (a thread continua quando o socio responder)

NA THREAD QUANDO O SOCIO RESPONDER ("quinta as 14h"):
- Voce recebe o historico completo
- Identifica que a info que faltava chegou
- criar_tarefa(titulo="Reuniao com prefeito de X — monitoramento WhatsApp", lead_id=<aquele>, data_vencimento="<quinta calculada>", hora="14:00", tipo="reuniao", prioridade="alta")
- responder_no_telegram(resumo="✅ <b>Reuniao</b> agendada: <b>quinta-feira as 14h</b> com prefeito de X. Tarefa criada e vinculada ao lead.")
- finalizar

═══════════════════════════════════════════════════
Aja sempre. Voce e operacional, nao consultivo. PERGUNTA so quando falta info CRITICA."""


def _execute_tool(tool_name, args, msg_row, msg_id, user_label="Agente IA"):
    """Executa uma tool no banco e retorna dict com {ok, ...} pro modelo continuar."""
    if not supabase:
        return {"ok": False, "error": "DB offline"}
    try:
        if tool_name == "buscar_lead":
            q = (args.get("query") or "").lower().strip()
            if not q:
                return {"ok": True, "matches": []}
            r = supabase.table("leads").select("id, nome, cidade, estado, status").is_null("deleted_at").limit(200).execute()
            matches = []
            for l in (r.data or []):
                blob = ((l.get("nome") or "") + " " + (l.get("cidade") or "") + " " + (l.get("estado") or "")).lower()
                if q in blob:
                    matches.append(l)
            return {"ok": True, "matches": matches[:10]}

        if tool_name == "criar_lead":
            data = {
                "nome": args.get("nome"),
                "tipo": args.get("tipo"),
                "cidade": args.get("cidade"),
                "estado": args.get("estado") or "PR",
                "vertical_id": args.get("vertical_id"),
                "telefone": args.get("telefone"),
                "email": args.get("email"),
                "notas": args.get("notas"),
                "status": "Novo",
                "origem": "Agente IA",
                "responsavel": (msg_row or {}).get("sender_name") or "Agente IA"
            }
            data = {k: v for k, v in data.items() if v is not None}
            r = supabase.table("leads").insert(data).execute()
            new_id = r.data[0]["id"] if r.data else None
            try:
                audit("create", "leads", new_id, f"Agente IA criou lead: {data.get('nome')}")
            except Exception:
                pass
            return {"ok": True, "id": new_id, "nome": data.get("nome"), "kind": "lead"}

        if tool_name == "atualizar_lead":
            lead_id = args.get("lead_id")
            if not lead_id:
                return {"ok": False, "error": "lead_id obrigatorio"}
            campos = ("telefone", "email", "status", "cidade", "estado", "proximo_passo")
            data = {k: args.get(k) for k in campos if args.get(k) is not None}
            # notas: ACRESCENTA ao texto atual, nunca sobrescreve
            nova_nota = args.get("notas")
            if nova_nota:
                atual = supabase.table("leads").select("nome, notas").eq("id", lead_id).limit(1).execute()
                if not atual.data:
                    return {"ok": False, "error": "lead nao encontrado"}
                notas_atuais = (atual.data[0].get("notas") or "").strip()
                carimbo = f"[Telegram {datetime.now(BR_TZ).strftime('%d/%m')}] {nova_nota}"
                data["notas"] = (notas_atuais + "\n" + carimbo).strip() if notas_atuais else carimbo
            if not data:
                return {"ok": False, "error": "nada pra atualizar"}
            r = supabase.table("leads").update(data).eq("id", lead_id).execute()
            nome = r.data[0].get("nome") if r.data else None
            supabase.table("mensagens_socios").update({
                "status": "triado",
                "lead_id": lead_id,
                "triado_em": datetime.now().isoformat(),
                "triado_por": user_label
            }).eq("id", msg_id).execute()
            try:
                audit("update", "leads", lead_id, f"Agente IA atualizou lead: {', '.join(data.keys())}")
            except Exception:
                pass
            return {"ok": True, "id": lead_id, "nome": nome, "campos": list(data.keys()), "kind": "lead_update"}

        if tool_name == "criar_contato":
            data = {
                "lead_id": args.get("lead_id"),
                "nome": args.get("nome"),
                "telefone": args.get("telefone"),
                "email": args.get("email"),
                "cargo": args.get("cargo"),
                "decisor": bool(args.get("decisor")),
                "influenciador": bool(args.get("influenciador"))
            }
            data = {k: v for k, v in data.items() if v is not None}
            r = supabase.table("contatos").insert(data).execute()
            new_id = r.data[0]["id"] if r.data else None
            try:
                audit("create", "contatos", new_id, f"Agente IA: contato {data.get('nome')}")
            except Exception:
                pass
            return {"ok": True, "id": new_id, "nome": data.get("nome"), "lead_id": data.get("lead_id"), "kind": "contato"}

        if tool_name == "criar_tarefa":
            sender = (msg_row or {}).get("sender_name") or "Joao"
            data = {
                "titulo": (args.get("titulo") or "(sem titulo)")[:200],
                "descricao": args.get("descricao") or (msg_row or {}).get("text"),
                "responsavel": args.get("responsavel") or sender,
                "data_vencimento": args.get("data_vencimento") or hoje_br(),
                "hora": args.get("hora"),
                "prioridade": args.get("prioridade") or "media",
                "tipo": args.get("tipo") or "outro",
                "lead_id": args.get("lead_id"),
                "status": "aberta"
            }
            data = {k: v for k, v in data.items() if v is not None}
            r = supabase.table("tarefas").insert(data).execute()
            new_id = r.data[0]["id"] if r.data else None
            # Marca a mensagem como triada vinculando a tarefa
            supabase.table("mensagens_socios").update({
                "status": "triado",
                "tarefa_id": new_id,
                "lead_id": args.get("lead_id"),
                "triado_em": datetime.now().isoformat(),
                "triado_por": user_label
            }).eq("id", msg_id).execute()
            try:
                audit("create", "tarefas", new_id, f"Agente IA: tarefa {data.get('titulo')}")
            except Exception:
                pass
            return {"ok": True, "id": new_id, "titulo": data.get("titulo"), "lead_id": data.get("lead_id"), "kind": "tarefa"}

        if tool_name == "registrar_acao":
            data = {
                "lead_id": args.get("lead_id"),
                "tipo": args.get("tipo"),
                "descricao": args.get("descricao"),
                "resultado": args.get("resultado"),
                "proximo_contato": args.get("proximo_contato"),
                "responsavel": user_label
            }
            data = {k: v for k, v in data.items() if v is not None}
            r = supabase.table("historico_acoes").insert(data).execute()
            new_id = r.data[0]["id"] if r.data else None
            supabase.table("mensagens_socios").update({
                "status": "triado",
                "lead_id": args.get("lead_id"),
                "triado_em": datetime.now().isoformat(),
                "triado_por": user_label
            }).eq("id", msg_id).execute()
            try:
                audit("create", "historico_acoes", new_id, f"Agente IA: {data.get('tipo')}")
            except Exception:
                pass
            return {"ok": True, "id": new_id, "tipo": data.get("tipo"), "lead_id": data.get("lead_id"), "kind": "historico"}

        if tool_name == "anexar_msg_a_lead":
            lead_id = args.get("lead_id")
            supabase.table("mensagens_socios").update({
                "status": "triado",
                "lead_id": lead_id,
                "triado_em": datetime.now().isoformat(),
                "triado_por": user_label
            }).eq("id", msg_id).execute()
            try:
                audit("update", "mensagens_socios", msg_id, f"Agente IA anexou ao lead {lead_id}")
            except Exception:
                pass
            return {"ok": True, "lead_id": lead_id, "kind": "anexar"}

        if tool_name == "arquivar_msg":
            supabase.table("mensagens_socios").update({
                "status": "arquivado",
                "triado_em": datetime.now().isoformat(),
                "triado_por": user_label
            }).eq("id", msg_id).execute()
            try:
                audit("update", "mensagens_socios", msg_id, "Agente IA arquivou")
            except Exception:
                pass
            return {"ok": True, "kind": "arquivar"}

        if tool_name == "perguntar_no_telegram":
            pergunta = (args.get("pergunta") or "").strip()
            if not pergunta:
                return {"ok": False, "error": "pergunta vazia"}
            # Thread root = a primeira mensagem do socio (pra rastreio do historico).
            # Em continuacao, thread_root e a msg-raiz original.
            thread_root = (msg_row or {}).get("replied_to_telegram_message_id") or (msg_row or {}).get("telegram_message_id")
            chat_id_local = (msg_row or {}).get("telegram_chat_id")
            current_tg_id = (msg_row or {}).get("telegram_message_id")
            bot_msg_id = send_telegram_message(f"❓ {pergunta}", reply_to_message_id=current_tg_id)
            if bot_msg_id:
                register_bot_message_in_db(bot_msg_id, pergunta, thread_root)
                # IMPORTANTE: marca a MSG ATUAL como awaiting=true (nao a root
                # antiga). Assim a thread "avanca" — a proxima resposta vai linkar
                # a msg atual, evitando "thread zumbi" infinita.
                if chat_id_local and current_tg_id:
                    try:
                        supabase.table("mensagens_socios").update({"awaiting_user_response": True}) \
                            .eq("telegram_chat_id", chat_id_local) \
                            .eq("telegram_message_id", current_tg_id) \
                            .execute()
                    except Exception as e:
                        print(f"⚠️ erro marcando awaiting_user_response: {e}")
                try:
                    audit("update", "mensagens_socios", msg_id, "Agente IA perguntou no Telegram")
                except Exception:
                    pass
                return {"ok": True, "kind": "pergunta", "telegram_message_id": bot_msg_id, "pergunta": pergunta}
            return {"ok": False, "error": "falha ao enviar mensagem no Telegram"}

        if tool_name == "responder_no_telegram":
            resumo = (args.get("resumo") or "").strip()
            if not resumo:
                return {"ok": False, "error": "resumo vazio"}
            thread_root = (msg_row or {}).get("replied_to_telegram_message_id") or (msg_row or {}).get("telegram_message_id")
            reply_to = (msg_row or {}).get("telegram_message_id")
            bot_msg_id = send_telegram_message(resumo, reply_to_message_id=reply_to)
            if bot_msg_id:
                register_bot_message_in_db(bot_msg_id, resumo, thread_root)
                return {"ok": True, "kind": "resumo", "telegram_message_id": bot_msg_id}
            return {"ok": False, "error": "falha ao enviar resumo no Telegram"}

        if tool_name == "rascunhar_email":
            assunto = (args.get("assunto") or "").strip()
            corpo = (args.get("corpo") or "").strip()
            dest = (args.get("destinatario") or "").strip()
            if not corpo:
                return {"ok": False, "error": "corpo vazio"}
            # Escapa partes dinamicas — corpo e texto livre e quebraria o parse_mode HTML do Telegram
            def _esc(s):
                return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            head = "✍️ <b>Rascunho de e-mail</b>"
            if dest:
                head += f" para <b>{_esc(dest)}</b>"
            texto = (
                f"{head}\n<b>Assunto:</b> {_esc(assunto)}\n\n{_esc(corpo)}\n\n"
                "<i>Revise e envie pela aba E-mail do CRM — eu não envio sozinho.</i>"
            )
            reply_to = (msg_row or {}).get("telegram_message_id")
            send_telegram_message(texto, reply_to_message_id=reply_to)
            return {"ok": True, "kind": "rascunho_email", "assunto": assunto}

        return {"ok": False, "error": f"tool desconhecida: {tool_name}"}

    except Exception as e:
        return {"ok": False, "error": str(e)}


_PALAVRAS_REUNIAO = ("reuni", "encontro", "marcar uma", "agendar uma")
_PALAVRAS_DATA = ("amanh", "hoje", "segunda", "terca", "terça", "quarta", "quinta",
                  "sexta", "sabado", "sábado", "domingo", "semana", "horas", " às ",
                  " as ", "manha", "manhã", "tarde", "noite", " h ")
_REGEX_DATA_NUMERICA = re.compile(r"\d{1,2}\s*[/\-]\s*\d{1,2}")
_REGEX_HORA = re.compile(r"\d{1,2}\s*(?:h|hs|:|hora)", re.IGNORECASE)


def mensagem_pede_reuniao_sem_data(texto):
    """True se a mensagem original menciona reuniao/encontro mas NAO traz data+hora.
    Usado pra bloquear o agente de criar lead/tarefa parciais na primeira passada.
    Quando o socio responder com data/hora (continuacao), o agente cria tudo de uma vez.
    """
    if not texto:
        return False
    t = texto.lower()
    tem_reuniao = any(p in t for p in _PALAVRAS_REUNIAO)
    if not tem_reuniao:
        return False
    tem_data_num = bool(_REGEX_DATA_NUMERICA.search(texto))
    tem_hora = bool(_REGEX_HORA.search(texto))
    tem_palavra_data = any(p in t for p in _PALAVRAS_DATA)
    return not (tem_data_num or tem_hora or tem_palavra_data)


def classify_message_with_ai(msg_id):
    """Agente operacional: roda em thread daemon, le a mensagem, executa o
    workflow completo (extrair entidades, criar leads/contatos/tarefas).
    Em vez de propor, AGE diretamente no banco.
    """
    if not openai_client or not supabase:
        return
    try:
        supabase.table("mensagens_socios").update({"ai_status": "processing"}).eq("id", msg_id).execute()

        row = supabase.table("mensagens_socios").select("*").eq("id", msg_id).limit(1).execute()
        if not row.data:
            return
        msg = row.data[0]

        # Áudio/voz sem texto: transcreve via Whisper e segue o fluxo normal sobre a fala.
        if not msg.get("text") and msg.get("attachment_type") in ("voice", "audio"):
            transcricao = transcrever_audio_telegram(msg.get("attachment_file_id"))
            if transcricao:
                supabase.table("mensagens_socios").update({
                    "text": transcricao,
                    "transcricao": transcricao
                }).eq("id", msg_id).execute()
                msg["text"] = transcricao
                msg["transcricao"] = transcricao

        if not msg.get("text"):
            supabase.table("mensagens_socios").update({
                "ai_status": "skipped",
                "ai_reasoning": "Mensagem sem texto (apenas anexo).",
                "ai_processed_at": datetime.now().isoformat()
            }).eq("id", msg_id).execute()
            return

        system_prompt = _build_agent_system_prompt()
        sender = msg.get("sender_name") or msg.get("sender_username") or "socio"

        # Se a mensagem faz parte de uma thread (continuacao de conversa com o bot),
        # carrega o historico completo e monta um sumario ESTRUTURADO com as entidades
        # ja criadas. Mostrar so o texto cru das mensagens anteriores confunde o modelo
        # (ele espelha respostas do bot tipo "falta contexto") — o sumario destacado e
        # muito mais robusto.
        thread_history = _load_thread_history(msg)
        if thread_history:
            # Esta mensagem CONSUMIU a pergunta pendente da thread root.
            # Limpa awaiting=false imediatamente pra evitar "thread zumbi"
            # caso o agente perguntar de novo (vai marcar awaiting na MSG ATUAL,
            # nao na root antiga).
            replied_to_local = msg.get("replied_to_telegram_message_id")
            if replied_to_local:
                try:
                    supabase.table("mensagens_socios").update({"awaiting_user_response": False}) \
                        .eq("telegram_chat_id", msg.get("telegram_chat_id")) \
                        .eq("telegram_message_id", replied_to_local) \
                        .execute()
                    print(f"🧹 Pergunta pendente da root tg_id={replied_to_local} consumida pela nova msg")
                except Exception as e:
                    print(f"⚠️ erro limpando awaiting da root: {e}")

            leads_criados, contatos_criados, tarefas_criadas = [], [], []
            historicos_registrados, perguntas_pendentes = 0, []
            root_msg = None
            for h in thread_history:
                if root_msg is None and not h.get("from_bot"):
                    root_msg = h
                for a in (h.get("ai_actions_taken") or []):
                    if not isinstance(a, dict):
                        continue
                    action = a.get("action")
                    result = a.get("result") or {}
                    if not result.get("ok"):
                        continue
                    if action == "criar_lead":
                        leads_criados.append({"id": result.get("id"), "nome": result.get("nome")})
                    elif action == "criar_contato":
                        contatos_criados.append({"id": result.get("id"), "nome": result.get("nome"), "lead_id": result.get("lead_id")})
                    elif action == "criar_tarefa":
                        tarefas_criadas.append({"id": result.get("id"), "titulo": result.get("titulo"), "lead_id": result.get("lead_id")})
                    elif action == "registrar_acao":
                        historicos_registrados += 1
                    elif action == "perguntar_no_telegram":
                        q = (a.get("args") or {}).get("pergunta")
                        if q:
                            perguntas_pendentes.append(q)

            # Mensagem CONSOLIDADA — combina pedido original + resposta atual como
            # se fosse uma unica intencao do socio. Evita o modelo se confundir com
            # historico cronologico que parece "conversa".
            mensagem_original = (root_msg or {}).get("text") or "(sem texto)"
            sender_orig = (root_msg or {}).get("sender_name") or sender
            pergunta_pendente = perguntas_pendentes[-1] if perguntas_pendentes else None
            lead_existente = leads_criados[0] if leads_criados else None

            ctx = []
            ctx.append(f"⚠️ ESTA MENSAGEM E CONTINUACAO DE UMA THREAD QUE VOCE JA INICIOU. NAO trate como mensagem isolada.")
            ctx.append("")
            ctx.append(f"━━━━ CONTEXTO COMPLETO DA CONVERSA ━━━━")
            ctx.append(f'1) {sender_orig} disse ORIGINALMENTE: "{mensagem_original}"')
            ctx.append("")
            ctx.append("2) Voce JA executou estas acoes na primeira passada:")
            if lead_existente:
                ctx.append(f"   ✅ Criou o lead \"{lead_existente['nome']}\" (lead_id: {lead_existente['id']}) ← USE ESTE ID, NAO CRIE OUTRO")
            for c in contatos_criados:
                ctx.append(f"   ✅ Criou contato {c.get('nome')} (contato_id: {c.get('id')})")
            for t in tarefas_criadas:
                ctx.append(f"   ✅ Criou tarefa \"{t.get('titulo')}\" (tarefa_id: {t.get('id')})")
            if historicos_registrados:
                ctx.append(f"   ✅ Registrou {historicos_registrados} acao(oes) no historico_acoes")
            if pergunta_pendente:
                ctx.append("")
                ctx.append(f'3) Voce ENTAO perguntou: "{pergunta_pendente}"')
            ctx.append("")
            ctx.append(f'4) AGORA o socio respondeu: "{msg["text"]}"')
            ctx.append("")
            ctx.append("━━━━ INTENCAO COMPLETA DO SOCIO (combinada) ━━━━")
            ctx.append(f'"{mensagem_original}" + "{msg["text"]}"')
            ctx.append("")
            ctx.append("━━━━ O QUE VOCE DEVE FAZER AGORA ━━━━")
            if lead_existente:
                ctx.append(f"- O lead JA EXISTE (id: {lead_existente['id']}). USE este id. NAO chame buscar_lead nem criar_lead.")
            ctx.append("- Considere a INTENCAO COMPLETA acima. A nova resposta complementa o pedido original.")
            ctx.append("- Se o pedido original era uma reuniao e agora voce tem data/hora, CRIE a tarefa de reuniao com tipo=reuniao, data_vencimento=<data calculada>, prioridade=alta, lead_id=<o existente>, responsavel=<quem mandou a mensagem original>.")
            ctx.append("- responder_no_telegram com confirmacao do que voce fez, depois finalizar.")
            ctx.append("- PROIBIDO perguntar de novo se ja foi respondido. Se ainda falta algo critico, peca de forma diferente.")
            user_content = "\n".join(ctx)
            print(f"🧵 Thread consolidada: lead={lead_existente['nome'] if lead_existente else '—'}, resp_atual=\"{msg['text'][:50]}\"")
        else:
            user_content = f"Mensagem de {sender} no grupo Telegram interno:\n\n{msg['text']}"

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content}
        ]
        actions_taken = []
        max_iter = 6
        final_summary = None

        # Reasoning models (o1, o3, o4-mini, gpt-5-thinking, etc) so aceitam
        # temperature=1 (default). Detectamos pelo nome OU descobrimos no runtime
        # via fallback automatico (vide _AGENT_TEMP_DISABLED).
        _m = OPENAI_MODEL.lower()
        _is_reasoning = _m.startswith("o1") or _m.startswith("o3") or _m.startswith("o4") or "thinking" in _m or "reasoning" in _m

        # EM CONTINUACAO DE THREAD: removemos perguntar_no_telegram das tools
        # disponiveis. O agente JA fez essa pergunta na primeira passagem; agora
        # tem a resposta. Forcar ele a EXECUTAR (criar_tarefa, etc) em vez de
        # perguntar de novo. Resolve o caso em que modelos reasoning ficam
        # perguntando em loop mesmo com contexto completo.
        if thread_history:
            # CONTINUACAO: agente DEVE executar com os dados do sumario. Tira a
            # tool de perguntar pra forcar acao.
            tools_para_chamada = [
                t for t in AI_TOOLS
                if t.get("function", {}).get("name") != "perguntar_no_telegram"
            ]
            print(f"🔒 Continuacao detectada — perguntar_no_telegram bloqueada. Agente DEVE executar.")
        elif mensagem_pede_reuniao_sem_data(msg.get("text") or ""):
            # PRIMEIRA PASSADA, mensagem pede reuniao mas SEM data/hora claras.
            # Bloqueia TODAS as tools de criacao — agente so pode perguntar.
            # Quando o socio responder com data/hora, o agente cria tudo de uma vez.
            tools_para_chamada = [
                t for t in AI_TOOLS
                if t.get("function", {}).get("name") in (
                    "perguntar_no_telegram", "responder_no_telegram", "finalizar"
                )
            ]
            print(f"🚫 Reuniao sem data — bloqueando criacao. Agente SO pode perguntar nesta passada.")
        else:
            tools_para_chamada = AI_TOOLS

        _completion_kwargs = {
            "model": OPENAI_MODEL,
            "tools": tools_para_chamada,
            "tool_choice": "required",
            "timeout": 90 if _is_reasoning else 45
        }
        global _AGENT_TEMP_DISABLED
        if not _is_reasoning and not _AGENT_TEMP_DISABLED:
            _completion_kwargs["temperature"] = 0.1

        # Log do prompt enviado (truncado) pra debug rapido nos logs do Coolify
        _u_preview = user_content[:300].replace("\n", " | ")
        print(f"📨 user_content preview: {_u_preview}...")

        for i in range(max_iter):
            try:
                completion = openai_client.chat.completions.create(
                    messages=messages,
                    **_completion_kwargs
                )
            except Exception as oe:
                _err = str(oe).lower()
                # Fallback automatico: alguns reasoning models nao tem prefixo
                # obvio mas rejeitam temperature em runtime. Detecta, marca global
                # pra proximas mensagens nao reincidir, e refaz a chamada.
                if "temperature" in _err and ("does not support" in _err or "only the default" in _err) and "temperature" in _completion_kwargs:
                    _AGENT_TEMP_DISABLED = True
                    _completion_kwargs.pop("temperature", None)
                    print(f"⚠️ {OPENAI_MODEL} rejeitou temperature; refazendo sem o parametro (cache global ativado)")
                    completion = openai_client.chat.completions.create(
                        messages=messages,
                        **_completion_kwargs
                    )
                else:
                    raise
            choice = completion.choices[0]
            resp = choice.message

            if not resp.tool_calls:
                # Modelo terminou sem chamar tool — registra e sai
                break

            # Anexa resposta do assistant no historico
            assistant_msg = {"role": "assistant", "content": resp.content or "", "tool_calls": []}
            for tc in resp.tool_calls:
                assistant_msg["tool_calls"].append({
                    "id": tc.id, "type": "function",
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments}
                })
            messages.append(assistant_msg)

            finalized = False
            for tc in resp.tool_calls:
                tool_name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except Exception:
                    args = {}

                if tool_name == "finalizar":
                    final_summary = args.get("summary")
                    actions_taken.append({"action": "finalizar", "summary": final_summary})
                    # Anexa tool response (mesmo pra finalizar) pra fechar o ciclo
                    messages.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps({"ok": True})})
                    finalized = True
                    continue

                result = _execute_tool(tool_name, args, msg, msg_id)
                actions_taken.append({"action": tool_name, "args": args, "result": result})
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps(result, default=str)[:4000]
                })

            if finalized:
                break

        # Se essa mensagem era uma continuacao de thread e o agente conseguiu
        # executar acoes uteis sem perguntar de novo, considera a thread RESOLVIDA:
        # limpa o awaiting_user_response E marca status='triado' na root tambem
        # (pra Inbox da Caixa nao ficar poluida com a mensagem original).
        now_iso = datetime.now().isoformat()
        replied_to = msg.get("replied_to_telegram_message_id")
        if replied_to:
            perguntou_de_novo = any(
                isinstance(a, dict) and a.get("action") == "perguntar_no_telegram"
                and (a.get("result") or {}).get("ok")
                for a in actions_taken
            )
            executou_acao_util = any(
                isinstance(a, dict) and a.get("action") in (
                    "criar_tarefa", "criar_lead", "criar_contato",
                    "registrar_acao", "anexar_msg_a_lead", "arquivar_msg"
                ) and (a.get("result") or {}).get("ok")
                for a in actions_taken
            )
            if executou_acao_util and not perguntou_de_novo:
                try:
                    supabase.table("mensagens_socios").update({
                        "awaiting_user_response": False,
                        "status": "triado",
                        "triado_em": now_iso,
                        "triado_por": "Agente IA (thread resolvida)"
                    }).eq("telegram_chat_id", msg.get("telegram_chat_id")) \
                        .eq("telegram_message_id", replied_to) \
                        .execute()
                    print(f"✅ Thread resolvida: root tg_id={replied_to} marcada triado")
                except Exception as e:
                    print(f"⚠️ erro resolvendo thread root: {e}")

        # AUTO-ARQUIVAR: se a mensagem foi processada mas o agente nao gerou
        # NENHUMA acao util (so respondeu/comentou) e nao perguntou nada, arquiva
        # automaticamente pra nao poluir a Inbox. Mensagens como "ok", "valeu",
        # "ja criou a tarefa, esta tudo certo" caem aqui — sao confirmacoes do
        # socio, nao tem motivo pra ficar na inbox.
        fez_alguma_acao_de_dados = any(
            isinstance(a, dict) and a.get("action") in (
                "criar_tarefa", "criar_lead", "criar_contato",
                "registrar_acao", "anexar_msg_a_lead"
            ) and (a.get("result") or {}).get("ok")
            for a in actions_taken
        )
        perguntou = any(
            isinstance(a, dict) and a.get("action") == "perguntar_no_telegram"
            and (a.get("result") or {}).get("ok")
            for a in actions_taken
        )
        arquivou_explicitamente = any(
            isinstance(a, dict) and a.get("action") == "arquivar_msg"
            and (a.get("result") or {}).get("ok")
            for a in actions_taken
        )
        if not fez_alguma_acao_de_dados and not perguntou and not arquivou_explicitamente:
            try:
                supabase.table("mensagens_socios").update({
                    "status": "arquivado",
                    "triado_em": now_iso,
                    "triado_por": "Agente IA (sem acao necessaria)"
                }).eq("id", msg_id).execute()
                print(f"📦 Mensagem auto-arquivada (agente nao precisou agir)")
            except Exception as e:
                print(f"⚠️ erro auto-arquivando: {e}")

        update = {
            "ai_status": "processed",
            "ai_reasoning": final_summary or "Agente nao finalizou explicitamente",
            "ai_actions_taken": actions_taken,
            "ai_processed_at": datetime.now().isoformat()
        }
        # Mantem ai_proposed_action vazio (nao "proposta", executada)
        supabase.table("mensagens_socios").update(update).eq("id", msg_id).execute()
        print(f"🤖 Agente IA terminou msg {str(msg_id)[:8]}: {len(actions_taken)} ações — {final_summary or '(sem summary)'}")

    except Exception as e:
        print(f"❌ Agente IA falhou: {e}")
        try:
            supabase.table("mensagens_socios").update({
                "ai_status": "error",
                "ai_reasoning": f"Erro: {str(e)[:200]}",
                "ai_processed_at": datetime.now().isoformat()
            }).eq("id", msg_id).execute()
        except Exception:
            pass


def _mascara_id(valor):
    """Mascara IDs do Telegram em log, mantendo so os 4 ultimos digitos."""
    s = str(valor)
    if len(s) > 4:
        return "***" + s[-4:]
    return "****"


def _extrai_anexo(message):
    """Extrai (tipo, file_id) de uma mensagem Telegram. Retorna (None, None) se nao tem anexo."""
    if not isinstance(message, dict):
        return None, None
    if message.get("photo"):
        photos = message["photo"]
        if isinstance(photos, list) and photos:
            # photo vem como array crescente de tamanhos; o maior fica no final
            return "photo", photos[-1].get("file_id")
    for tipo in ("voice", "audio", "video", "document", "sticker"):
        anexo = message.get(tipo)
        if isinstance(anexo, dict):
            return tipo, anexo.get("file_id")
    return None, None


@app.route("/webhook/telegram", methods=["POST"])
def webhook_telegram():
    """Recebe updates do bot Telegram dos socios e grava em mensagens_socios.

    Seguranca:
    - Header X-Telegram-Bot-Api-Secret-Token == TELEGRAM_WEBHOOK_SECRET.
    - chat_id deve bater com TELEGRAM_ALLOWED_CHAT_ID (grupo dos socios).
    - Idempotente por (telegram_chat_id, telegram_message_id).
    """
    if not TELEGRAM_WEBHOOK_SECRET:
        print("⚠️ webhook_telegram: TELEGRAM_WEBHOOK_SECRET nao configurado")
        return jsonify({"error": "webhook nao configurado"}), 503

    if not hmac.compare_digest(request.headers.get("X-Telegram-Bot-Api-Secret-Token", ""), TELEGRAM_WEBHOOK_SECRET):
        print(f"🚫 webhook_telegram: secret invalido de {request.remote_addr}")
        return jsonify({"error": "nao autorizado"}), 401

    update = request.get_json(silent=True) or {}
    message = update.get("message") or update.get("edited_message") or update.get("channel_post")
    if not isinstance(message, dict):
        # Updates sem message (ex.: callback_query) — confirma 200 pra Telegram nao reenviar
        return jsonify({"status": "ignorado"}), 200

    chat_id = (message.get("chat") or {}).get("id")
    message_id = message.get("message_id")
    if chat_id is None or message_id is None:
        return jsonify({"error": "payload incompleto"}), 400

    # Whitelist do grupo dos socios — bloqueia chats desconhecidos
    if TELEGRAM_ALLOWED_CHAT_ID:
        try:
            if int(chat_id) != int(TELEGRAM_ALLOWED_CHAT_ID):
                print(f"🚫 webhook_telegram: chat {_mascara_id(chat_id)} fora da whitelist")
                return jsonify({"status": "ignorado"}), 200
        except (TypeError, ValueError):
            print("⚠️ TELEGRAM_ALLOWED_CHAT_ID invalido — esperado inteiro")

    if not supabase:
        print("⚠️ webhook_telegram: supabase offline, descartando update")
        return jsonify({"error": "db offline"}), 503

    # Idempotencia: se ja existe, retorna 200 sem reinserir
    try:
        existing = supabase.table("mensagens_socios").select("id") \
            .eq("telegram_chat_id", chat_id) \
            .eq("telegram_message_id", message_id) \
            .limit(1).execute()
        if existing.data:
            return jsonify({"status": "ja processado"}), 200
    except Exception as e:
        print(f"webhook_telegram: erro checando idempotencia: {e}")
        # Segue — o unique constraint do banco e a rede de seguranca final

    sender = message.get("from") or {}
    attachment_type, attachment_file_id = _extrai_anexo(message)
    nome_completo = (str(sender.get("first_name") or "") + " " + str(sender.get("last_name") or "")).strip()

    # Se o socio respondeu a uma mensagem do bot, descobre a thread root
    # (a primeira mensagem do socio que iniciou a conversa).
    reply_to = message.get("reply_to_message") or {}
    thread_root_id = None
    if reply_to and (reply_to.get("from") or {}).get("is_bot"):
        bot_msg_telegram_id = reply_to.get("message_id")
        try:
            bot_row = supabase.table("mensagens_socios").select("replied_to_telegram_message_id") \
                .eq("telegram_chat_id", chat_id) \
                .eq("telegram_message_id", bot_msg_telegram_id) \
                .eq("from_bot", True).limit(1).execute()
            if bot_row.data:
                thread_root_id = bot_row.data[0].get("replied_to_telegram_message_id")
        except Exception as e:
            print(f"webhook_telegram: erro lookup thread root: {e}")

    # Continuacao DETERMINISTICA: se existe mensagem do mesmo socio nesse chat
    # com awaiting_user_response=true, essa nova mensagem e a resposta a pergunta
    # pendente do bot. TTL de 15 min evita "thread zumbi".
    if thread_root_id is None and supabase and sender.get("id"):
        try:
            # Usa UTC explicito pra evitar mismatch de timezone com timestamptz do Postgres
            from datetime import timezone as _tz
            cutoff_awaiting = (datetime.now(_tz.utc) - timedelta(minutes=15)).isoformat()
            aguardando = supabase.table("mensagens_socios").select("telegram_message_id, created_at") \
                .eq("telegram_chat_id", chat_id) \
                .eq("telegram_user_id", sender.get("id")) \
                .eq("from_bot", False) \
                .eq("awaiting_user_response", True) \
                .gte("created_at", cutoff_awaiting) \
                .order("telegram_message_id", desc=True) \
                .limit(1).execute()
            data = aguardando.data or []
            print(f"🔍 awaiting lookup: chat={chat_id} user={sender.get('id')} cutoff={cutoff_awaiting} → {len(data)} match(es)")
            if data:
                thread_root_id = data[0]["telegram_message_id"]
                print(f"🧵 Thread aguardando resposta: msg {_mascara_id(message_id)} → root {_mascara_id(thread_root_id)}")
        except Exception as e:
            print(f"❌ webhook_telegram: erro awaiting lookup: {e}")

    registro = {
        "telegram_message_id": message_id,
        "telegram_chat_id": chat_id,
        "telegram_user_id": sender.get("id"),
        "sender_name": nome_completo or None,
        "sender_username": sender.get("username"),
        "text": message.get("text") or message.get("caption"),
        "attachment_type": attachment_type,
        "attachment_file_id": attachment_file_id,
        "raw_payload": update,
        "status": "inbox",
        "replied_to_telegram_message_id": thread_root_id
    }

    try:
        result = supabase.table("mensagens_socios").insert(registro).execute()
        inserted_id = result.data[0]["id"] if result.data else None
        print(f"✅ telegram gravado: msg {_mascara_id(message_id)} chat {_mascara_id(chat_id)}")
        try:
            audit("create", "mensagens_socios", inserted_id, "telegram webhook")
        except Exception as audit_err:
            print(f"audit falhou (nao bloqueia): {audit_err}")
        # Dispara classificacao IA em background — nao bloqueia o webhook
        if openai_client and inserted_id:
            threading.Thread(target=classify_message_with_ai, args=(inserted_id,), daemon=True).start()
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        print(f"webhook_telegram: erro inserindo: {e}")
        # Responde 200 pra Telegram nao entrar em loop de retry
        return jsonify({"status": "erro interno", "saved": False}), 200


# ============================================================
# API: MENSAGENS DOS SOCIOS (Inbox — base para o Kanban no passo 2)
# ============================================================

@app.route("/api/mensagens-socios")
@login_required
def api_mensagens_socios():
    if not supabase:
        return jsonify([])
    status_filter = request.args.get("status")
    include_bot = request.args.get("include_bot") == "1"
    try:
        query = supabase.table("mensagens_socios").select("*").order("created_at", desc=True).limit(200)
        if status_filter:
            query = query.eq("status", status_filter)
        if not include_bot:
            query = query.eq("from_bot", False)
        result = query.execute()
        return jsonify(result.data or [])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/mensagens-socios/<msg_id>", methods=["PATCH"])
@login_required
@role_can_write
def api_update_mensagem_socio(msg_id):
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    data = request.json or {}
    # So aceita mudar campos de triagem — payload bruto e ids do Telegram sao imutaveis
    permitido = {k: v for k, v in data.items() if k in ("status", "tarefa_id", "lead_id")}
    if data.get("status") in ("triado", "arquivado"):
        permitido["triado_em"] = datetime.now().isoformat()
        permitido["triado_por"] = session.get("display_name", "sistema")
    if not permitido:
        return jsonify({"error": "nenhum campo permitido para atualizar"}), 400
    try:
        result = supabase.table("mensagens_socios").update(permitido).eq("id", msg_id).execute()
        audit("update", "mensagens_socios", msg_id, f"campos: {list(permitido.keys())}")
        return jsonify(result.data[0] if result.data else {})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/mensagens-socios/<msg_id>/aprovar-ia", methods=["POST"])
@login_required
@role_can_write
def api_aprovar_ia(msg_id):
    """Executa a acao proposta pela IA. Usado pelo botao 'Aprovar sugestao' na Caixa."""
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    row = supabase.table("mensagens_socios").select("*").eq("id", msg_id).limit(1).execute()
    if not row.data:
        return jsonify({"error": "mensagem nao encontrada"}), 404
    msg = row.data[0]
    if msg.get("ai_status") != "processed":
        return jsonify({"error": "IA ainda nao processou essa mensagem"}), 400

    action = msg.get("ai_proposed_action")
    payload = msg.get("ai_payload") or {}
    user = session.get("display_name", "sistema")
    now = datetime.now().isoformat()
    triado_por = f"{user} (IA)"

    try:
        if action == "criar_tarefa":
            tarefa_data = {
                "titulo": (payload.get("titulo") or "(sem titulo)")[:200],
                "descricao": payload.get("descricao") or msg.get("text"),
                "responsavel": payload.get("responsavel") or user,
                "data_vencimento": payload.get("data_vencimento") or hoje_br(),
                "hora": payload.get("hora"),
                "prioridade": payload.get("prioridade") or "media",
                "tipo": payload.get("tipo") or "outro",
                "lead_id": payload.get("lead_id"),
                "status": "aberta"
            }
            result = supabase.table("tarefas").insert(tarefa_data).execute()
            new_id = result.data[0]["id"] if result.data else None
            supabase.table("mensagens_socios").update({
                "status": "triado",
                "tarefa_id": new_id,
                "lead_id": payload.get("lead_id"),
                "triado_em": now,
                "triado_por": triado_por
            }).eq("id", msg_id).execute()
            audit("create", "tarefas", new_id, f"Aprovado pela IA: {tarefa_data['titulo']}")
            return jsonify({"ok": True, "action": action, "tarefa_id": new_id}), 201

        if action == "criar_nota_em_lead":
            sender = msg.get("sender_name") or msg.get("sender_username") or "socio"
            anotacao = payload.get("anotacao") or msg.get("text") or ""
            nota_data = {
                "lead_id": payload.get("lead_id"),
                "tipo": "anotacao",
                "descricao": f"[Telegram, {sender}] {anotacao}",
                "responsavel": user
            }
            result = supabase.table("historico_acoes").insert(nota_data).execute()
            new_id = result.data[0]["id"] if result.data else None
            supabase.table("mensagens_socios").update({
                "status": "triado",
                "lead_id": payload.get("lead_id"),
                "triado_em": now,
                "triado_por": triado_por
            }).eq("id", msg_id).execute()
            audit("create", "historico_acoes", new_id, "Aprovado pela IA (nota)")
            return jsonify({"ok": True, "action": action, "historico_id": new_id}), 201

        if action == "anexar_a_lead":
            supabase.table("mensagens_socios").update({
                "status": "triado",
                "lead_id": payload.get("lead_id"),
                "triado_em": now,
                "triado_por": triado_por
            }).eq("id", msg_id).execute()
            audit("update", "mensagens_socios", msg_id, "Anexada a lead pela IA")
            return jsonify({"ok": True, "action": action})

        if action == "arquivar":
            supabase.table("mensagens_socios").update({
                "status": "arquivado",
                "triado_em": now,
                "triado_por": triado_por
            }).eq("id", msg_id).execute()
            audit("update", "mensagens_socios", msg_id, "Arquivada pela IA")
            return jsonify({"ok": True, "action": action})

        # nao_fazer_nada ou desconhecida
        return jsonify({"error": f"acao nao executavel: {action}"}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/mensagens-socios/<msg_id>/reclassificar", methods=["POST"])
@login_required
@role_can_write
def api_reclassificar_ia(msg_id):
    """Reroda a classificacao IA. Util quando os leads mudaram ou o agente foi atualizado."""
    if not openai_client:
        return jsonify({"error": "Agente IA desligado (OPENAI_API_KEY ausente)"}), 503
    threading.Thread(target=classify_message_with_ai, args=(msg_id,), daemon=True).start()
    return jsonify({"ok": True, "msg": "reclassificacao disparada em background"}), 202


# ============================================================
# LEMBRETE DE TAREFAS ATRASADAS (Telegram — 1x/dia às 08h BR)
# ============================================================

def _tarefas_atrasadas():
    """Tarefas não concluídas, vencidas antes de hoje (fuso BR) e não arquivadas."""
    if not supabase:
        return []
    try:
        r = supabase.table("tarefas").select(
            "id, titulo, responsavel, data_vencimento, leads(nome)"
        ).is_null("deleted_at").eq("concluida", False).lt("data_vencimento", hoje_br()).order("data_vencimento").execute()
        return r.data or []
    except Exception as e:
        print(f"⚠️ _tarefas_atrasadas erro: {e}")
        return []


def _formata_lembrete_atrasadas(tarefas):
    """Texto HTML do lembrete, agrupado por responsável, com dias de atraso."""
    from collections import defaultdict
    por_resp = defaultdict(list)
    for t in tarefas:
        por_resp[t.get("responsavel") or "Sem responsável"].append(t)
    hoje_dt = datetime.strptime(hoje_br(), "%Y-%m-%d")
    linhas = [f"⏰ <b>Tarefas atrasadas</b> ({len(tarefas)})"]
    for resp in sorted(por_resp):
        linhas.append(f"\n👤 <b>{resp}</b>")
        for t in por_resp[resp]:
            try:
                dias = (hoje_dt - datetime.strptime(t.get("data_vencimento") or "", "%Y-%m-%d")).days
                atraso = f" <i>({dias}d)</i>" if dias > 0 else ""
            except Exception:
                atraso = ""
            titulo = (t.get("titulo") or "(sem título)").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            lead = (t.get("leads") or {}).get("nome")
            lead_txt = f" — {lead}" if lead else ""
            linhas.append(f"  • {titulo}{lead_txt}{atraso}")
    return "\n".join(linhas)


def enviar_lembrete_atrasadas():
    """Manda o resumo de tarefas atrasadas no Telegram. Silencioso se não houver."""
    tarefas = _tarefas_atrasadas()
    if not tarefas:
        print("⏰ [LEMBRETE] Nenhuma tarefa atrasada — nada a enviar")
        return
    enviado = send_telegram_message(_formata_lembrete_atrasadas(tarefas))
    print(f"⏰ [LEMBRETE] {len(tarefas)} atrasada(s) — enviado: {bool(enviado)}")


def _segundos_ate(hora=8, minuto=0):
    """Segundos da hora atual até o próximo horário alvo no fuso BR."""
    agora = datetime.now(BR_TZ)
    alvo = agora.replace(hour=hora, minute=minuto, second=0, microsecond=0)
    if alvo <= agora:
        alvo += timedelta(days=1)
    return (alvo - agora).total_seconds()


def _task_reminder_loop():
    """Dispara o lembrete uma vez por dia às 08h (fuso BR)."""
    import time as _time
    while True:
        try:
            _time.sleep(_segundos_ate(8, 0))
            enviar_lembrete_atrasadas()
            _time.sleep(60)  # passa do minuto alvo p/ não recalcular pro mesmo horário
        except Exception as e:
            print(f"⚠️ task_reminder_loop erro: {e}")
            _time.sleep(3600)


def start_task_reminder():
    """Inicia a thread do lembrete diário. Desliga sozinho se o Telegram não estiver configurado."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_ALLOWED_CHAT_ID:
        print("⏰ [LEMBRETE] Telegram não configurado — lembrete de tarefas desligado")
        return
    threading.Thread(target=_task_reminder_loop, daemon=True, name="task-reminder").start()
    print("⏰ [LEMBRETE] Thread de lembrete de tarefas atrasadas iniciada (08h BR)")


# ============================================================
# BACKUP AUTOMÁTICO — snapshot diário em JSON p/ o bucket privado "backups"
# ============================================================
# Camada extra de segurança além do backup nativo do Supabase Pro (diário, gerenciado).
# Gera uma cópia lógica baixável pelos sócios. AO CRIAR TABELA NOVA, adicione aqui.
BACKUP_BUCKET = "backups"
BACKUP_RETENTION = int(os.getenv("BACKUP_RETENTION", "14"))  # nº de snapshots mantidos
BACKUP_HOUR = int(os.getenv("BACKUP_HOUR", "3"))             # hora BR do backup diário
BACKUP_TABLES = [
    "leads", "tarefas", "contratos", "documentos", "despesas", "receitas",
    "emprestimos", "contas_bancarias", "categorias_financeiras", "fornecedores",
    "contatos", "historico_acoes", "metas", "verticais", "crm_users", "anexos",
    "entidades", "mensagens_socios", "audit_log", "health_logs", "deploy_health",
    "onboarding_steps", "templates_email", "governo_dados", "supermercados_dados",
    "escolas_dados", "eventos_dados", "condominios_dados", "franquias_dados",
    "hoteis_dados", "saude_dados", "varejo_dados",
]


def _backup_headers(extra=None):
    h = {"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"}
    if extra:
        h.update(extra)
    return h


def _fetch_all_rows(table, page=1000):
    """Lê TODAS as linhas de uma tabela via PostgREST, paginando por Range
    (o PostgREST limita a resposta; sem paginar o backup ficaria truncado)."""
    rows, start = [], 0
    while True:
        resp = requests.get(
            f"{SUPABASE_URL}/rest/v1/{table}?select=*",
            headers=_backup_headers({"Range-Unit": "items", "Range": f"{start}-{start + page - 1}"}),
            timeout=30,
        )
        if resp.status_code not in (200, 206):
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:120]}")
        batch = resp.json()
        rows.extend(batch)
        if len(batch) < page:
            return rows
        start += page


def _prune_backups():
    """Mantém só os últimos BACKUP_RETENTION snapshots no bucket."""
    try:
        resp = requests.post(
            f"{SUPABASE_URL}/storage/v1/object/list/{BACKUP_BUCKET}",
            headers=_backup_headers({"Content-Type": "application/json"}),
            json={"prefix": "", "limit": 1000, "sortBy": {"column": "name", "order": "asc"}},
            timeout=30,
        )
        if resp.status_code >= 400:
            return
        nomes = sorted(o["name"] for o in (resp.json() or []) if o.get("name", "").startswith("backup_"))
        excedentes = nomes[:-BACKUP_RETENTION] if len(nomes) > BACKUP_RETENTION else []
        if excedentes:
            requests.delete(
                f"{SUPABASE_URL}/storage/v1/object/{BACKUP_BUCKET}",
                headers=_backup_headers({"Content-Type": "application/json"}),
                json={"prefixes": excedentes}, timeout=30,
            )
            print(f"💾 [BACKUP] removidos {len(excedentes)} backups antigos")
    except Exception as e:
        print(f"💾 [BACKUP] prune erro: {e}")


def run_backup():
    """Gera o snapshot JSON de todas as tabelas e sobe no bucket privado."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        return {"ok": False, "error": "Supabase não configurado"}
    meta = {}
    dados = {}
    for t in BACKUP_TABLES:
        try:
            linhas = _fetch_all_rows(t)
            dados[t] = linhas
            meta[t] = len(linhas)
        except Exception as e:
            meta[t] = f"erro: {e}"
            print(f"💾 [BACKUP] erro lendo {t}: {e}")
    snapshot = {"_meta": {"gerado_em": datetime.now(BR_TZ).isoformat(), "tabelas": meta}, "dados": dados}
    payload = json.dumps(snapshot, ensure_ascii=False, default=str).encode("utf-8")

    ts = datetime.now(BR_TZ).strftime("%Y%m%d_%H%M%S")
    path = f"backup_{ts}.json"
    up = requests.post(
        f"{SUPABASE_URL}/storage/v1/object/{BACKUP_BUCKET}/{path}",
        headers=_backup_headers({"Content-Type": "application/json"}),
        data=payload, timeout=90,
    )
    if up.status_code >= 400:
        return {"ok": False, "error": up.text[:200]}
    _prune_backups()
    print(f"💾 [BACKUP] snapshot salvo: {path} ({len(payload)} bytes)")
    return {"ok": True, "path": path, "bytes": len(payload), "tabelas": meta}


def _backup_loop():
    """Roda o backup uma vez por dia na hora configurada (fuso BR)."""
    import time as _time
    while True:
        try:
            _time.sleep(_segundos_ate(BACKUP_HOUR, 0))
            run_backup()
            _time.sleep(60)  # passa do minuto alvo
        except Exception as e:
            print(f"💾 [BACKUP] loop erro: {e}")
            _time.sleep(3600)


def start_backup_job():
    """Inicia a thread de backup diário. Desliga sozinho se o Supabase não estiver configurado."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        print("💾 [BACKUP] Supabase não configurado — backup desligado")
        return
    threading.Thread(target=_backup_loop, daemon=True, name="backup").start()
    print(f"💾 [BACKUP] Thread de backup diário iniciada ({BACKUP_HOUR}h BR, mantém {BACKUP_RETENTION})")


@app.route("/api/backup/run", methods=["POST"])
@login_required
@admin_required
def api_backup_run():
    """Dispara um backup manual agora (admin)."""
    res = run_backup()
    audit("backup", "backups", None, f"Backup manual: {res.get('path', 'falhou')}")
    return jsonify(res), (200 if res.get("ok") else 500)


@app.route("/api/backup/list")
@login_required
@admin_required
def api_backup_list():
    """Lista os snapshots existentes no bucket (mais recente primeiro)."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        return jsonify([])
    try:
        resp = requests.post(
            f"{SUPABASE_URL}/storage/v1/object/list/{BACKUP_BUCKET}",
            headers=_backup_headers({"Content-Type": "application/json"}),
            json={"prefix": "", "limit": 1000, "sortBy": {"column": "name", "order": "desc"}},
            timeout=30,
        )
        if resp.status_code >= 400:
            return jsonify({"error": resp.text[:150]}), 500
        itens = [
            {"name": o["name"], "size": (o.get("metadata") or {}).get("size"), "created_at": o.get("created_at")}
            for o in (resp.json() or []) if o.get("name", "").startswith("backup_")
        ]
        return jsonify(itens)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/backup/file/<path:filename>")
@login_required
@admin_required
def api_backup_file(filename):
    """URL assinada (10 min) para download do snapshot — admin only."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        return jsonify({"error": "Storage não configurado"}), 503
    try:
        resp = requests.post(
            f"{SUPABASE_URL}/storage/v1/object/sign/{BACKUP_BUCKET}/{filename}",
            headers=_backup_headers({"Content-Type": "application/json"}),
            json={"expiresIn": 600}, timeout=15,
        )
        if resp.status_code >= 400:
            return jsonify({"error": "Backup não encontrado"}), 404
        signed = resp.json().get("signedURL") or resp.json().get("signedUrl")
        if not signed:
            return jsonify({"error": "Falha ao assinar URL"}), 500
        return redirect(f"{SUPABASE_URL}/storage/v1{signed}")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# LIXEIRA — soft-delete reversível (admin)
# ============================================================
# Tabelas com soft-delete e qual coluna usar como título do item na Lixeira.
SOFT_DELETE_TABLES = {
    "leads":      {"label": "Lead",      "title": "nome"},
    "tarefas":    {"label": "Tarefa",    "title": "titulo"},
    "documentos": {"label": "Documento", "title": "titulo"},
    "despesas":   {"label": "Despesa",   "title": "descricao"},
    "receitas":   {"label": "Receita",   "title": "descricao"},
}


@app.route("/api/lixeira")
@login_required
@admin_required
def api_lixeira():
    """Lista os itens arquivados (deleted_at != null) das tabelas com soft-delete."""
    if not supabase:
        return jsonify([])
    itens = []
    for tabela, meta in SOFT_DELETE_TABLES.items():
        try:
            r = supabase.table(tabela).select(
                f"id, deleted_at, deleted_by, {meta['title']}"
            ).not_null("deleted_at").order("deleted_at", desc=True).execute()
            for row in (r.data or []):
                itens.append({
                    "tabela": tabela,
                    "tipo": meta["label"],
                    "id": row.get("id"),
                    "titulo": row.get(meta["title"]) or "(sem título)",
                    "deleted_at": row.get("deleted_at"),
                    "deleted_by": row.get("deleted_by"),
                })
        except Exception as e:
            print(f"⚠️ api_lixeira erro em {tabela}: {e}")
    itens.sort(key=lambda x: x.get("deleted_at") or "", reverse=True)
    return jsonify(itens)


@app.route("/api/lixeira/restaurar", methods=["POST"])
@login_required
@admin_required
def api_lixeira_restaurar():
    """Restaura um item arquivado (deleted_at = null)."""
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    data = request.json or {}
    tabela = data.get("tabela")
    row_id = data.get("id")
    if tabela not in SOFT_DELETE_TABLES or not row_id:
        return jsonify({"error": "tabela ou id inválido"}), 400
    try:
        supabase.table(tabela).update({"deleted_at": None, "deleted_by": None}).eq("id", row_id).execute()
        audit("restore", tabela, row_id, "Restaurado da Lixeira")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/lixeira/<tabela>/<row_id>", methods=["DELETE"])
@login_required
@admin_required
def api_lixeira_excluir_definitivo(tabela, row_id):
    """Exclusão DEFINITIVA (hard delete) de item já na Lixeira. Irreversível."""
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    if tabela not in SOFT_DELETE_TABLES:
        return jsonify({"error": "tabela inválida"}), 400
    try:
        # Só apaga se já estiver arquivado — barreira contra hard-delete de item ativo
        atual = supabase.table(tabela).select("id, deleted_at").eq("id", row_id).limit(1).execute()
        if not atual.data:
            return jsonify({"error": "não encontrado"}), 404
        if not atual.data[0].get("deleted_at"):
            return jsonify({"error": "item não está na Lixeira"}), 400
        supabase.table(tabela).delete().eq("id", row_id).execute()
        audit("delete", tabela, row_id, "Exclusão definitiva da Lixeira")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# E-MAIL DA EMPRESA (IMAP/SMTP — caixa contato@nodedata.com.br)
# ============================================================
# Stdlib pura (imaplib/smtplib/email). Sem armazenar a caixa em massa: a INBOX
# e lida AO VIVO via IMAP. So vira registro persistido quando um socio vincula
# um e-mail a um lead ou envia resposta (grava em historico_acoes). Decisao de
# minimizacao de dados — a caixa carrega correspondencia de prefeitura (LGPD).
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS", "")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
EMAIL_IMAP_HOST = os.getenv("EMAIL_IMAP_HOST", "imap.hostinger.com")
EMAIL_IMAP_PORT = int(os.getenv("EMAIL_IMAP_PORT", "993"))
EMAIL_SMTP_HOST = os.getenv("EMAIL_SMTP_HOST", "smtp.hostinger.com")
EMAIL_SMTP_PORT = int(os.getenv("EMAIL_SMTP_PORT", "465"))
EMAIL_DISPLAY_NAME = os.getenv("EMAIL_DISPLAY_NAME", "Node Data")

if EMAIL_ADDRESS and EMAIL_PASSWORD:
    print(f"📧 E-mail configurado ({EMAIL_ADDRESS} via {EMAIL_IMAP_HOST})")
else:
    print("⚠️ EMAIL_ADDRESS/EMAIL_PASSWORD ausentes — modulo de e-mail desligado (CRM segue normal)")

# Cache leve da INBOX em memoria — evita rebater IMAP a cada clique. TTL curto.
_inbox_cache = {"data": None, "ts": None}
_INBOX_TTL_SECONDS = 60

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _email_enabled():
    return bool(EMAIL_ADDRESS and EMAIL_PASSWORD)


def _valid_email(addr):
    return bool(addr and _EMAIL_RE.match(addr.strip()))


def _mask_email(addr):
    """Mascara o local-part pra log (LGPD). 'joao@x.com' -> 'j***@x.com'."""
    addr = (addr or "").strip()
    if "@" not in addr:
        return "***"
    local, _, domain = addr.partition("@")
    return f"{local[:1]}***@{domain}"


def _decode_mime(raw):
    """Decodifica header MIME (assunto/nome) pra str legivel. Nunca levanta."""
    if not raw:
        return ""
    try:
        return str(make_header(decode_header(raw)))
    except Exception:
        return str(raw)


def _imap_login():
    """Abre conexao IMAP4_SSL logada. Quem chama e responsavel por .logout()."""
    ctx = ssl.create_default_context()
    conn = imaplib.IMAP4_SSL(EMAIL_IMAP_HOST, EMAIL_IMAP_PORT, ssl_context=ctx, timeout=20)
    conn.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    return conn


def _decode_payload(part):
    """Texto de uma parte MIME, respeitando charset. Nunca levanta."""
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, "ignore")
    except Exception:
        return ""


def _extract_bodies(msg):
    """Extrai (texto_plano, html) de uma mensagem, ignorando anexos."""
    text, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            disp = str(part.get("Content-Disposition") or "").lower()
            if "attachment" in disp:
                continue
            ctype = part.get_content_type()
            if ctype == "text/plain" and not text:
                text = _decode_payload(part)
            elif ctype == "text/html" and not html:
                html = _decode_payload(part)
    else:
        payload = _decode_payload(msg)
        if msg.get_content_type() == "text/html":
            html = payload
        else:
            text = payload
    return text, html


def _date_to_iso(raw):
    try:
        return parsedate_to_datetime(raw).isoformat()
    except Exception:
        return raw or ""


def _fetch_inbox(limit=40):
    """Le os ultimos `limit` e-mails da INBOX ao vivo (so headers — rapido).
    Retorna lista de dicts, mais recentes primeiro. Levanta em falha de conexao."""
    conn = _imap_login()
    try:
        conn.select("INBOX", readonly=True)
        typ, data = conn.uid("search", None, "ALL")
        if typ != "OK" or not data or not data[0]:
            return []
        uids = data[0].split()
        recent = uids[-limit:]
        if not recent:
            return []
        uid_set = b",".join(recent)
        typ, msg_data = conn.uid(
            "fetch", uid_set,
            "(FLAGS BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)])"
        )
        if typ != "OK":
            return []
        items = []
        for part in msg_data:
            if not isinstance(part, tuple) or len(part) < 2:
                continue
            envelope = part[0]
            env_str = envelope.decode("utf-8", "ignore") if isinstance(envelope, bytes) else str(envelope)
            uid_m = re.search(r"UID (\d+)", env_str)
            if not uid_m:
                continue
            uid = int(uid_m.group(1))
            try:
                flags = imaplib.ParseFlags(envelope)
            except Exception:
                flags = ()
            flags_norm = [f.decode() if isinstance(f, bytes) else f for f in flags]
            seen = "\\Seen" in flags_norm
            hdr = message_from_bytes(part[1])
            from_name, from_addr = parseaddr(_decode_mime(hdr.get("From", "")))
            items.append({
                "uid": uid,
                "from_name": from_name or from_addr,
                "from_addr": (from_addr or "").lower(),
                "subject": _decode_mime(hdr.get("Subject", "")) or "(sem assunto)",
                "date": _date_to_iso(hdr.get("Date", "")),
                "message_id": (hdr.get("Message-ID") or "").strip(),
                "seen": seen,
            })
        items.sort(key=lambda x: x["uid"], reverse=True)
        return items
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def _fetch_message(uid, mark_seen=True):
    """Corpo completo de uma mensagem por UID. Marca como lida por padrao."""
    conn = _imap_login()
    try:
        conn.select("INBOX")
        typ, msg_data = conn.uid("fetch", str(uid).encode(), "(BODY.PEEK[])")
        if typ != "OK" or not msg_data or not isinstance(msg_data[0], tuple):
            return None
        msg = message_from_bytes(msg_data[0][1])
        from_name, from_addr = parseaddr(_decode_mime(msg.get("From", "")))
        text, html = _extract_bodies(msg)
        if mark_seen:
            try:
                conn.uid("store", str(uid).encode(), "+FLAGS", "\\Seen")
            except Exception:
                pass
        return {
            "uid": int(uid),
            "from_name": from_name or from_addr,
            "from_addr": (from_addr or "").lower(),
            "to": _decode_mime(msg.get("To", "")),
            "subject": _decode_mime(msg.get("Subject", "")) or "(sem assunto)",
            "date": _date_to_iso(msg.get("Date", "")),
            "message_id": (msg.get("Message-ID") or "").strip(),
            "references": (msg.get("References") or "").strip(),
            "body_text": text,
            "body_html": html,
        }
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def _send_email(to_addr, subject, body_text, in_reply_to=None, references=None):
    """Envia e-mail via SMTP_SSL. Retorna o Message-ID. Levanta em falha."""
    msg = EmailMessage()
    msg["From"] = formataddr((EMAIL_DISPLAY_NAME, EMAIL_ADDRESS))
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    mid = make_msgid()
    msg["Message-ID"] = mid
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = references or in_reply_to
    msg.set_content(body_text)
    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL(EMAIL_SMTP_HOST, EMAIL_SMTP_PORT, timeout=20, context=ctx) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)
    return mid


def _inbox_cached(force=False):
    now = datetime.now()
    cache = _inbox_cache
    if not force and cache["data"] is not None and cache["ts"]:
        if (now - cache["ts"]).total_seconds() < _INBOX_TTL_SECONDS:
            return cache["data"]
    data = _fetch_inbox()
    cache["data"] = data
    cache["ts"] = now
    return data


def _leads_by_email():
    """Mapa {email_lower: {id, nome}} dos leads — pra casar remetente <-> lead."""
    out = {}
    if not supabase:
        return out
    try:
        r = supabase.table("leads").select("id, nome, email").is_null("deleted_at").limit(1000).execute()
        for l in (r.data or []):
            em = (l.get("email") or "").strip().lower()
            if em:
                out[em] = {"id": l["id"], "nome": l.get("nome")}
    except Exception:
        pass
    return out


@app.route("/api/emails")
@login_required
def api_emails():
    """Lista a INBOX ao vivo. ?lead_id=<id> filtra pelo endereco do lead.
    ?refresh=1 ignora o cache de 60s."""
    if not _email_enabled():
        return jsonify({"error": "E-mail não configurado", "disabled": True}), 503
    try:
        items = _inbox_cached(force=request.args.get("refresh") == "1")
    except Exception as e:
        print(f"⚠️ api_emails erro IMAP: {e}")
        return jsonify({"error": "Não foi possível conectar à caixa de e-mail"}), 502

    leads_map = _leads_by_email()
    for it in items:
        match = leads_map.get(it.get("from_addr") or "")
        it["lead_id"] = match["id"] if match else None
        it["lead_nome"] = match["nome"] if match else None

    lead_id = request.args.get("lead_id")
    if lead_id:
        lead_email = ""
        if supabase:
            try:
                r = supabase.table("leads").select("email").eq("id", lead_id).limit(1).execute()
                lead_email = ((r.data[0].get("email") if r.data else "") or "").strip().lower()
            except Exception:
                pass
        if not lead_email:
            return jsonify([])
        items = [it for it in items if it.get("from_addr") == lead_email]

    return jsonify(items)


@app.route("/api/emails/<uid>")
@login_required
def api_email_detail(uid):
    if not _email_enabled():
        return jsonify({"error": "E-mail não configurado"}), 503
    if not uid.isdigit():
        return jsonify({"error": "UID inválido"}), 400
    try:
        msg = _fetch_message(uid)
    except Exception as e:
        print(f"⚠️ api_email_detail erro: {e}")
        return jsonify({"error": "Falha ao abrir e-mail"}), 502
    if not msg:
        return jsonify({"error": "E-mail não encontrado"}), 404
    _inbox_cache["ts"] = None  # marcou como lido — invalida cache da lista
    return jsonify(msg)


@app.route("/api/emails/enviar", methods=["POST"])
@login_required
@role_can_write
def api_email_enviar():
    if not _email_enabled():
        return jsonify({"error": "E-mail não configurado"}), 503
    data = request.json or {}
    to_addr = (data.get("to") or "").strip()
    subject = (data.get("subject") or "").strip()
    body = (data.get("body") or "").strip()
    if not _valid_email(to_addr):
        return jsonify({"error": "Destinatário inválido"}), 400
    if not subject:
        return jsonify({"error": "Assunto vazio"}), 400
    if not body:
        return jsonify({"error": "Corpo vazio"}), 400
    try:
        mid = _send_email(
            to_addr, subject, body,
            in_reply_to=(data.get("in_reply_to") or "").strip() or None,
            references=(data.get("references") or "").strip() or None,
        )
    except Exception as e:
        print(f"⚠️ envio SMTP falhou para {_mask_email(to_addr)}: {e}")
        return jsonify({"error": "Falha ao enviar e-mail"}), 502

    # Persiste no historico do lead so quando o envio esta vinculado a um lead
    lead_id = data.get("lead_id")
    if lead_id and supabase:
        try:
            supabase.table("historico_acoes").insert({
                "lead_id": lead_id,
                "tipo": "email_enviado",
                "descricao": f"E-mail enviado: {subject}"[:300],
                "resultado": body[:500],
                "responsavel": session.get("display_name", ""),
            }).execute()
        except Exception as e:
            print(f"⚠️ historico email_enviado: {e}")

    audit("create", "emails", lead_id, f"E-mail enviado p/ {_mask_email(to_addr)}: {subject[:60]}")
    _inbox_cache["ts"] = None
    return jsonify({"ok": True, "message_id": mid})


@app.route("/api/emails/vincular", methods=["POST"])
@login_required
@role_can_write
def api_email_vincular():
    """Vincula um e-mail RECEBIDO a um lead, gravando em historico_acoes."""
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    data = request.json or {}
    lead_id = data.get("lead_id")
    if not lead_id:
        return jsonify({"error": "lead_id obrigatório"}), 400
    subject = (data.get("subject") or "(sem assunto)").strip()
    from_addr = (data.get("from_addr") or "").strip()
    snippet = (data.get("snippet") or "")[:500]
    try:
        supabase.table("historico_acoes").insert({
            "lead_id": lead_id,
            "tipo": "email_recebido",
            "descricao": f"E-mail recebido de {from_addr}: {subject}"[:300],
            "resultado": snippet,
            "responsavel": session.get("display_name", ""),
        }).execute()
        audit("create", "historico_acoes", lead_id, f"E-mail vinculado: {subject[:60]}")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    ensure_admin_exists()
    start_health_monitor()
    start_task_reminder()
    start_backup_job()
    port = int(os.getenv("PORT", 5010))
    print(f"🚀 CRM Node Data running on port {port}")
    if supabase:
        print("📦 Using Supabase database")
    else:
        print("⚠️ Running without database!")
    app.run(host="0.0.0.0", port=port, debug=os.getenv("FLASK_ENV") != "production")
