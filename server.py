import sys
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

import os
import json
import secrets
import requests
import threading
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv

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

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if os.getenv("FLASK_ENV") == "production":
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


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


# ============================================================
# AUTH ROUTES
# ============================================================

@app.route("/login", methods=["GET", "POST"])
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

        try:
            result = supabase.table("crm_users").select("*").eq("username", username).eq("active", True).execute()
            if result.data and len(result.data) == 1:
                user = result.data[0]
                if check_password_hash(user["password_hash"], password):
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
                    error = "Senha incorreta."
                    audit("login", details=f"Senha incorreta para: {username}")
            else:
                error = "Usuário não encontrado."
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
        leads = supabase.table("leads").select("id, status, valor_mensal, valor_setup, valor_fechado, created_at, vertical_id").execute()
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
        tarefas = supabase.table("tarefas").select("id, concluida, data_vencimento").eq("concluida", False).execute()
        pending_tasks = len(tarefas.data or [])
        overdue = 0
        for t in (tarefas.data or []):
            if t.get("data_vencimento") and t["data_vencimento"] < now.strftime("%Y-%m-%d"):
                overdue += 1

        # Contratos ativos
        contratos = supabase.table("contratos").select("id, status, valor").execute()
        contratos_ativos = sum(1 for c in (contratos.data or []) if c.get("status") == "ativo")
        receita_contratos = sum(float(c.get("valor", 0)) for c in (contratos.data or []) if c.get("status") == "ativo")

        return jsonify({
            "total_leads": total,
            "leads_by_status": by_status,
            "mrr": mrr,
            "total_fechado": total_fechado,
            "new_this_month": new_this_month,
            "pending_tasks": pending_tasks,
            "overdue_tasks": overdue,
            "contratos_ativos": contratos_ativos,
            "receita_contratos": receita_contratos
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
        ).order("created_at", desc=True).execute()
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
        supabase.table("leads").delete().eq("id", lead_id).execute()
        audit("delete", "leads", lead_id, f"Deletado: {nome}")
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
            "*, leads(nome, status)"
        ).order("data_vencimento").execute()
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
    if data.get("concluida"):
        data["concluida_em"] = datetime.now().isoformat()
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
        supabase.table("tarefas").delete().eq("id", tarefa_id).execute()
        audit("delete", "tarefas", tarefa_id)
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
        ).order("created_at", desc=True).execute()
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


@app.route("/api/upload", methods=["POST"])
@login_required
@role_can_write
def api_upload_file():
    """Upload arquivo para Supabase Storage e retorna URL pública."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        return jsonify({"error": "Storage não configurado"}), 503

    if "file" not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Arquivo sem nome"}), 400

    # Gerar nome único
    import uuid
    ext = f.filename.rsplit(".", 1)[-1] if "." in f.filename else "bin"
    safe_name = f"{int(datetime.now().timestamp())}_{uuid.uuid4().hex[:8]}.{ext}"

    try:
        # Upload via Supabase Storage REST API
        upload_url = f"{SUPABASE_URL}/storage/v1/object/documentos/{safe_name}"
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

        # URL pública
        public_url = f"{SUPABASE_URL}/storage/v1/object/public/documentos/{safe_name}"
        audit("upload", "documentos", None, f"Upload: {f.filename} -> {safe_name}")
        return jsonify({"url": public_url, "filename": safe_name}), 201

    except Exception as e:
        return jsonify({"error": f"Falha no upload: {str(e)}"}), 500


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
        supabase.table("documentos").delete().eq("id", doc_id).execute()
        audit("delete", "documentos", doc_id)
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
        result = supabase.table("despesas").select("*, verticais(nome, icone, codigo)").order("data", desc=True).execute()
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


@app.route("/api/despesas/<despesa_id>", methods=["DELETE"])
@login_required
@role_can_write
def api_delete_despesa(despesa_id):
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    try:
        supabase.table("despesas").delete().eq("id", despesa_id).execute()
        audit("delete", "despesas", despesa_id)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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
        result = supabase.table("leads").select("id, nome, deploy_url, status, verticais(nome, icone)").execute()
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
        result = supabase.table("leads").select("id, nome, deploy_url").execute()
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


@app.route("/api/users", methods=["POST"])
@login_required
@admin_required
def api_create_user():
    if not supabase:
        return jsonify({"error": "DB offline"}), 503
    data = request.json
    password = data.pop("password", None)
    if not password or len(password) < 6:
        return jsonify({"error": "Senha deve ter pelo menos 6 caracteres"}), 400

    data["password_hash"] = generate_password_hash(password)
    try:
        result = supabase.table("crm_users").insert(data).execute()
        audit("create", "crm_users", details=f"Novo usuário: {data.get('username')}")
        return jsonify({"ok": True, "id": result.data[0]["id"] if result.data else None}), 201
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
# MAIN
# ============================================================

if __name__ == "__main__":
    ensure_admin_exists()
    start_health_monitor()
    port = int(os.getenv("PORT", 5010))
    print(f"🚀 CRM Node Data running on port {port}")
    if supabase:
        print("📦 Using Supabase database")
    else:
        print("⚠️ Running without database!")
    app.run(host="0.0.0.0", port=port, debug=os.getenv("FLASK_ENV") != "production")
