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
                    "responsavel": {"type": "string", "enum": ["Joao", "Guilherme", "Marcos"]},
                    "data_vencimento": {"type": "string", "description": "Data ISO YYYY-MM-DD. Calcule de DATA DE HOJE pra termos relativos (amanha, sexta, semana que vem)."},
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
            "name": "arquivar_msg",
            "description": "Arquiva a mensagem (triviais, brincadeiras, emojis sozinhos, conversa solta sem valor de negocio).",
            "parameters": {"type": "object", "properties": {}, "required": []}
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


def _build_agent_system_prompt():
    """Prompt do agente — descreve empresa, sociedade, leads existentes, verticais
    e workflow esperado. Como muda pouco entre chamadas, OpenAI usa prompt caching
    automatico (50% off no input cacheado quando >1024 tokens).
    """
    leads_data, verticais_data = [], []
    if supabase:
        try:
            r = supabase.table("leads").select("id, nome, status, cidade, estado, verticais(nome)").limit(500).execute()
            leads_data = r.data or []
        except Exception:
            pass
        try:
            r = supabase.table("verticais").select("id, nome, codigo").execute()
            verticais_data = r.data or []
        except Exception:
            pass

    leads_str = "\n".join(
        f"- {l.get('nome', '?')} (id: {l['id']}, status: {l.get('status', '—')}, cidade: {l.get('cidade', '—')}/{l.get('estado', '—')}, vertical: {(l.get('verticais') or {}).get('nome', '—')})"
        for l in leads_data
    ) or "(nenhum lead cadastrado ainda)"

    verticais_str = "\n".join(
        f"- {v['nome']} (id: {v['id']}, codigo: {v.get('codigo', '—')})"
        for v in verticais_data
    ) or "(nenhuma vertical)"

    hoje = datetime.now().strftime("%Y-%m-%d")
    return f"""Voce e o AGENTE OPERACIONAL da Node Data — empresa que vende software de inteligencia (analise de sentimento de cidadaos via WhatsApp) para PREFEITURAS e CAMPANHAS POLITICAS.

Os 3 socios sao:
- Joao (dono, comercial e tecnico)
- Guilherme (socio)
- Marcos (socio)

VOCE TEM AUTONOMIA TOTAL para EXECUTAR acoes no CRM. Quando uma mensagem nova chega no grupo Telegram interno dos socios, voce deve:
1. Extrair TODAS as entidades mencionadas (clientes, pessoas, telefones, prazos, valores, assuntos).
2. Executar TODAS as acoes necessarias usando as tools (criar leads novos, criar contatos, registrar interacoes passadas, criar tarefas futuras).
3. SEMPRE chamar `finalizar` no final com um resumo curto.

VOCE NAO PROPOE — VOCE EXECUTA. Nao espera aprovacao.

DATA DE HOJE: {hoje}

LEADS EXISTENTES NO CRM (use o id exato quando referenciar):
{leads_str}

VERTICAIS DISPONIVEIS (use o id em criar_lead quando aplicavel):
{verticais_str}

WORKFLOW POR TIPO DE MENSAGEM:

A) Mensagem menciona NOVO cliente (ainda nao na lista de leads):
  1. buscar_lead(query=nome do cliente) — SEMPRE primeiro, pra evitar duplicata
  2. Se nao encontrou: criar_lead(nome, tipo, cidade, estado, ...). Para prefeituras tipo=governo. Para candidatos tipo=politico.
  3. Se a mensagem menciona PESSOAS com nome+telefone: criar_contato pra cada uma, vinculadas ao lead
  4. Se a mensagem conta acao JA ocorrida ("falei com", "mandei proposta"): registrar_acao no historico
  5. Se a mensagem pede acao FUTURA ("ligar amanha", "preparar X"): criar_tarefa
  6. finalizar(summary)

B) Mensagem menciona cliente EXISTENTE:
  1. Identifique o lead na lista acima pelo id
  2. Mesmas etapas 3-6 do caso A

C) Mensagem sem entidade clara mas com info util:
  - Use anexar_msg_a_lead se relevante a algum cliente
  - Caso contrario, deixe ela na inbox: chame so finalizar sem fazer nada

D) Mensagem trivial (bom dia, ok, "kk", emoji sozinho, brincadeira):
  - arquivar_msg + finalizar

REGRAS DE OURO:

- TITULO DE TAREFA: nunca copie a mensagem inteira. Faca curto e acionavel: "Ligar para Carlos sobre CPSI", "Preparar proposta Cianorte", "Visitar Atacaforte sexta".
- DATA RELATIVA: calcule sempre baseado em DATA DE HOJE acima.
- TELEFONE: extraia so digitos. "44 99154-8588" → "44991548588".
- RESPONSAVEL DEFAULT da tarefa: o socio que MANDOU a mensagem (nao assume Joao se Marcos mandou).
- Estado default: PR. Use outro so se a mensagem indicar.
- Tipo de lead: prefeitura/secretaria = "governo", empresa privada = "empresa", candidato = "politico".
- NUNCA invente lead_id. Use so o que veio da lista acima ou de criar_lead.
- Em duvida entre acao e nota: se tem prazo futuro = tarefa, se e fato passado = registrar_acao.

EXEMPLO:
mensagem: "falei com pessoal da prefeitura de Maringa, me passaram o contato do carlos 44 991548588, precisa ligar pra ele amanha sobre CPSI"

Workflow:
1. buscar_lead(query="Maringa") → []
2. criar_lead(nome="Prefeitura de Maringa", tipo="governo", cidade="Maringa", estado="PR")
3. criar_contato(lead_id=<acima>, nome="Carlos", telefone="44991548588")
4. registrar_acao(lead_id=<acima>, tipo="ligacao", descricao="Contato inicial com pessoal da prefeitura. Conseguiu o contato do Carlos.")
5. criar_tarefa(titulo="Ligar para Carlos sobre CPSI", lead_id=<acima>, responsavel="Marcos", data_vencimento="{hoje}", prioridade="alta", tipo="ligacao", descricao="Carlos passou-se via prefeitura de Maringa. Falar sobre CPSI.")
   (substitua a data_vencimento pela data de AMANHA calculada de DATA DE HOJE)
6. finalizar(summary="Criei lead Prefeitura de Maringa, contato Carlos, registrei a interacao e criei tarefa de ligacao pra amanha.")

Aja sempre. Voce e operacional, nao consultivo."""


def _execute_tool(tool_name, args, msg_row, msg_id, user_label="Agente IA"):
    """Executa uma tool no banco e retorna dict com {ok, ...} pro modelo continuar."""
    if not supabase:
        return {"ok": False, "error": "DB offline"}
    try:
        if tool_name == "buscar_lead":
            q = (args.get("query") or "").lower().strip()
            if not q:
                return {"ok": True, "matches": []}
            r = supabase.table("leads").select("id, nome, cidade, estado, status").limit(200).execute()
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
                "data_vencimento": args.get("data_vencimento") or datetime.now().strftime("%Y-%m-%d"),
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

        return {"ok": False, "error": f"tool desconhecida: {tool_name}"}

    except Exception as e:
        return {"ok": False, "error": str(e)}


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

        if not msg.get("text"):
            supabase.table("mensagens_socios").update({
                "ai_status": "skipped",
                "ai_reasoning": "Mensagem sem texto (apenas anexo).",
                "ai_processed_at": datetime.now().isoformat()
            }).eq("id", msg_id).execute()
            return

        system_prompt = _build_agent_system_prompt()
        sender = msg.get("sender_name") or msg.get("sender_username") or "socio"
        user_content = f"Mensagem de {sender} no grupo Telegram interno:\n\n{msg['text']}"

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content}
        ]
        actions_taken = []
        max_iter = 6
        final_summary = None

        for i in range(max_iter):
            completion = openai_client.chat.completions.create(
                model=OPENAI_MODEL,
                messages=messages,
                tools=AI_TOOLS,
                tool_choice="required",
                temperature=0.1,
                timeout=45
            )
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

    if request.headers.get("X-Telegram-Bot-Api-Secret-Token", "") != TELEGRAM_WEBHOOK_SECRET:
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
        "status": "inbox"
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
    try:
        query = supabase.table("mensagens_socios").select("*").order("created_at", desc=True).limit(200)
        if status_filter:
            query = query.eq("status", status_filter)
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
                "data_vencimento": payload.get("data_vencimento") or datetime.now().strftime("%Y-%m-%d"),
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
