"""Testa o agente de demo localmente, SEM WhatsApp e SEM subir o Flask.

Uso:
    python testar_agente.py "quanto faturei esse mes e quantos leads em negociacao?"

Dependências (leves):  pip install openai python-dotenv requests
Precisa do .env com SUPABASE_URL, SUPABASE_KEY e OPENAI_API_KEY.

Este script NÃO importa o server.py (por isso não precisa de Flask). Ele monta
um mini-cliente Supabase REST só com o que o agente usa, igual ao do server.
"""
import os
import sys

import requests
from dotenv import load_dotenv

load_dotenv()


# --- Mini cliente Supabase REST (só os métodos que o agente_demo usa) ---
class _Tabela:
    def __init__(self, url, key, tabela):
        self.base = f"{url}/rest/v1/{tabela}"
        self.headers = {
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Prefer": "return=representation",
        }
        self.params = {}
        self.method = "GET"
        self.body = None

    def select(self, cols="*"):
        self.params["select"] = cols
        self.method = "GET"
        return self

    def insert(self, data):
        self.body = data
        self.method = "POST"
        return self

    def update(self, data):
        self.body = data
        self.method = "PATCH"
        return self

    def eq(self, col, val):
        self.params[col] = f"eq.{val}"
        return self

    def is_null(self, col):
        self.params[col] = "is.null"
        return self

    def limit(self, n):
        self.headers["Range"] = f"0-{n - 1}"
        return self

    def execute(self):
        try:
            r = requests.request(
                self.method, self.base, headers=self.headers,
                params=self.params, json=self.body, timeout=20,
            )
            if r.status_code >= 400:
                print(f"[Supabase {r.status_code}] {r.text[:200]}")
                return type("R", (), {"data": []})()
            d = r.json() if r.text else []
            return type("R", (), {"data": d if isinstance(d, list) else [d]})()
        except Exception as e:
            print(f"[Supabase erro] {e}")
            return type("R", (), {"data": []})()


class _SupabaseMini:
    def __init__(self, url, key):
        self.url = url
        self.key = key
        self.connected = bool(url and key)

    def table(self, name):
        return _Tabela(self.url, self.key, name)

    def __bool__(self):
        return self.connected


def main():
    url = os.getenv("SUPABASE_URL", "").rstrip("/")
    key = os.getenv("SUPABASE_KEY", "")
    okey = os.getenv("OPENAI_API_KEY", "")
    model = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")

    if not (url and key):
        print("❌ Falta SUPABASE_URL e/ou SUPABASE_KEY no .env")
        return
    if not okey:
        print("❌ Falta OPENAI_API_KEY no .env")
        return

    from openai import OpenAI
    from agente_demo import AgenteDemoCRM

    agente = AgenteDemoCRM(_SupabaseMini(url, key), OpenAI(api_key=okey), model)
    pergunta = " ".join(sys.argv[1:]).strip() or \
        "quanto faturei esse mes e quantos leads estao em negociacao?"
    print(f"\n🧑 {pergunta}\n" + "-" * 60)
    resposta = agente.responder(pergunta, remetente="João Marcos")
    print(f"🤖 {resposta}\n")


if __name__ == "__main__":
    main()
