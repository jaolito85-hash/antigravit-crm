# Configuração do Gunicorn para produção (Coolify/Docker).
#
# UM worker DE PROPÓSITO (concorrência vem das threads):
#  - O Health Monitor é uma thread em memória do processo. Com vários workers,
#    cada um iniciaria a thread → pings e alertas WhatsApp DUPLICADOS pros clientes.
#  - O rate limiter usa storage "memory://" — vários workers = contadores
#    inconsistentes (o limite real viraria 60 * nº de workers).
#  - O cache da caixa de e-mail também vive em memória do processo.
# Para o uso interno dos sócios, 1 worker + threads dá folga de sobra. Quando
# precisar escalar horizontalmente, migrar rate limiter + cache p/ Redis primeiro.
import os

bind = f"0.0.0.0:{os.getenv('PORT', '5010')}"
workers = 1
threads = int(os.getenv("GUNICORN_THREADS", "4"))
timeout = 120
graceful_timeout = 30
accesslog = "-"   # stdout — Coolify captura
errorlog = "-"
loglevel = os.getenv("GUNICORN_LOGLEVEL", "info")


def when_ready(server):
    """Sobe os jobs de background UMA única vez no master.
    O bloco `if __name__ == '__main__'` do server.py NÃO roda sob Gunicorn, então
    sem isto o Health Monitor não iniciaria e os alertas dos clientes parariam."""
    from server import ensure_admin_exists, start_health_monitor
    ensure_admin_exists()
    start_health_monitor()
    server.log.info("✅ ensure_admin + health monitor iniciados (when_ready)")
