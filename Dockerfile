FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5010

# Gunicorn (gerenciador de workers de produção) em vez do servidor de dev do Flask.
# A config (1 worker + threads, jobs de background) vive em gunicorn.conf.py.
CMD ["gunicorn", "-c", "gunicorn.conf.py", "server:app"]
