import os
import logging
from logging.handlers import SysLogHandler, RotatingFileHandler
from flask import Flask, request, redirect, url_for, session, jsonify, render_template, Response
from functools import wraps
from dotenv import load_dotenv
from prometheus_client import Counter, Histogram, generate_latest

# Cria o diretório de logs se não existir
if not os.path.exists('logs'):
    os.makedirs('logs')

# Carrega variáveis do .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")

# Configuração de logger aprimorada
logger = logging.getLogger("TaskManagerLogger")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Define manipulação para SysLog e arquivo de log com fallback
if os.path.exists('/dev/log'):
    try:
        syslog_handler = SysLogHandler(address='/dev/log')
        syslog_handler.setFormatter(formatter)
        logger.addHandler(syslog_handler)
        logger.info("Usando SysLogHandler via /dev/log")
    except Exception as e:
        logger.error(f"Erro ao configurar SysLogHandler: {e}")

# Configura logs para arquivo local
log_file_handler = RotatingFileHandler('logs/task_manager.log', maxBytes=1000000, backupCount=5)
log_file_handler.setFormatter(formatter)
logger.addHandler(log_file_handler)
logger.info("Logs também gravados em logs/task_manager.log")

# Middleware de segurança
@app.after_request
def set_secure_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# Mock de banco de usuários e tarefas baseado em memória
user_db = {}
task_db = {}

def carregar_usuario_env():
    usuario = os.getenv("USUARIO")
    senha = os.getenv("SENHA")
    if usuario and senha:
        user_db[usuario] = {"username": usuario, "password": senha}
        task_db[usuario] = []
        logger.info("Usuário padrão carregado do .env.")
    else:
        logger.warning("USUARIO e SENHA não definidos no .env.")

carregar_usuario_env()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            logger.warning("Acesso negado: usuário não está autenticado.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = user_db.get(username)
        if user and user["password"] == password:
            session["logged_in"] = True
            session["username"] = username
            logger.info(f"Usuário {username} autenticado com sucesso.")
            return redirect(url_for("home_page"))  # Correção: usar "home_page"
        logger.warning("Tentativa de login falhou.")
        return render_template("login.html", message="Login falhou. Tente novamente.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    session.pop("username", None)
    logger.info("Usuário desconectado.")
    return redirect(url_for("login"))

# Contadores para monitorar requisições e tarefas
REQUEST_COUNT = Counter('app_requests_total', 'Total de requisições recebidas', ['method', 'endpoint'])
TASK_COUNT = Counter('tasks_created_total', 'Total de tarefas criadas')
REQUEST_LATENCY = Histogram('app_request_latency_seconds', 'Tempo de resposta por endpoint', ['endpoint'])

@app.before_request
def before_request():
    REQUEST_COUNT.labels(method=request.method, endpoint=request.path).inc()

@app.route('/metrics')
def metrics():
    return Response(generate_latest(), mimetype='text/plain')

# Página inicial com monitoramento de latência
@app.route("/")
@login_required
@REQUEST_LATENCY.labels(endpoint='/').time()
def home_page():
    username = session.get("username")
    user_tasks = task_db.get(username, [])
    logger.info(f"Usuário {username} acessou a página inicial.")
    return render_template("view_tasks.html", tasks=user_tasks)

@app.route("/add_task", methods=["GET", "POST"])
@login_required
@REQUEST_LATENCY.labels(endpoint='/add_task').time()
def add_task_page():
    if request.method == "POST":
        task_description = request.form.get("task")
        username = session.get("username")
        task_db[username].append(task_description)
        TASK_COUNT.inc()
        logger.info(f"Tarefa adicionada para usuário {username}: {task_description}")
        return redirect(url_for("home_page"))
    return render_template("add_task.html")

@app.route("/delete_task/<int:task_id>")
@login_required
def delete_task(task_id):
    username = session.get("username")
    user_tasks = task_db.get(username, [])
    if 0 <= task_id < len(user_tasks):
        deleted_task = user_tasks.pop(task_id)
        logger.info(f"Tarefa excluída para usuário {username}: {deleted_task}")
    return redirect(url_for("home_page"))

@app.route("/account_settings", methods=["GET", "POST"])
@login_required
def account_settings():
    username = session.get("username")
    if request.method == "POST":
        new_username = request.form.get("username")
        new_password = request.form.get("password")
        user_db.pop(username, None)
        user_db[new_username] = {"username": new_username, "password": new_password}
        task_db[new_username] = task_db.pop(username, [])
        session["username"] = new_username
        logger.info(f"Informações do usuário {username} atualizadas para {new_username}.")
        return redirect(url_for("home_page"))
    return render_template("account_settings.html", username=username)

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0")
