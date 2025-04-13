import os
import logging
from logging.handlers import SysLogHandler
from flask import Flask, request, redirect, url_for, session, jsonify, render_template
from functools import wraps
from dotenv import load_dotenv

# Carrega variáveis do .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")

# Configuração de logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

if os.path.exists('/dev/log'):
    try:
        handler = SysLogHandler(address='/dev/log')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.info("Usando SysLogHandler via /dev/log")
    except Exception as e:
        print(f"Erro ao configurar SysLogHandler: {e}")
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.info("Fallback para StreamHandler")
else:
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.info("Syslog não disponível. Usando StreamHandler.")

logger.info("Aplicação iniciada.")

# Middleware de segurança
@app.after_request
def set_secure_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# Mock de banco de usuários baseado em .env
user_db = {}

def carregar_usuario_env():
    usuario = os.getenv("USUARIO")
    senha = os.getenv("SENHA")
    if usuario and senha:
        user_db[usuario] = {"username": usuario, "password": senha}
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
            logger.info(f"Usuário {username} autenticado com sucesso.")
            return redirect(url_for("home"))
        logger.warning("Tentativa de login falhou.")
        return render_template("login.html", message="Login falhou. Tente novamente.", user_hint=os.getenv("USUARIO"), pass_hint=os.getenv("SENHA"))

    return render_template("login.html", user_hint=os.getenv("USUARIO"), pass_hint=os.getenv("SENHA"))

@app.route("/logout")
def logout():
    session["logged_in"] = False
    logger.info("Usuário desconectado.")
    return redirect(url_for("login"))

@app.route("/")
@login_required
def home():
    logger.info("Rota '/' acessada com sucesso.")
    return "Bem-vindo! Você está autenticado."

# ---------------------
# CRUD de Usuários (Mock)
# ---------------------

@app.route("/users", methods=["GET"])
@login_required
def list_users():
    return jsonify(list(user_db.values()))

@app.route("/users", methods=["POST"])
@login_required
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    if username in user_db:
        return {"error": "Usuário já existe"}, 400
    user_db[username] = {"username": username, "password": password}
    logger.info(f"Usuário {username} criado.")
    return {"message": "Usuário criado"}, 201

@app.route("/users/<username>", methods=["GET"])
@login_required
def get_user(username):
    user = user_db.get(username)
    if not user:
        return {"error": "Usuário não encontrado"}, 404
    return user

@app.route("/users/<username>", methods=["PUT"])
@login_required
def update_user(username):
    data = request.json
    if username not in user_db:
        return {"error": "Usuário não encontrado"}, 404
    user_db[username]["password"] = data.get("password", user_db[username]["password"])
    logger.info(f"Usuário {username} atualizado.")
    return {"message": "Usuário atualizado"}

@app.route("/users/<username>", methods=["DELETE"])
@login_required
def delete_user(username):
    if username in user_db:
        del user_db[username]
        logger.info(f"Usuário {username} deletado.")
        return {"message": "Usuário deletado"}
    return {"error": "Usuário não encontrado"}, 404

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
