import os
import logging
from logging.handlers import SysLogHandler
from flask import Flask, request, redirect, url_for, session
from functools import wraps

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'  # Alterar para uma chave segura

# Configuração de logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Tenta usar SysLogHandler, senão faz fallback para StreamHandler
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

logger.info("Aplicação iniciada.")  # Log de inicialização

# Autenticação básica simulada
users = {"usuario": "senha123"}

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
        if username in users and users[username] == password:
            session["logged_in"] = True
            logger.info(f"Usuário {username} autenticado com sucesso.")
            return redirect(url_for("home"))
        logger.warning("Tentativa de login falhou.")
        return "Login falhou. Tente novamente."
    return '''
    <form method="post">
        Usuário: <input type="text" name="username">
        Senha: <input type="password" name="password">
        <input type="submit">
    </form>
    '''

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

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
