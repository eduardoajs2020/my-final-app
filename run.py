from flask import Flask, request, redirect, url_for, session
from functools import wraps

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'

users = {"usuario": "senha123"}  # Usuários e senhas simulados

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
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
            return redirect(url_for("home"))
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
    return redirect(url_for("login"))

@app.route("/")
@login_required
def home():
    return "Bem-vindo! Você está autenticado."

