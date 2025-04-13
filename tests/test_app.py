import pytest
import os
from flask import session
from app import app as flask_app
from dotenv import load_dotenv

# Carrega variáveis do .env
load_dotenv()

@pytest.fixture
def client():
    # Configurações de teste
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False  # Desativa CSRF para facilitar o teste
    with flask_app.test_client() as client:
        yield client

def test_login_success(client):
    usuario = os.getenv("USUARIO")  # Carrega do .env
    senha = os.getenv("SENHA")      # Carrega do .env

    response = client.post('/login', data={
        'username': usuario,
        'password': senha
    }, follow_redirects=True)

    response_text = response.data.decode('utf-8')

    try:
        assert "Você ainda não tem tarefas" in response_text
    except AssertionError:
        pytest.fail(f"Erro: Texto esperado 'Você ainda não tem tarefas' não encontrado na resposta:\n{response_text}")

def test_login_failure(client):
    usuario = os.getenv("USUARIO")
    senha_errada = "senha_incorreta"

    response = client.post('/login', data={
        'username': usuario,
        'password': senha_errada
    })
    response_text = response.data.decode('utf-8')

    assert "Login falhou. Tente novamente." in response_text, f"Erro: Mensagem 'Login falhou. Tente novamente.' não encontrada na resposta:\n{response_text}"

def test_protected_route_requires_login(client):
    response = client.get('/')
    assert response.status_code == 302, f"Erro: Código de status esperado 302, recebido {response.status_code}"
    assert '/login' in response.headers['Location'], "Erro: Redirecionamento para /login não ocorreu."

def test_logout(client):
    usuario = os.getenv("USUARIO")
    senha = os.getenv("SENHA")

    client.post('/login', data={'username': usuario, 'password': senha})
    response = client.get('/logout', follow_redirects=True)
    response_text = response.data.decode('utf-8')

    assert "Usuário" in response_text, f"Erro: Texto 'Usuário' não encontrado na resposta:\n{response_text}"
    assert "Usuário de teste" in response_text, f"Erro: Texto 'Usuário de teste' não encontrado na resposta:\n{response_text}"

def test_headers_seguranca(client):
    usuario = os.getenv("USUARIO")
    senha = os.getenv("SENHA")

    client.post('/login', data={'username': usuario, 'password': senha})
    response = client.get('/', follow_redirects=True)

    assert response.headers.get('X-Content-Type-Options') == 'nosniff', "Erro: Cabeçalho 'X-Content-Type-Options' incorreto."
    assert response.headers.get('X-Frame-Options') == 'DENY', "Erro: Cabeçalho 'X-Frame-Options' incorreto."
    assert response.headers.get('X-XSS-Protection') == '1; mode=block', "Erro: Cabeçalho 'X-XSS-Protection' incorreto."
