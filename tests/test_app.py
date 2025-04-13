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

    # Testa login válido
    response = client.post('/login', data={
        'username': usuario,
        'password': senha
    }, follow_redirects=True)

    # Decodifica response.data para comparação com strings normais
    response_text = response.data.decode('utf-8')
    assert "Adicione uma agora" in response_text

def test_login_failure(client):
    usuario = os.getenv("USUARIO")  # Carrega do .env
    senha_errada = "senha_incorreta"

    # Testa login inválido
    response = client.post('/login', data={
        'username': usuario,
        'password': senha_errada
    })
    response_text = response.data.decode('utf-8')
    assert "Login falhou" in response_text

def test_protected_route_requires_login(client):
    response = client.get('/')
    assert response.status_code == 302
    assert '/login' in response.headers['Location']

def test_logout(client):
    usuario = os.getenv("USUARIO")  # Carrega do .env
    senha = os.getenv("SENHA")      # Carrega do .env

    # Testa logout após login
    client.post('/login', data={'username': usuario, 'password': senha})
    response = client.get('/logout', follow_redirects=True)

    # Decodifica response.data para comparação com strings normais
    response_text = response.data.decode('utf-8')
    assert "Usuário" in response_text
    assert "Usuário de teste" in response_text

def test_headers_seguranca(client):
    usuario = os.getenv("USUARIO")  # Carrega do .env
    senha = os.getenv("SENHA")      # Carrega do .env

    # Testa cabeçalhos de segurança
    client.post('/login', data={'username': usuario, 'password': senha})
    response = client.get('/', follow_redirects=True)
    assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    assert response.headers.get('X-Frame-Options') == 'DENY'
    assert response.headers.get('X-XSS-Protection') == '1; mode=block'
