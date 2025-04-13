import pytest
from flask import session
from app import app as flask_app

@pytest.fixture
def client():
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False  # Desativa CSRF para facilitar o teste
    with flask_app.test_client() as client:
        yield client

def test_login_success(client):
    response = client.post('/login', data={
        'username': 'usuario',
        'password': 'senha123'
    }, follow_redirects=True)
    assert b'Bem-vindo! Voc\xc3\xaa est\xc3\xa1 autenticado.' in response.data

def test_login_failure(client):
    response = client.post('/login', data={
        'username': 'usuario',
        'password': 'senha_errada'
    })
    assert b'Login falhou' in response.data

def test_protected_route_requires_login(client):
    response = client.get('/')
    assert response.status_code == 302
    assert '/login' in response.headers['Location']

def test_logout(client):
    client.post('/login', data={'username': 'usuario', 'password': 'senha123'})
    response = client.get('/logout', follow_redirects=True)
    assert b'Usu\xc3\xa1rio: <input type="text" name="username">' in response.data

def test_headers_segurança(client):
    client.post('/login', data={'username': 'usuario', 'password': 'senha123'})
    response = client.get('/', follow_redirects=True)
    assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    assert response.headers.get('X-Frame-Options') == 'DENY'
    assert response.headers.get('X-XSS-Protection') == '1; mode=block'
