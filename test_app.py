import pytest
from app import User, bcrypt, create_app, db


@pytest.fixture
def app(tmp_path):
    application = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret-key",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'test.db'}",
        "RATELIMIT_ENABLED": False,
    })
    with application.app_context():
        db.drop_all()
        db.create_all()
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()


def csrf(client):
    response = client.get("/register")
    with client.session_transaction() as session:
        return session["csrf_token"]


def registration(client, token, password="StrongPassword!42"):
    return client.post("/register", data={
        "csrf_token": token, "full_name": "Test User", "username": "testuser",
        "email": "test@example.com", "password": password, "confirm_password": password,
    }, follow_redirects=True)


def test_registration_hashes_password_and_does_not_store_plaintext(client, app):
    response = registration(client, csrf(client))
    assert response.status_code == 200
    with app.app_context():
        user = db.session.query(User).filter_by(username="testuser").one()
        assert user.password_hash != "StrongPassword!42"
        assert bcrypt.check_password_hash(user.password_hash, "StrongPassword!42")


def test_login_dashboard_and_logout(client, app):
    registration(client, csrf(client))
    token = csrf(client)
    response = client.post("/login", data={"csrf_token": token, "identifier": "testuser", "password": "StrongPassword!42"}, follow_redirects=True)
    assert b"Welcome, Test User" in response.data
    with client.session_transaction() as session:
        assert "user_id" in session
    token = csrf(client)
    response = client.post("/logout", data={"csrf_token": token}, follow_redirects=True)
    assert b"securely logged out" in response.data
    assert client.get("/dashboard").status_code == 302


def test_invalid_login_message_is_generic(client):
    token = csrf(client)
    response = client.post("/login", data={"csrf_token": token, "identifier": "unknown", "password": "wrong"}, follow_redirects=True)
    assert b"Invalid username/email or password" in response.data
    assert b"unknown" not in response.data


def test_csrf_blocks_registration(client):
    response = client.post("/register", data={"full_name": "Bad", "username": "baduser", "email": "bad@example.com", "password": "StrongPassword!42", "confirm_password": "StrongPassword!42"}, follow_redirects=True)
    assert b"Invalid form security token" in response.data


def test_weak_password_rejected(client):
    response = registration(client, csrf(client), password="weak")
    assert b"at least 12 characters" in response.data
