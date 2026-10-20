"""API Security tests (OWASP Top 10): SQLi, XSS, Broken Access Control, Misconfiguration.

Проверяемый файл задаётся переменной окружения APP_FILE (по умолчанию app.py),
что позволяет прогнать те же тесты на уязвимой версии before/app_v1.py.
"""
import importlib.util
import os
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
APP_FILE = ROOT / os.environ.get("APP_FILE", "app.py")
TOKEN = "test-token"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("API_TOKEN", TOKEN)
    spec = importlib.util.spec_from_file_location(f"app_{uuid.uuid4().hex}", APP_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.app.config["TESTING"] = False
    c = module.app.test_client()
    for name, email in (("alice", "alice@test.com"), ("bob", "bob@test.com")):
        assert c.post("/api/users", json={"name": name, "email": email}).status_code == 201
    return c


# ---------- TC-03: SQL Injection (OWASP A03 Injection) ----------
@pytest.mark.parametrize("payload", [
    "' OR '1'='1",
    "%' OR 1=1 --",
    "x' UNION SELECT 1, sqlite_version(), 3 --",
])
def test_sqli_in_search_does_not_leak_data(client, payload):
    resp = client.get("/api/users", query_string={"name": payload})
    assert resp.status_code in (200, 400)
    if resp.status_code == 200:
        assert resp.get_json() == [], "инъекция вернула чужие записи"


def test_sqli_in_body_is_rejected_without_db_error(client):
    resp = client.post("/api/users", json={"name": "a'); DROP TABLE users; --",
                                           "email": "evil@test.com"})
    assert resp.status_code == 400
    assert len(client.get("/api/users").get_json()) == 2


def test_sqli_in_delete_path(client):
    resp = client.delete("/api/users/1 OR 1=1", headers={"X-API-Key": TOKEN})
    assert resp.status_code == 404
    assert len(client.get("/api/users").get_json()) == 2


# ---------- TC-04: XSS (OWASP A03 Injection) ----------
@pytest.mark.parametrize("payload", [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
])
def test_xss_payload_rejected_on_create(client, payload):
    resp = client.post("/api/users", json={"name": payload, "email": "x@test.com"})
    assert resp.status_code == 400


def test_responses_are_json_and_not_sniffable(client):
    resp = client.get("/api/users", query_string={"name": "<script>alert(1)</script>"})
    assert resp.mimetype == "application/json"
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert "Content-Security-Policy" in resp.headers


# ---------- OWASP A01: Broken Access Control ----------
def test_delete_requires_token(client):
    assert client.delete("/api/users/1").status_code == 401
    assert client.delete("/api/users/1", headers={"X-API-Key": "wrong"}).status_code == 401
    assert len(client.get("/api/users").get_json()) == 2


def test_delete_with_token(client):
    assert client.delete("/api/users/1", headers={"X-API-Key": TOKEN}).status_code == 200
    assert client.delete("/api/users/1", headers={"X-API-Key": TOKEN}).status_code == 404


# ---------- OWASP A05: Security Misconfiguration ----------
def test_errors_do_not_leak_internals(client):
    resp = client.post("/api/users", data="not json", content_type="application/json")
    body = resp.get_data(as_text=True)
    assert resp.status_code == 400
    for marker in ("Traceback", "sqlite3", "SELECT", "INSERT", "KeyError"):
        assert marker not in body
    resp = client.get("/api/users", query_string={"name": "'"})
    assert resp.status_code != 500
    assert "SELECT" not in resp.get_data(as_text=True)


@pytest.mark.parametrize("header", ["X-Frame-Options", "Referrer-Policy"])
def test_security_headers(client, header):
    assert header in client.get("/api/users").headers
