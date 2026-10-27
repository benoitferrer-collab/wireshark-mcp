import pytest
from cryptography.fernet import Fernet
from app.identity.settings import WebSettings

def configure(monkeypatch):
    values={'WEB_AUTH_ENABLED':'true','WEB_ENTRA_TENANT_ID':'4b0a3328-264b-4f04-a6e9-66b104b58487','WEB_ADMIN_OID':'65c6def3-d34c-414d-9d6e-a9266fa76264','WEB_ENTRA_CLIENT_ID':'11111111-1111-1111-1111-111111111111','WEB_ENTRA_CLIENT_SECRET':'secret','WEB_PUBLIC_ORIGIN':'https://app.example','DATABASE_URL':'postgresql://user:password@db.example/app?sslmode=require','WEB_SESSION_ENCRYPTION_KEY':Fernet.generate_key().decode(),'API_ACCESS_TOKEN':'x'*40,'CRON_SECRET':'y'*40}
    for key,value in values.items():monkeypatch.setenv(key,value)

def test_enabled_config_requires_tls_and_dedicated_cron_secret(monkeypatch):
    configure(monkeypatch)
    assert WebSettings.from_env().origin=='https://app.example'
    monkeypatch.setenv('DATABASE_URL','postgresql://user:password@db.example/app')
    with pytest.raises(ValueError):WebSettings.from_env()
    monkeypatch.setenv('DATABASE_URL','postgresql://user:password@db.example/app?sslmode=require')
    monkeypatch.setenv('CRON_SECRET','x'*40)
    with pytest.raises(ValueError):WebSettings.from_env()

def test_unconfigured_auth_stays_opt_in(monkeypatch):
    monkeypatch.delenv('WEB_AUTH_ENABLED',raising=False)
    assert WebSettings.from_env() is None
