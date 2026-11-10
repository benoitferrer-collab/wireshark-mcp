from fastapi.testclient import TestClient

def test_homepage_renders_with_current_starlette_template_signature(monkeypatch):
    from app.main import app, settings
    monkeypatch.setattr(settings, "max_file_size", 100 * 1024**2)
    with TestClient(app) as client:
        response = client.get('/')
        assert response.status_code == 200
        assert 'id="uploadArea"' in response.text
        assert "100 Mo maximum" in response.text
        assert 'id="supportBrief"' in response.text
        assert "/static/js/support-workspace.js?v=" in response.text
