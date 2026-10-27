from fastapi.testclient import TestClient

def test_homepage_renders_with_current_starlette_template_signature():
    from app.main import app
    with TestClient(app) as client:
        response = client.get('/')
        assert response.status_code == 200
        assert 'id="uploadArea"' in response.text
