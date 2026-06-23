import pytest
import json
from src.cli import main as cli_main
from src.server import app
from fastapi.testclient import TestClient

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_cli_import():
    # Smoke test: ensure CLI can be imported without errors
    try:
        from src.cli import main
        assert callable(main)
    except ImportError:
        pytest.fail("CLI module not importable")