from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from pentis_service.main import create_app


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())
