from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from keelson_service.main import create_app


@pytest.fixture
def app() -> FastAPI:
    return create_app()


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())
