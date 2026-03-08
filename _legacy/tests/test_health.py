from __future__ import annotations

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from keelson_service import __version__

# --- Synchronous tests using TestClient fixture from conftest.py ---


def test_health_status_code(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200


def test_health_status_is_ok(client: TestClient) -> None:
    response = client.get("/health")
    assert response.json()["status"] == "ok"


def test_health_version_key_present(client: TestClient) -> None:
    response = client.get("/health")
    assert "version" in response.json()


def test_health_version_value(client: TestClient) -> None:
    response = client.get("/health")
    assert response.json()["version"] == __version__


def test_health_content_type_json(client: TestClient) -> None:
    response = client.get("/health")
    assert "application/json" in response.headers["content-type"]


def test_health_response_shape(client: TestClient) -> None:
    response = client.get("/health")
    assert set(response.json().keys()) == {"status", "version"}


def test_unknown_route_returns_404(client: TestClient) -> None:
    response = client.get("/nonexistent")
    assert response.status_code == 404


def test_create_app_returns_fastapi_instance(app: FastAPI) -> None:
    assert isinstance(app, FastAPI)


# --- Async tests using httpx.AsyncClient with ASGITransport ---


async def test_health_async_status_code(app: FastAPI) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as ac:
        response = await ac.get("/health")
    assert response.status_code == 200


async def test_health_async_status_is_ok(app: FastAPI) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as ac:
        response = await ac.get("/health")
    assert response.json()["status"] == "ok"


async def test_health_async_version_present(app: FastAPI) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as ac:
        response = await ac.get("/health")
    assert "version" in response.json()
