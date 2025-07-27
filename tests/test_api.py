import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import httpx
from app.services.osv_service import fetch_vulnerability
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch, AsyncMock
from app.main import app
from app.utils import project_severity
from app.storage import dependencies
from app.models import Dependency

@pytest_asyncio.fixture(scope="module")
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

@pytest_asyncio.fixture
async def created_project(client, tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("flask==2.0.1\nrequests==2.31.0\n")
    with open(req_file, "rb") as f:
        files = {"file": f}
        data = {"name": "Security Test Project", "description": "Testing vulnerabilities"}
        response = await client.post("/projects", data=data, files=files)
    assert response.status_code == 200
    return response.json()["id"]

# ------------------- POSITIVE TEST CASES -------------------

@pytest.mark.asyncio
async def test_get_projects(client, created_project):
    response = await client.get("/projects")
    assert response.status_code == 200
    assert any(p["name"] == "Security Test Project" for p in response.json())

@pytest.mark.asyncio
async def test_get_project_dependencies(client, created_project):
    response = await client.get(f"/projects/{created_project}/dependencies")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_get_all_dependencies(client):
    response = await client.get("/dependencies")
    assert response.status_code == 200
    assert any(d["name"] == "flask" for d in response.json())


@pytest.mark.asyncio
async def test_get_specific_dependency(client):
    response = await client.get("/dependencies/flask")
    assert response.status_code == 200
    assert response.json()["name"] == "flask"


# ------------------- NEGATIVE TEST CASES -------------------

@pytest.mark.asyncio
async def test_create_project_without_file(client):
    data = {"name": "Invalid Project", "description": "No file uploaded"}
    response = await client.post("/projects", data=data)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_get_project_dependencies_invalid_id(client):
    response = await client.get("/projects/invalid-id/dependencies")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_get_specific_dependency_not_found(client):
    response = await client.get("/dependencies/some-random-dep")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_invalid_requirement_line(client, tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("this-is-not-valid")
    with open(req_file, "rb") as f:
        files = {"file": f}
        data = {"name": "Invalid Req Project", "description": "Invalid requirement"}
        response = await client.post("/projects", data=data, files=files)
    assert response.status_code == 200


@pytest.mark.parametrize("scores,expected", [
    ([9.0], "High"),
    ([7.5], "High"),
    ([5.0], "Medium"),
    ([3.5], "Low"),
    ([], "None"),
])
def test_project_severity_all_branches(scores, expected):
    vulns = [{"score": s} for s in scores]
    assert project_severity(vulns) == expected


@pytest.mark.asyncio
@patch("app.services.osv_service.fetch_vulnerability", return_value={"vulns": []})
async def test_project_with_no_vulnerabilities(mock_fetch, client, tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("safe-package==1.0.0")
    with open(req_file, "rb") as f:
        files = {"file": f}
        data = {"name": "Safe Project", "description": "No vulnerabilities expected"}
        response = await client.post("/projects", data=data, files=files)
    assert response.status_code == 200
    assert response.json()["severity"] == "None"

@pytest_asyncio.fixture(autouse=True)
def add_flask_dependency():
    dependencies["flask"] = Dependency(
        name="flask",
        vulnerabilities=[],
        vulnerable=False
    )

@pytest.mark.asyncio
@patch("httpx.AsyncClient.post", side_effect=httpx.RequestError("Connection error"))
async def test_fetch_vulnerability_request_error(mock_post):
    data = await fetch_vulnerability("failing-package")
    assert data == {"vulns": []}  # Should fallback to empty on error

@pytest.mark.asyncio
@patch("httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_fetch_vulnerability_invalid_score(mock_post):
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.json = lambda: {
        "vulns": [{"score": "invalid"}, {"score": None}]
    }
    mock_post.return_value = mock_response

    data = await fetch_vulnerability("weird-package")
    assert all(isinstance(v["score"], float) for v in data["vulns"])
