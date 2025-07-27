from typing import List
from fastapi import FastAPI, Form, UploadFile, HTTPException
from app.schemas import ProjectResponse, DependencyResponse
from app.services.project_service import create_project
from app.storage import dependencies, projects
from app.utils import project_severity

app = FastAPI(title="OSV FastAPI Vulnerability Tracker")


@app.post("/projects", response_model=ProjectResponse)
async def add_project(
    name: str = Form(...),
    description: str = Form(...),
    file: UploadFile = None
):
    # Enforce file upload validation
    requirements = []
    if file:
        requirements = (await file.read()).decode().splitlines()
    elif not file:
        raise HTTPException(status_code=422, detail="requirements.txt file is required")

    project = await create_project(name, description, requirements)
    vulns = [v for dep in project.requirements for v in dependencies[dep].vulnerabilities]

    return ProjectResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        vulnerable=any([dependencies[d].vulnerable for d in project.requirements]),
        severity=project_severity(vulns)
    )


@app.get("/projects", response_model=List[ProjectResponse])
async def list_projects():
    responses = []
    for p in projects.values():
        vulns = [v for dep in p.requirements for v in dependencies[dep].vulnerabilities]
        responses.append(ProjectResponse(
            id=p.id,
            name=p.name,
            description=p.description,
            vulnerable=any([dependencies[d].vulnerable for d in p.requirements]),
            severity=project_severity(vulns)
        ))
    return responses


@app.get("/projects/{project_id}/dependencies", response_model=List[DependencyResponse])
async def project_deps(project_id: str):
    p = projects.get(project_id)
    if not p:
        raise HTTPException(status_code=404, detail="Project not found")
    return [dependencies[d] for d in p.requirements]


@app.get("/dependencies", response_model=List[DependencyResponse])
async def all_deps():
    return list(dependencies.values())


@app.get("/dependencies/{name}", response_model=DependencyResponse)
async def dep_details(name: str):
    dep = dependencies.get(name)
    if not dep:
        raise HTTPException(status_code=404, detail="Dependency not found")
    return dep
