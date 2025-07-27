import uuid
from app.models import Project, Dependency
from app.storage import dependencies, projects
from app.services.osv_service import batch_fetch_vulnerabilities


async def create_project(name: str, description: str, requirements: list) -> Project:
    project_id = str(uuid.uuid4())
    projects[project_id] = Project(id=project_id, name=name, description=description, requirements=[])

    # Normalize dependency names
    dep_names = [extract_dep_name(req) for req in requirements]

    vulns_data = await batch_fetch_vulnerabilities(dep_names)

    for dep_name, data in vulns_data.items():
        vulns = data.get("vulns", [])
        vulnerable = len(vulns) > 0
        dependencies[dep_name] = Dependency(
            name=dep_name,
            vulnerable=vulnerable,
            vulnerabilities=[{"score": v.get("score", 0), "id": v.get("id")} for v in vulns]
        )
        projects[project_id].requirements.append(dep_name)

    return projects[project_id]

def extract_dep_name(requirement_line: str) -> str:
    # Simple approach: split by "==", ">=", "<=", ">", "<" or space and take first token
    for sep in ["==", ">=", "<=", ">", "<", " "]:
        if sep in requirement_line:
            return requirement_line.split(sep)[0].strip()
    return requirement_line.strip()

