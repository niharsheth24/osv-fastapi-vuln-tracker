from pydantic import BaseModel
from typing import List, Dict

class DependencyResponse(BaseModel):
    name: str
    vulnerable: bool
    vulnerabilities: List[Dict]


class ProjectResponse(BaseModel):
    id: str
    name: str
    description: str
    vulnerable: bool
    severity: str