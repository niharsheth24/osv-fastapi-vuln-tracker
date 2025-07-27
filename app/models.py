from pydantic import BaseModel
from typing import List, Dict, Any

class Dependency(BaseModel):
    name: str
    vulnerable: bool
    vulnerabilities: List[Dict[str, Any]]

class Project(BaseModel):
    id: str
    name: str
    description: str
    requirements: List[str]
