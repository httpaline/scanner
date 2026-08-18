from dataclasses import dataclass, field
from enum import Enum

@dataclass
class Endpoint:
    method: str
    path: str
    path_params: list[str]
    query_params: list[str]
    request_body_schema: dict
    response_schema: dict
    requires_auth: bool
   
@dataclass
class RequestData:
    method: str
    url: str
    headers: dict
    body: dict | None = None  
   
@dataclass
class ResponseData:
    status_code: int
    headers: dict
    body: dict | str | None = None
    
@dataclass
class Evidence:
    request: RequestData
    response: ResponseData
    identity_label: str
    
@dataclass
class Identity:
    identity_label: str
    is_admin: bool
    username: str
    password: str

@dataclass
class TestContext:
    identities: list[Identity]
    
@dataclass
class RawFinding:
    signal: str
    category: str
    endpoint: Endpoint
    evidence: Evidence
    
class Severity(str, Enum):
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'    
    
@dataclass
class Finding:
    vulnerability: str
    category: str
    severity: Severity
    endpoint: Endpoint
    evidence: Evidence        
    
if __name__ == "__main__":
    req = RequestData(method="GET", url="/users/5", headers={"Authorization": "Bearer ..."})
    resp = ResponseData(status_code=200, headers={}, body={"id": 5, "name": "Maria"})
    ev = Evidence(request=req, response=resp, identity_label="usuario_b")
    print(ev)

    id_a = Identity(identity_label="usuario_a", is_admin=False, username="a", password="x")
    id_b = Identity(identity_label="usuario_b", is_admin=False, username="b", password="y")
    tc = TestContext(identities=[id_a, id_b])
    print(tc)
    
    endpoint = Endpoint(
        method="GET",
        path="/users/{id}",
        path_params=["id"],
        query_params=[],
        request_body_schema={},
        response_schema={},
        requires_auth=True,
    )

    raw = RawFinding(signal="cross_user_read_success", category="API1", endpoint=endpoint, evidence=ev)
    print(raw)

    finding = Finding(
        vulnerability="Broken Object Level Authorization",
        category="API1",
        severity=Severity.HIGH,
        endpoint=endpoint,
        evidence=ev,
    )
    print(finding)