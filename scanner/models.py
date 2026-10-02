from dataclasses import dataclass
from pydantic import BaseModel, field_validator
from enum import Enum

class Endpoint(BaseModel):
    method: str
    path: str
    path_params: list[str]
    query_params: list[str]
    request_body_schema: dict | None = None
    response_schema: dict
    requires_auth: bool
   
@dataclass(frozen=True)
class RequestData:
    method: str
    url: str
    headers: dict
    body: dict | None = None  
   
@dataclass(frozen=True)
class ResponseData:
    status_code: int
    headers: dict
    body: dict | str | None = None
    
@dataclass(frozen=True)
class Evidence:
    request: RequestData
    response: ResponseData
    identity_label: str
    
class Identity(BaseModel):
    identity_label: str
    is_admin: bool
    username: str
    password: str

class TestContext(BaseModel):
    identities: list[Identity]
    @field_validator("identities")
    @classmethod
    def validate_quantity(cls, v):
        if not (2 <= len(v) <= 3):
            raise ValueError("Expecting between 2 or 3 identities.")
        return v
    
class Signal(str,Enum):
    CROSS_USER_READ_SUCCESS = "cross_user_read_success"
    CREDENTIALS_IN_QUERY_STRING = "credentials_in_query_string"     
       
@dataclass(frozen=True)
class RawFinding:
    signal: Signal
    category: str
    endpoint: Endpoint
    evidence: Evidence
  
class Severity(str, Enum):
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'    
    
@dataclass(frozen=True)
class Finding:
    vulnerability: str
    category: str
    severity: Severity
    endpoint: Endpoint
    evidence: list[Evidence]           
    
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

    raw = RawFinding(signal=Signal.CROSS_USER_READ_SUCCESS, category="API1", endpoint=endpoint, evidence=ev)
    print(raw)

    finding = Finding(
        vulnerability="Broken Object Level Authorization",
        category="API1",
        severity=Severity.HIGH,
        endpoint=endpoint,
        evidence=[ev],
    )
    print(finding)