from dataclasses import dataclass
from models import Severity, Signal 

@dataclass(frozen=True)
class Rule:
  vulnerability: str
  severity: Severity
  
RULES = {
  Signal.CROSS_USER_READ_SUCCESS: Rule("Broken Object Level Authorization", Severity.HIGH),
  Signal.CREDENTIALS_IN_QUERY_STRING: Rule("Credentials in Query String", Severity.MEDIUM),
  Signal.MASS_ASSIGNMENT_PRIVILEGE_ESCALATION: Rule("Mass Assignment / Broken Object Property Level Authorization", Severity.HIGH),
}


  