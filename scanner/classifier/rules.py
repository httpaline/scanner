from dataclasses import dataclass
from models import Severity, Signal 

@dataclass(frozen=True)
class Rule:
  vulnerability: str
  severity: Severity
  
RULES = {
  Signal.CROSS_USER_READ_SUCCESS: Rule("Broken Object Level Authorization", Severity.HIGH),
}  
  