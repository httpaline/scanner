from models import Finding, RawFinding
from classifier.rules import RULES

def classify(raw: RawFinding)-> Finding:
  rule =  RULES.get(raw.signal)
  if rule is None:
    raise ValueError(f"No classification rule for signal: {raw.signal}")
  
  return Finding(
    vulnerability=rule.vulnerability,
    category=raw.category,
    severity=rule.severity,
    endpoint=raw.endpoint,
    evidence=[raw.evidence],   
  )