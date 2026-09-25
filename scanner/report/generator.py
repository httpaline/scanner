from dataclasses import asdict

from models import Finding


def group_findings(findings: list[Finding]) -> list[Finding]:
  groups: dict[tuple, list[Finding]] = {}
  for finding in findings:
    key = (finding.category, finding.endpoint.method, finding.endpoint.path)
    groups.setdefault(key, []).append(finding)

  merged = []
  for group in groups.values():
    first = group[0]
    all_evidence = [ev for f in group for ev in f.evidence]
    merged.append(Finding(
      vulnerability=first.vulnerability,
      category=first.category,
      severity=first.severity,
      endpoint=first.endpoint,
      evidence=all_evidence,
    ))
  return merged


def finding_to_dict(finding: Finding) -> dict:
  return {
    "vulnerability": finding.vulnerability,
    "category": finding.category,
    "severity": finding.severity.value,
    "endpoint": finding.endpoint.model_dump(),
    "evidence": [asdict(ev) for ev in finding.evidence],
  }


def build_summary(findings: list[Finding]) -> dict:
  by_category = {}
  by_severity = {}

  for finding in findings:
    by_category[finding.category] = by_category.get(finding.category, 0) + 1
    by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1

  return {
    "total_findings": len(findings),
    "by_category": by_category,
    "by_severity": by_severity,
  }


def generate_report(findings: list[Finding]) -> dict:
  grouped = group_findings(findings)
  return {
    "summary": build_summary(grouped),
    "findings": [finding_to_dict(f) for f in grouped],
  }
