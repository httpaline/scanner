from models import RawFinding, Signal

TRACEBACK_MARKER = "Traceback (most recent call last)"


async def run(endpoints, credentials, http_client) -> list[RawFinding]:
  findings = []

  get_endpoints = [e for e in endpoints if e.method == "GET" and not e.path_params]

  for endpoint in get_endpoints:
    evidence = await http_client.request("GET", endpoint.path)
    body = evidence.response.body
    if isinstance(body, str) and TRACEBACK_MARKER in body:
      findings.append(RawFinding(
        signal=Signal.VERBOSE_ERROR_STACK_TRACE,
        category="API8",
        endpoint=endpoint,
        evidence=evidence,
      ))

  return findings
