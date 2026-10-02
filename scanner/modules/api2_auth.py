from models import RawFinding, Signal


async def run(endpoints, credentials, http_client) -> list[RawFinding]:
  findings = []

  login_endpoints = [e for e in endpoints if e.method == "POST" and "login" in e.path.lower()]

  for login_endpoint in login_endpoints:
    same_path_get = [e for e in endpoints if e.path == login_endpoint.path and e.method == "GET"]
    if not same_path_get:
      continue

    identity = credentials.identities[0]
    url = f"{login_endpoint.path}?username={identity.username}&password={identity.password}"
    evidence = await http_client.request("GET", url)

    if evidence.response.status_code == 200:
      findings.append(RawFinding(
        signal=Signal.CREDENTIALS_IN_QUERY_STRING,
        category="API2",
        endpoint=same_path_get[0],
        evidence=evidence,
      ))

  return findings
