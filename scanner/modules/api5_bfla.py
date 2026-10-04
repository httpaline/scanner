from models import RawFinding, Signal


async def run(endpoints, credentials, http_client) -> list[RawFinding]:
  findings = []

  admin_endpoints = [e for e in endpoints if "admin" in e.path.lower() and e.requires_auth]
  non_admin_identities = [i for i in credentials.identities if not i.is_admin]

  for endpoint in admin_endpoints:
    for identity in non_admin_identities:
      evidence = await http_client.authenticated_request(endpoint.method, endpoint.path, identity)
      if evidence.response.status_code == 200:
        findings.append(RawFinding(
          signal=Signal.BROKEN_FUNCTION_LEVEL_AUTHORIZATION,
          category="API5",
          endpoint=endpoint,
          evidence=evidence,
        ))

  return findings
