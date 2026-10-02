from models import RawFinding, Signal

CANDIDATE_IDS = [1, 2, 3, 4, 5]


async def run(endpoints, credentials, http_client) -> list[RawFinding]:
  findings = []

  writable_endpoints = [e for e in endpoints if e.method in ("PUT", "PATCH") and e.path_params]
  non_admin_identities = [i for i in credentials.identities if not i.is_admin]

  for endpoint in writable_endpoints:
    for identity in non_admin_identities:
      for candidate_id in CANDIDATE_IDS:
        url = endpoint.path.replace("{" + endpoint.path_params[0] + "}", str(candidate_id))
        body = {"name": "Mass Assignment Test", "is_admin": True}

        evidence = await http_client.authenticated_request(endpoint.method, url, identity, json_body=body)
        if evidence.response.status_code != 200:
          continue

        response_body = evidence.response.body
        if isinstance(response_body, dict) and response_body.get("is_admin") is True:
          findings.append(RawFinding(
            signal=Signal.MASS_ASSIGNMENT_PRIVILEGE_ESCALATION,
            category="API3",
            endpoint=endpoint,
            evidence=evidence,
          ))
        break

  return findings
