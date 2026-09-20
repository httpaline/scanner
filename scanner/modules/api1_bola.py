from itertools import combinations

from models import Endpoint, RawFinding, TestContext

async def run(endpoints: list[Endpoint], credentials: TestContext, http_client) -> list[RawFinding]:
  findings = []

  testable_endpoints = [e for e in endpoints if e.method == "GET" and e.path_params]
  non_admin_identities = [i for i in credentials.identities if not i.is_admin] 

  candidate_ids = [1,2,3,4,5]  
  
  for identity_a, identity_b in combinations(non_admin_identities, 2):
    for endpoint in testable_endpoints:
      for candidate_id in candidate_ids:
        url = endpoint.path.replace("{" + endpoint.path_params[0] + "}", str(candidate_id))

        evidence_a = await http_client.authenticated_request("GET", url, identity_a)
        if evidence_a.response.status_code != 200:
          continue

        evidence_b = await http_client.authenticated_request("GET", url, identity_b)
        if evidence_b.response.status_code == 200:
          findings.append(RawFinding(
            signal="cross_user_read_success",
            category="API1",
            endpoint=endpoint,
            evidence=evidence_b,
          ))
  return findings
