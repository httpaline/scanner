import json
from models import Endpoint

def load_openapi_spec(path: str) -> list[Endpoint]:
  with open(path) as f:
    spec = json.load(f)
  
  endpoints = []
  for endpoint_path, methods in spec["paths"].items():
    for method, operation in methods.items():
      parameters = operation.get("parameters", [])
      path_params = [p["name"] for p in parameters if p["in"] == "path"]
      query_params = [p["name"] for p in parameters if p["in"] == "query"]
      request_body = operation.get("requestBody", {})
      request_body_schema = request_body.get("content", {}).get("application/json", {}).get("schema")
      responses = operation.get("responses", {})
      response_schema = {}
      
      for status_code, response in responses.items():
        if status_code.startswith("2"):
          response_schema = response.get("content", {}).get("application/json", {}).get("schema", {})
          break
        
      operation_security = operation.get("security")
      if operation_security is None:
        operation_security = spec.get("security", [])
      requires_auth = len(operation_security) > 0
      
      endpoints.append(
        Endpoint(
          method=method,
          path=endpoint_path,
          path_params=path_params,
          query_params=query_params,
          request_body_schema=request_body_schema,
          response_schema=response_schema,
          requires_auth=requires_auth,
        )
      )
 
  return endpoints

  
        