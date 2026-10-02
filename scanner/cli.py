import argparse
import asyncio
import json
from pathlib import Path

from classifier.severity import classify
from config.credentials_loader import load_credentials
from config.openapi_loader import load_openapi_spec
from http_client import HttpClient
from modules import api1_bola, api2_auth
from report.generator import generate_report

MODULES = [api1_bola, api2_auth]


def parse_args() -> argparse.Namespace:
  parser = argparse.ArgumentParser(description="REST API vulnerability scanner (OWASP API Top 10).")
  parser.add_argument("--spec", required=True, help="Path to the OpenAPI spec (JSON).")
  parser.add_argument("--credentials", required=True, help="Path to the test credentials (YAML).")
  parser.add_argument("--base-url", required=True, help="Base URL of the target API.")
  parser.add_argument("--login-path", required=True, help="Login endpoint path of the target API.")
  parser.add_argument("--token-field", default="token", help="JSON field holding the token in the login response.")
  parser.add_argument("--output", default="output/report.json", help="Where to write the JSON report.")
  return parser.parse_args()


async def run_scan(args: argparse.Namespace) -> dict:
  endpoints = load_openapi_spec(args.spec)
  credentials = load_credentials(args.credentials)

  raw_findings = []
  async with HttpClient(base_url=args.base_url, login_path=args.login_path, token_field=args.token_field) as client:
    for module in MODULES:
      raw_findings.extend(await module.run(endpoints, credentials, client))

  findings = [classify(raw) for raw in raw_findings]
  return generate_report(findings)


def main() -> None:
  args = parse_args()
  report = asyncio.run(run_scan(args))
  
  Path(args.output).parent.mkdir(parents=True, exist_ok=True)

  with open(args.output, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2)

  print(f"Report written to {args.output} ({report['summary']['total_findings']} findings)")


if __name__ == "__main__":
  main()
