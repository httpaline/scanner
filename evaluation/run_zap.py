import json
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from run_scanner import BASE_URL, RUNS, start_api

ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = ROOT / "evaluation" / "results" / "zap"
ZAP_IMAGE = "zaproxy/zap-stable"
ZAP_IDENTITY = {"username": "usuario_a", "password": "senha_teste_a"}


def obtain_token() -> str:
  body = json.dumps(ZAP_IDENTITY).encode()
  request = urllib.request.Request(
    f"{BASE_URL}/auth/login", data=body, headers={"Content-Type": "application/json"}
  )
  with urllib.request.urlopen(request) as response:
    return json.loads(response.read())["token"]


def ensure_authenticated(token: str) -> None:
  request = urllib.request.Request(
    f"{BASE_URL}/users/1", headers={"Authorization": f"Bearer {token}"}
  )
  try:
    with urllib.request.urlopen(request) as response:
      status = response.status
  except urllib.error.HTTPError as error:
    status = error.code
  if status != 200:
    raise RuntimeError(f"Authenticated precheck failed (status {status}); the token is not accepted by the API.")


def replacer_options(token: str) -> str:
  return (
    "-config replacer.full_list(0).description=auth1 "
    "-config replacer.full_list(0).enabled=true "
    "-config replacer.full_list(0).matchtype=REQ_HEADER "
    "-config replacer.full_list(0).matchstr=Authorization "
    "-config replacer.full_list(0).regex=false "
    f"-config replacer.full_list(0).replacement='Bearer {token}'"
  )


def image_digest() -> str:
  result = subprocess.run(
    ["docker", "image", "inspect", "--format", "{{.Id}}", ZAP_IMAGE],
    capture_output=True, text=True, check=True,
  )
  return result.stdout.strip()


def run_once(run_number: int) -> dict:
  run_dir = RESULTS_DIR / f"run{run_number}"
  run_dir.mkdir(parents=True, exist_ok=True)

  with (run_dir / "api.log").open("w") as api_log:
    api = start_api(api_log)
    try:
      with urllib.request.urlopen(f"{BASE_URL}/openapi.json") as response:
        (run_dir / "openapi.json").write_bytes(response.read())
      token = obtain_token()
      ensure_authenticated(token)

      started_at = datetime.now(timezone.utc).isoformat()
      started = time.monotonic()
      completed = subprocess.run(
        [
          "docker", "run", "--rm", "--network", "host",
          "-v", f"{run_dir.resolve()}:/zap/wrk:rw,Z",
          ZAP_IMAGE,
          "zap-api-scan.py",
          "-t", f"{BASE_URL}/openapi.json",
          "-f", "openapi",
          "-J", "report.json",
          "-r", "report.html",
          "-z", replacer_options(token),
        ],
        capture_output=True,
        text=True,
      )
      elapsed = time.monotonic() - started
    finally:
      api.terminate()
      api.wait()

  metadata = {
    "run": run_number,
    "tool": "ZAP",
    "image": ZAP_IMAGE,
    "image_id": image_digest(),
    "identity": ZAP_IDENTITY["username"],
    "started_at": started_at,
    "elapsed_seconds": round(elapsed, 3),
    "exit_code": completed.returncode,
  }
  (run_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))
  (run_dir / "zap.log").write_text(completed.stdout + completed.stderr)
  return metadata


def main() -> None:
  RESULTS_DIR.mkdir(parents=True, exist_ok=True)
  for run_number in range(1, RUNS + 1):
    metadata = run_once(run_number)
    print(f"run {run_number}: exit={metadata['exit_code']} elapsed={metadata['elapsed_seconds']}s")


if __name__ == "__main__":
  main()
