import json
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API_DIR = ROOT / "vulnerable_api"
SCANNER_DIR = ROOT / "scanner"
RESULTS_DIR = ROOT / "evaluation" / "results" / "scanner"
HOST = "127.0.0.1"
PORT = 8000
BASE_URL = f"http://{HOST}:{PORT}"
RUNS = 3


def ensure_port_free() -> None:
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    if sock.connect_ex((HOST, PORT)) == 0:
      raise RuntimeError(
        f"Port {PORT} is already in use. Stop the running API server before executing the harness."
      )


def wait_until_ready(process: subprocess.Popen, timeout: float = 15.0) -> None:
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    if process.poll() is not None:
      raise RuntimeError(f"API process exited early with code {process.returncode}; see api.log")
    try:
      with urllib.request.urlopen(f"{BASE_URL}/openapi.json", timeout=1):
        return
    except OSError:
      time.sleep(0.2)
  raise RuntimeError("API did not become ready in time; see api.log")


def start_api(api_log) -> subprocess.Popen:
  ensure_port_free()
  process = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(PORT)],
    cwd=API_DIR,
    stdout=api_log,
    stderr=subprocess.STDOUT,
  )
  try:
    wait_until_ready(process)
  except Exception:
    process.kill()
    process.wait()
    raise
  return process


def run_once(run_number: int) -> dict:
  run_dir = RESULTS_DIR / f"run{run_number}"
  run_dir.mkdir(parents=True, exist_ok=True)

  with (run_dir / "api.log").open("w") as api_log:
    api = start_api(api_log)
    try:
      spec_path = run_dir / "openapi.json"
      with urllib.request.urlopen(f"{BASE_URL}/openapi.json") as response:
        spec_path.write_bytes(response.read())

      started_at = datetime.now(timezone.utc).isoformat()
      started = time.monotonic()
      completed = subprocess.run(
        [
          sys.executable, "cli.py",
          "--spec", str(spec_path),
          "--credentials", str(SCANNER_DIR / "config" / "credentials.example.yaml"),
          "--base-url", BASE_URL,
          "--login-path", "/auth/login",
          "--output", str(run_dir / "report.json"),
        ],
        cwd=SCANNER_DIR,
        capture_output=True,
        text=True,
      )
      elapsed = time.monotonic() - started
    finally:
      api.terminate()
      api.wait()

  metadata = {
    "run": run_number,
    "started_at": started_at,
    "elapsed_seconds": round(elapsed, 3),
    "exit_code": completed.returncode,
  }
  (run_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))
  (run_dir / "scanner.log").write_text(completed.stdout + completed.stderr)
  return metadata


def main() -> None:
  RESULTS_DIR.mkdir(parents=True, exist_ok=True)
  for run_number in range(1, RUNS + 1):
    metadata = run_once(run_number)
    print(f"run {run_number}: exit={metadata['exit_code']} elapsed={metadata['elapsed_seconds']}s")


if __name__ == "__main__":
  main()
