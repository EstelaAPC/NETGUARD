import json
import os
import sys
import time
from urllib import error, request

API_URL = os.environ.get("API_URL", "http://api:8000").rstrip("/")
SERVICE_TOKEN = os.environ.get("NETGUARD_SERVICE_TOKEN", "").strip()
BOOTSTRAP_PATH = "/lab/bootstrap"
HEALTH_PATH = "/health"
MAX_TRIES = int(os.environ.get("LAB_BOOTSTRAP_MAX_TRIES", "40"))
SLEEP_SEC = float(os.environ.get("LAB_BOOTSTRAP_SLEEP_SEC", "3"))


def http_json(method: str, path: str, payload: dict | None = None):
    body = None
    headers = {}
    if SERVICE_TOKEN:
        headers["X-NetGuard-Service-Token"] = SERVICE_TOKEN

    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = request.Request(f"{API_URL}{path}", data=body, method=method, headers=headers)
    with request.urlopen(req, timeout=20) as response:
        data = response.read().decode("utf-8")
        return json.loads(data) if data else None


def wait_for_api():
    last_error = None

    for attempt in range(1, MAX_TRIES + 1):
        try:
            response = http_json("GET", HEALTH_PATH)
            if response and response.get("status") == "ok":
                print(f"API pronta na tentativa {attempt}")
                return
        except Exception as exc:
            last_error = exc

        time.sleep(SLEEP_SEC)

    raise RuntimeError(f"API indisponivel para bootstrap: {last_error}")


def run_bootstrap():
    last_error = None

    for attempt in range(1, MAX_TRIES + 1):
        try:
            response = http_json("POST", BOOTSTRAP_PATH, {})
            print(json.dumps(response, ensure_ascii=True))
            return
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            last_error = f"HTTP {exc.code}: {detail}"
        except Exception as exc:
            last_error = str(exc)

        time.sleep(SLEEP_SEC)

    raise RuntimeError(f"Falha no bootstrap do lab-linux-01: {last_error}")


def main():
    wait_for_api()
    run_bootstrap()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
