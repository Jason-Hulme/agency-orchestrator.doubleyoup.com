# The installer's own enrol step, copied byte for byte (everything below the comment lines) from
#   infra self-hosted/host-install.sh at infra commit 987e8082be717918b93e7719d340caca7cf58877, lines 934-977
#   (the python of enroll_and_build_params; the heredoc body between `<<'PY'` and `PY`).
# The installer is published as self-hosted/dist/host-install.sh, sha256
#   a8f1f2eda7813d298808e12f26e266e361657b72c561ccb7870153b71aec84ca
# (the orchestrator pins it in src/cell-bootstrap.ts). Do not edit the code below: if the installer changes, copy it again.
import base64
import json
import sys
import urllib.error
import urllib.request

origin = sys.argv[1]
input_lines = sys.stdin.read().split("\n")
if len(input_lines) < 2:
    sys.exit("the enrol facts and the enrol code are both needed")
blob, code = input_lines[0].strip(), input_lines[1].strip()
prefix = "dyenrol2."
if not blob.startswith(prefix):
    sys.exit("the enrol facts must start with dyenrol2.")
encoded = blob[len(prefix):]
try:
    facts = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
except Exception:
    sys.exit("the enrol facts are not valid")
if not isinstance(facts, dict):
    sys.exit("the enrol facts are not valid")
if len(code) < 32:
    sys.exit("the enrol code is shorter than 32 characters")
request = urllib.request.Request(
    origin + "/enroll-host",
    data=json.dumps({"facts": facts, "code": code}).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(request, timeout=60) as response:
        material = json.loads(response.read().decode("utf-8"))
except urllib.error.HTTPError as error:
    sys.exit("the Worker refused the enrolment (HTTP %d): %s" % (error.code, error.read(300).decode("utf-8", "replace")))
except Exception as error:
    sys.exit("the Worker did not answer: %s" % error)
params = material.get("params") if isinstance(material, dict) else None
if not isinstance(params, dict):
    sys.exit("the Worker's answer holds no install params")
params = dict(params)
params["hostAgentToken"] = material.get("hostAgentToken")
params["tunnelToken"] = material.get("tunnelToken")
params["mode"] = "start"
print(json.dumps(params))
