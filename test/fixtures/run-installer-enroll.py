# Test harness for the installer's enrol python (host-install-enroll.py). It stubs ONLY urllib.request.urlopen, so the
# request goes to the local server given in DY_TEST_ENROLL_SERVER (host:port), which hands it to the Worker handler.
# Then it runs the installer's code unchanged, with the same argv and stdin the installer gives it.
import http.client
import io
import os
import sys
import urllib.error
import urllib.request


class StubResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def stub_urlopen(request, timeout=None):
    host, port = os.environ["DY_TEST_ENROLL_SERVER"].split(":")
    connection = http.client.HTTPConnection(host, int(port), timeout=timeout)
    path = request.full_url.split("/", 3)[3]
    connection.request(request.get_method(), "/" + path, body=request.data, headers=dict(request.header_items()))
    answer = connection.getresponse()
    body = answer.read()
    if answer.status >= 400:
        raise urllib.error.HTTPError(request.full_url, answer.status, answer.reason, answer.headers, io.BytesIO(body))
    return StubResponse(body)


urllib.request.urlopen = stub_urlopen
installer_code_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "host-install-enroll.py")
with open(installer_code_path, "r", encoding="utf-8") as handle:
    installer_code = handle.read()
exec(compile(installer_code, installer_code_path, "exec"), {"__name__": "__main__"})
