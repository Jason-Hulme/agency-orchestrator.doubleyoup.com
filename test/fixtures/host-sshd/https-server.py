# Serves /srv over HTTPS on port 443 as installer.test (hub#476 test material only).
import functools
import http.server
import ssl

handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory="/srv")
server = http.server.ThreadingHTTPServer(("127.0.0.1", 443), handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/usr/local/share/ca-certificates/installer-test.crt", "/etc/ssl/private/installer-test.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
