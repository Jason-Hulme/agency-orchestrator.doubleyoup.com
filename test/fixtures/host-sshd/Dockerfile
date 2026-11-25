# hub#476: the test server for the Worker's SSH client (test/host-ssh.worker.test.ts, started by
# test/host-sshd.global-setup.ts). A real OpenSSH server on Debian 12 (the planning/58 guest OS), a login
# `dy` with passwordless sudo, and an HTTPS server for installer.test on port 443 that serves the stub
# installer at the content-addressed path /self-hosted/host-install-<sha256>.sh. Test material only.
FROM debian:12-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openssh-server sudo curl ca-certificates openssl python3 procps \
 && rm -rf /var/lib/apt/lists/*

# The login the Worker uses. Its authorized key is written by the global setup at start.
RUN useradd --create-home --shell /bin/bash dy \
 && echo 'dy ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/dy \
 && chmod 0440 /etc/sudoers.d/dy \
 && mkdir -p /run/sshd /srv/self-hosted \
 && echo '127.0.0.1 installer.test' >> /etc/hosts.installer

# A self-signed certificate for installer.test, trusted by the system store, so the stub's
# `curl --proto =https` download is a real TLS download.
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=installer.test" \
      -addext "subjectAltName=DNS:installer.test" \
      -keyout /etc/ssl/private/installer-test.key -out /usr/local/share/ca-certificates/installer-test.crt \
 && update-ca-certificates

COPY https-server.py /usr/local/bin/https-server.py
COPY start.sh /usr/local/bin/start.sh
RUN chmod 0755 /usr/local/bin/start.sh

EXPOSE 22
CMD ["/usr/local/bin/start.sh"]
