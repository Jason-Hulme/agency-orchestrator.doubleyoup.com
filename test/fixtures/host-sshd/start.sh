#!/bin/sh
# hub#476 test server start. A fresh ED25519 host key per container, so the pinned fingerprint is never a fixed value.
set -eu
cat /etc/hosts.installer >> /etc/hosts
rm -f /etc/ssh/ssh_host_*
ssh-keygen -q -t ed25519 -N "" -f /etc/ssh/ssh_host_ed25519_key
python3 /usr/local/bin/https-server.py > /var/log/https-server.log 2>&1 &
exec /usr/sbin/sshd -D -e -o PasswordAuthentication=no -o HostKey=/etc/ssh/ssh_host_ed25519_key
