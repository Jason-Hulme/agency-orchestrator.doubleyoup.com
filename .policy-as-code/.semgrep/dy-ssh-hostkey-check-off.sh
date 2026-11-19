#!/usr/bin/env sh
# Fixture for dy-ssh-hostkey-check-off (hub#495 rule C12). Never run: semgrep test reads it.

# ruleid: dy-ssh-hostkey-check-off
ssh -o StrictHostKeyChecking=no deploy@example.com true
# ruleid: dy-ssh-hostkey-check-off
ssh -o "StrictHostKeyChecking no" deploy@example.com true
# ruleid: dy-ssh-hostkey-check-off
ssh -o UserKnownHostsFile=/dev/null deploy@example.com true
# ruleid: dy-ssh-hostkey-check-off
GIT_SSH_COMMAND="ssh -o stricthostkeychecking=off" git fetch

# ok: dy-ssh-hostkey-check-off
ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/ssh/known_hosts deploy@example.com true
# ok: dy-ssh-hostkey-check-off
ssh -o StrictHostKeyChecking=accept-new deploy@example.com true
