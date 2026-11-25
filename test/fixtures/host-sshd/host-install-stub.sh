#!/bin/sh
# hub#476: a STUB of the infra host installer, for test/host-ssh.worker.test.ts. It follows the installer contract
# in src/actuate-host.ts: one JSON line on stdin, no argv, and one JSON result line last on stdout. It installs
# nothing. It records what it received, so the test can check that the secrets came on stdin and not on argv.
set -eu
state_root="$HOME/.dy-test-install"
mkdir -p "$state_root"
IFS= read -r job_line
field() {
  printf '%s\n' "$job_line" | sed -n "s/.*\"$1\":\"\\([^\"]*\\)\".*/\\1/p"
}
cell_id=$(field cellId)
mode=$(field mode)
op=$(field op)
state_file="$state_root/$cell_id.state"
printf '%s\n' "$#" > "$state_root/$cell_id.argc"
printf '%s\n' "$job_line" > "$state_root/$cell_id.$mode.stdin"
# The installer elevates itself; the test login has passwordless sudo.
sudo -n true
if [ "$mode" = "poll" ]; then
  if [ -f "$state_file" ]; then
    printf '{"state":"%s","step":"verify","detail":"%s polled","hypervisor":"libvirt","hostAgentVersion":"0.0.0-stub"}\n' "$(cat "$state_file")" "$op"
  else
    printf '{"state":"none","detail":"no run on record"}\n'
  fi
  exit 0
fi
if [ -f "$state_file" ] && [ "$(cat "$state_file")" = "done" ]; then
  printf '{"state":"done","step":"verify","detail":"already enrolled","hypervisor":"libvirt","hostAgentVersion":"0.0.0-stub"}\n'
  exit 0
fi
echo running > "$state_file"
# The detached "install": a real installer runs its long steps here, after the SSH session has ended.
nohup sh -c "sleep 1; echo done > '$state_file'" > /dev/null 2>&1 < /dev/null &
printf '{"state":"running","step":"preflight","detail":"%s started"}\n' "$op"
