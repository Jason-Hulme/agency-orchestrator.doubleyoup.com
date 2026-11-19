#!/usr/bin/env sh
#
# Self-test of scripts/policy-gate.sh: a change under test cannot turn the gate green by editing the
# gate's own rules, scripts, ignore lists or workflow, because the gate reads none of them from the target.
#
# Usage: sh scripts/policy-gate-selftest.sh   (npm run policy:gate-selftest)
#
# It copies this checkout's tracked files twice: once as the gate (the "base branch"), once as the target
# (the "pull request"). Each case below edits only the TARGET, and checks the gate's exit code. GitHub's
# part of the design (a pull_request_target run reads its workflow from the default branch, not from the
# PR) cannot be run here; it is GitHub's documented behaviour, and the workflow case below shows that the
# target's workflow file is only data to the gate.
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
WORK_DIR=$(mktemp -d)
trap 'rm -rf -- "$WORK_DIR"' EXIT

copy_tracked_files() {
  destination=$1
  mkdir -p "$destination"
  (cd "$REPO_ROOT" && git ls-files -z | tar --null -T - -cf -) | tar -xf - -C "$destination"
}

copy_tracked_files "$WORK_DIR/gate"

FAILED_CASES=0
CASE_NUMBER=0

# A fresh target for each case, so one case's edits never leak into the next.
new_target() {
  CASE_NUMBER=$((CASE_NUMBER + 1))
  TARGET="$WORK_DIR/target-$CASE_NUMBER"
  copy_tracked_files "$TARGET"
}

# A TypeScript line that rule dy-derived-slot-name refuses: a slot name built outside the helper.
add_semgrep_violation() {
  cat > "$TARGET/src/selftest-violation.ts" <<'EOF'
export function selftestSlotPath(slug: string): string {
  return `/srv/dy-storage/platform/${slug}-staging`;
}
EOF
}

# A workflow job that can mint a cloud credential and runs an action by a movable tag: conftest denies it.
add_conftest_violation() {
  cat > "$TARGET/.github/workflows/selftest-violation.yml" <<'EOF'
name: selftest
on:
  push:
permissions:
  contents: read
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: google-github-actions/auth@v2
EOF
}

run_case() {
  expected=$1
  description=$2
  if sh "$WORK_DIR/gate/scripts/policy-gate.sh" "$WORK_DIR/gate" "$TARGET" > "$WORK_DIR/case-$CASE_NUMBER.log" 2>&1; then
    actual="pass"
  else
    actual="fail"
  fi
  if [ "$actual" = "$expected" ]; then
    echo "ok   $CASE_NUMBER: $description (gate: $actual)"
    return 0
  fi
  echo "FAIL $CASE_NUMBER: $description (gate: $actual, expected $expected). Log:"
  cat "$WORK_DIR/case-$CASE_NUMBER.log"
  FAILED_CASES=$((FAILED_CASES + 1))
}

new_target
run_case pass "an unchanged target passes"

new_target
add_semgrep_violation
run_case fail "a semgrep violation fails"

new_target
add_semgrep_violation
rm -f "$TARGET/.policy-as-code/.semgrep/dy-derived-slot-name.yaml"
printf 'rules: []\n' > "$TARGET/.policy-as-code/.semgrep/dy-derived-slot-name.yaml"
run_case fail "a semgrep violation still fails when the target empties the rule"

new_target
add_semgrep_violation
printf 'src/\n*.ts\n' > "$TARGET/.semgrepignore"
printf '*\n' > "$TARGET/src/.semgrepignore"
run_case fail "a semgrep violation still fails when the target's ignore lists skip it"

new_target
add_semgrep_violation
add_conftest_violation
printf '#!/usr/bin/env sh\nexit 0\n' > "$TARGET/scripts/conftest.sh"
printf '#!/usr/bin/env sh\nexit 0\n' > "$TARGET/scripts/policy-gate.sh"
printf '{"name":"selftest","scripts":{"semgrep:policy":"true","conftest":"true"}}\n' > "$TARGET/package.json"
run_case fail "violations still fail when the target's scripts and package.json pass everything"

new_target
add_conftest_violation
run_case fail "a workflow violation fails"

new_target
add_conftest_violation
for policy_file in "$TARGET"/.policy-as-code/.conftest/workflows/*.rego; do
  printf 'package main\n' > "$policy_file"
done
printf 'name: selftest\non:\n  pull_request:\njobs: {}\n' > "$TARGET/.github/workflows/policy.yml"
run_case fail "a workflow violation still fails when the target empties the Rego and rewrites policy.yml"

if [ "$FAILED_CASES" -gt 0 ]; then
  echo "$FAILED_CASES case(s) failed." >&2
  exit 1
fi
echo "All $CASE_NUMBER cases behaved as expected."
