#!/usr/bin/env sh
#
# The policy gate: the base branch's rules, scripts and ignore list, run against the code under test.
#
# Usage:
#   scripts/policy-gate.sh <gate-root> <target-root>
#
#   <gate-root>    a checkout of the BASE branch. Every rule, Rego policy, script and the .semgrepignore
#                  come from here.
#   <target-root>  a checkout of the code under test (the PR head). It is read as DATA only: semgrep and
#                  conftest read its files, and nothing in it is executed (no npm script, no shell script,
#                  no Rego). A PR therefore cannot change what "passing" means for its own check.
#
# The script CHANGES <target-root>: it replaces every .semgrepignore there with the gate's, so a PR cannot
# hide a file from the scan by adding an ignore file. It refuses to run when the two roots are the same
# folder, so a local run never edits your working tree. Use a scratch copy:
#   git worktree add /tmp/policy-target HEAD && sh scripts/policy-gate.sh . /tmp/policy-target
#
# scripts/policy-gate-selftest.sh shows the property: a target that edits the rules, the ignore list, the
# scripts or the workflow still fails on a violation.
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <gate-root> <target-root>" >&2
  exit 2
fi

GATE_ROOT=$(CDPATH='' cd -- "$1" && pwd -P)
TARGET_ROOT=$(CDPATH='' cd -- "$2" && pwd -P)

if [ "$GATE_ROOT" = "$TARGET_ROOT" ]; then
  echo "The gate root and the target root are the same folder ($GATE_ROOT). The gate edits the target's .semgrepignore files, so give it a separate checkout of the code under test." >&2
  exit 2
fi

for tool in semgrep conftest; do
  if ! command -v "$tool" > /dev/null 2>&1; then
    echo "$tool is not on PATH." >&2
    exit 127
  fi
done

GATE_SEMGREP_RULES="$GATE_ROOT/.policy-as-code/.semgrep"

# Track the worst exit code instead of stopping at the first failure, so one failing step does not
# hide the state of the others.
WORST_STATUS=0

echo "--- semgrep rule tests (gate rules)"
semgrep test "$GATE_SEMGREP_RULES" || WORST_STATUS=1

# The scan reads the GATE's ignore list only. semgrep reads every .semgrepignore under the project root
# (nested ones too), so each one in the target is removed, then the gate's is put at the target's root.
echo "--- semgrep scan (gate rules and gate ignore list, against the target)"
find "$TARGET_ROOT" -name .semgrepignore -exec rm -f -- {} +
cp -- "$GATE_ROOT/.semgrepignore" "$TARGET_ROOT/.semgrepignore"
# --timeout 0 and --max-target-bytes 0: a per-file timeout, or a file over semgrep's 1 MB default, skips
# that file and still exits 0, which would let a violation through a gate that looks green.
(cd "$TARGET_ROOT" && semgrep scan --config "$GATE_SEMGREP_RULES" --error --metrics=off --timeout 0 --max-target-bytes 0) || WORST_STATUS=1

# conftest reads a conftest.toml from its working directory, so it runs from the gate root.
echo "--- conftest policy unit tests (gate policies)"
(cd "$GATE_ROOT" && sh scripts/conftest.sh verify) || WORST_STATUS=1

echo "--- conftest policies (gate policies, against the target's workflows and actions)"
(cd "$GATE_ROOT" && POLICY_TARGET_ROOT="$TARGET_ROOT" sh scripts/conftest.sh) || WORST_STATUS=1

exit "$WORST_STATUS"
