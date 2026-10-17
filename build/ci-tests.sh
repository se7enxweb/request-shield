#!/usr/bin/env bash
#
# This file is part of cjw-network/request-shield.
#
# @copyright Copyright (C) 2026 JAC Systeme GmbH, CJW Network
# @license MIT, see LICENSE
#
#   build/ci-tests.sh            what the CI's test steps run: php tests/run.php
#
# On PHP 8.0 (CI_RETRY_FAILED=1) a test that failed is run once more on its own,
# and the step fails only when it fails again. PHP 8.0.30 is at its end of life,
# and on GitHub's runners the servers the end-to-end tests start crash now and
# then (exit 139, a segfault) or a request gets no answer (status 0) -- a
# different test each time, about one run in two, never on a machine of ours.
# At most five failed tests are run again; more than that is no crash, and the
# step fails. Every other PHP version fails at once, as before.
set -uo pipefail

log="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/request-shield-tests.log"
php tests/run.php 2>&1 | tee "$log"
status=${PIPESTATUS[0]}
[ "$status" = 0 ] && exit 0
[ "${CI_RETRY_FAILED:-0}" = 1 ] || exit "$status"

failed=()
while IFS= read -r line; do
  failed+=("$line")
done < <(sed -n 's/^  FAIL  \(.*\)$/\1/p' "$log")
if [ "${#failed[@]}" = 0 ] || [ "${#failed[@]}" -gt 5 ]; then
  echo "${#failed[@]} tests failed: not run again"
  exit "$status"
fi
for t in "${failed[@]}"; do
  echo "::warning::\"$t\" failed, running it once more on its own"
  php tests/run.php "$t" || exit 1
done
echo "Each failed test passed when run again."
