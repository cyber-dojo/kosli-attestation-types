#!/usr/bin/env bash

# Tests for metrics-compliance.rego, living in the parent dir.
#
# The fixtures are genuine: web-coverage-metrics.json and web-test-metrics.json
# are real reports from a cyber-dojo web build, and the -params.json beside each
# holds the bounds web judged that build by. Tests evaluate them, and mutations
# of them, with `kosli evaluate input` (no API calls).
#
# The two reports deliberately differ in shape - coverage is a nested tree, test
# metrics are flat - because one policy must serve both.
#
# Bounds a single test asserts about are written in that test instead, where the
# number and the message quoting it can be read together.

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"
readonly repo_dir="$(cd "${my_dir}/.." && pwd)"

readonly REGO="${repo_dir}/metrics-compliance.rego"

# Each report is paired with the bounds web set for it, in the shape web's own
# params file carries: every metric names both sides of its range, and the
# policy asks min <= value <= max.
readonly COVERAGE_REPORT="${my_dir}/fixtures/web-coverage-metrics.json"
readonly COVERAGE_BOUNDS="${my_dir}/fixtures/web-coverage-params.json"
readonly TEST_REPORT="${my_dir}/fixtures/web-test-metrics.json"
readonly TEST_BOUNDS="${my_dir}/fixtures/web-test-params.json"

# The bounds the shared coverage-metrics type demands, which web does not meet.
# Written here, not in fixtures/, because the numbers are what the test that
# uses them asserts about.
readonly STRICTER_COVERAGE_BOUNDS='{
  "artifact_name": "web",
  "attestation_name": "coverage-facts",
  "bounds": {
    "test": {
      "lines": {
        "missed": {"min":0, "max":0}
      },
      "branches": {
        "total":  {"min":1, "max":20},
        "missed": {"min":0, "max":0}
      }
    }
  }
}'

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Coverage metrics, the nested shape

test_allow_the_real_coverage_report_against_its_own_bounds()
{
  evaluate_facts "coverage-facts" "$(cat "${COVERAGE_REPORT}")" "$(cat "${COVERAGE_BOUNDS}")"
  assert_allow
}

test_deny_the_real_coverage_report_against_stricter_bounds()
{
  # The bounds baked into the shared coverage-metrics type. Naming each breach
  # individually is what tells a reader which number has to move.
  evaluate_facts "coverage-facts" "$(cat "${COVERAGE_REPORT}")" "${STRICTER_COVERAGE_BOUNDS}"
  assert_deny
  assert_violation_message "test.lines.missed is 9, above its maximum of 0"
  assert_violation_message "test.branches.missed is 8, above its maximum of 0"
  assert_violation_message "test.branches.total is 26, above its maximum of 20"
}

test_deny_an_all_zero_report_because_a_minimum_requires_more()
{
  # Upper bounds alone cannot catch this: a report of all zeros satisfies every
  # one of them. The min bounds exist precisely to fail it.
  local -r zeroed="$(jq 'walk(if type == "number" then 0 else . end)' "${COVERAGE_REPORT}")"
  evaluate_facts "coverage-facts" "${zeroed}" "$(cat "${COVERAGE_BOUNDS}")"
  assert_deny
  assert_violation_message "code.lines.total is 0, below its minimum of 1"
}

test_deny_when_a_bounded_metric_is_absent()
{
  # A metric that the params bound but the report omits must fail, not be
  # silently skipped - fail toward non-compliance.
  local -r without="$(jq 'del(.test.branches.missed)' "${COVERAGE_REPORT}")"
  evaluate_facts "coverage-facts" "${without}" "$(cat "${COVERAGE_BOUNDS}")"
  assert_deny
  assert_violation_message "test.branches.missed is absent, and must be between 0 and 8"
}

test_deny_when_the_named_attestation_is_missing_from_the_trail()
{
  # The params name coverage-facts; a trail carrying only some other
  # attestation must not read as compliant. Denying is not enough on its own:
  # without a reason, a CI failure here says only that something was wrong.
  evaluate_facts "some-other-facts" "$(cat "${COVERAGE_REPORT}")" "$(cat "${COVERAGE_BOUNDS}")"
  assert_deny
  assert_violation_message "no coverage-facts attestation on artifact web"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Test metrics, the flat shape, through the same policy

test_allow_the_real_test_metrics_against_their_own_bounds()
{
  evaluate_facts "test-facts" "$(cat "${TEST_REPORT}")" "$(cat "${TEST_BOUNDS}")"
  assert_allow
}

test_deny_when_the_test_count_falls_below_its_floor()
{
  # Tests disappearing is the failure a passing suite would otherwise hide.
  local -r fewer="$(jq '.test_count = 117' "${TEST_REPORT}")"
  evaluate_facts "test-facts" "${fewer}" "$(cat "${TEST_BOUNDS}")"
  assert_deny
  assert_violation_message "test_count is 117, below its minimum of 118"
}

test_deny_when_the_test_count_rises_above_its_ceiling()
{
  # The ceiling is what the params file's own number has to be moved to, so a
  # run whose suite grew cannot report metrics the bounds no longer describe.
  local -r more="$(jq '.test_count = 119' "${TEST_REPORT}")"
  evaluate_facts "test-facts" "${more}" "$(cat "${TEST_BOUNDS}")"
  assert_deny
  assert_violation_message "test_count is 119, above its maximum of 118"
}

test_deny_when_a_test_fails()
{
  local -r failed="$(jq '.failure_count = 1' "${TEST_REPORT}")"
  evaluate_facts "test-facts" "${failed}" "$(cat "${TEST_BOUNDS}")"
  assert_deny
  assert_violation_message "failure_count is 1, above its maximum of 0"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Params fail-safes

test_deny_when_the_params_name_no_bounds()
{
  # An empty or misconfigured params file must not read as compliant.
  local -r no_bounds='{"artifact_name":"web","attestation_name":"coverage-facts"}'
  evaluate_facts "coverage-facts" "$(cat "${COVERAGE_REPORT}")" "${no_bounds}"
  assert_deny
  assert_violation_message "params name no bounds, so nothing is being checked"
}

test_deny_when_a_bound_names_only_one_side()
{
  # A half-written range is a params mistake, and the metric it names is then
  # bounded on one side only. Reporting it beats applying the side that is
  # there and reading as compliant.
  local -r half='{
    "artifact_name": "web",
    "attestation_name": "test-facts",
    "bounds": {
      "test_count":    {"min":118},
      "failure_count": {"min":0, "max":0}
    }
  }'
  evaluate_facts "test-facts" "$(cat "${TEST_REPORT}")" "${half}"
  assert_deny
  assert_violation_message "test_count does not name both a min and a max"
}

test_deny_when_a_bound_is_a_bare_number()
{
  # The shape the params carried before each metric named a range. Left
  # unreported, such a metric would silently go unchecked.
  local -r bare='{
    "artifact_name": "web",
    "attestation_name": "test-facts",
    "bounds": {
      "test_count":    118,
      "failure_count": {"min":0, "max":0}
    }
  }'
  evaluate_facts "test-facts" "$(cat "${TEST_REPORT}")" "${bare}"
  assert_deny
  assert_violation_message "test_count does not name both a min and a max"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

# Wrap an attested metrics document in the trail input shape the policy expects,
# under the given attestation name.
wrap_facts()
{
  jq -n \
    --arg name "${1}" \
    --argjson facts "${2}" \
    '{
      trail: {
        name: "test-trail",
        compliance_status: {
          artifacts_statuses: {
            web: {attestations_statuses: {($name): {attestation_data: $facts}}}
          }
        }
      }
    }'
}

evaluate_input()
{
  local -r input="${1}"
  local -r params="${2}"
  echo "${input}" | kosli evaluate input \
    --policy "${REGO}" \
    --params "${params}" \
    --output json \
    >"${stdoutF}" 2>"${stderrF}"
  echo $? >"${statusF}"
}

# Evaluate a metrics document, attested under the given name, against the rego.
evaluate_facts()
{
  evaluate_input "$(wrap_facts "${1}" "${2}")" "${3}"
}

# Assert the policy allowed (allow == true) with no violations.
assert_allow()
{
  assertEquals "allow:$(dump_sss)" "true" "$(jq '.allow' "${stdoutF}")"
  assertEquals "violations:$(dump_sss)" "null" "$(jq '.violations' "${stdoutF}")"
}

# Assert the policy denied (allow == false), read from stdout regardless of exit.
assert_deny()
{
  assertEquals "allow:$(dump_sss)" "false" "$(jq '.allow' "${stdoutF}")"
}

# Assert the given exact string is one of the reported violations.
assert_violation_message()
{
  local -r expected="${1}"
  local found
  found="$(jq --arg s "${expected}" '.violations[]? | select(. == $s)' "${stdoutF}")"
  if [ -z "${found}" ]; then
    dump_sss
    fail "expected violations to include '${expected}'"
  fi
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

echo "::${0##*/}"
. ${my_dir}/shunit2_helpers.sh
. ${my_dir}/shunit2
