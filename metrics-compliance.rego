package policy

import rego.v1

# Evaluates a metrics facts attestation against per-repo bounds.
#
# The params drive everything: each leaf in the min/max trees names a path into
# the attested json and the bound to apply. The policy therefore works for any
# metrics attestation shape - a nested coverage report or a flat test-count
# report - and a repo bounds whatever metrics it cares about.
#
#   { "artifact_name": "web",
#     "attestation_name": "coverage-facts",
#     "min": { "code": { "lines": { "total": 1 } } },
#     "max": { "code": { "lines": { "missed": 0 } } } }

artifact_name    := data.params.artifact_name
attestation_name := data.params.attestation_name

default allow := false

# The attestations on the artifact the params name, or {} when that artifact is
# absent, so that a missing attestation can be reported rather than only denied.
artifact_attestations := object.get(
	input.trail,
	["compliance_status", "artifacts_statuses", artifact_name, "attestations_statuses"],
	{},
)

metrics := artifact_attestations[attestation_name].attestation_data

# Every numeric leaf of a bounds tree, as path -> bound.
bounds(tree) := {path: bound |
	walk(tree, [path, bound])
	is_number(bound)
}

# A bound is met only when the metric exists, is a number, and compares. A
# missing metric leaves the comparison undefined, which fails the enclosing
# every, so an absent metric is non-compliant rather than silently ignored.
meets_max(path, bound) if {
	value := object.get(metrics, path, null)
	is_number(value)
	value <= bound
}

meets_min(path, bound) if {
	value := object.get(metrics, path, null)
	is_number(value)
	value >= bound
}

max_bounds := bounds(object.get(data.params, "max", {}))

min_bounds := bounds(object.get(data.params, "min", {}))

# Params naming no bounds at all would allow everything, so a misconfigured or
# empty params file must not read as compliant.
some_bound_is_set if {
	count(max_bounds) + count(min_bounds) > 0
}

# The min bounds exist to stop an empty or absent report passing vacuously:
# with upper bounds alone, a report of all zeros satisfies every one of them.
within_bounds if {
	some_bound_is_set
	every path, bound in max_bounds {
		meets_max(path, bound)
	}
	every path, bound in min_bounds {
		meets_min(path, bound)
	}
}

# allow is a positive assertion that every bound is met, never the absence of
# violations, so a failure to build a diagnostic can only lose a message and
# cannot yield a compliant result.
allow if within_bounds

violations contains msg if {
	some path, bound in max_bounds
	not meets_max(path, bound)
	msg := sprintf("%v is %v, above its maximum of %v", [concat(".", path), object.get(metrics, path, "absent"), bound])
}

violations contains msg if {
	some path, bound in min_bounds
	not meets_min(path, bound)
	msg := sprintf("%v is %v, below its minimum of %v", [concat(".", path), object.get(metrics, path, "absent"), bound])
}

violations contains "params name no bounds, so nothing is being checked" if {
	not some_bound_is_set
}

# Without this, an absent attestation denies with no reason given: every other
# violation rule reaches through metrics, which is exactly what is undefined.
violations contains msg if {
	not artifact_attestations[attestation_name]
	msg := sprintf("no %v attestation on artifact %v", [attestation_name, artifact_name])
}
