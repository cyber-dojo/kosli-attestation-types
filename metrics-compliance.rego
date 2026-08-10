package policy

import rego.v1

# Evaluates a metrics facts attestation against per-repo bounds.
#
# The params drive everything: each leaf of the bounds tree names a path into
# the attested json and the range the value at that path must lie in. The
# policy therefore works for any metrics attestation shape - a nested coverage
# report or a flat test-count report - and a repo bounds whatever metrics it
# cares about.
#
#   { "artifact_name": "web",
#     "attestation_name": "coverage-facts",
#     "bounds": { "code": { "lines": { "total":  {"min": 1, "max": 496},
#                                      "missed": {"min": 0, "max": 0} } } } }
#
# Every metric names both sides of its range, and the check is
# min <= value <= max. Naming one side alone is a params mistake rather than a
# looser bound, so it is reported instead of applied.

artifact_name := data.params.artifact_name

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

bounds_tree := object.get(data.params, "bounds", {})

# Every well-formed range in the bounds tree, as path -> range.
ranges := {path: range |
	walk(bounds_tree, [path, range])
	is_number(range.min)
	is_number(range.max)
}

# The bounds-tree numbers that are not one side of a well-formed range: a bare
# number where a range belongs, or a half-written one. Each is reported by the
# path of the metric it was meant to bound, not by its own path.
malformed contains path if {
	walk(bounds_tree, [number_path, value])
	is_number(value)
	not inside_range(number_path)
	path := metric_path(number_path)
}

# True when the number at this path is the min or the max of a well-formed range.
inside_range(path) if {
	trailing_side(path)
	ranges[array.slice(path, 0, count(path) - 1)]
}

trailing_side(path) if {
	count(path) > 0
	path[count(path) - 1] in {"min", "max"}
}

# The metric a bounds-tree number was meant to bound: the number's own path,
# less a trailing min or max.
metric_path(path) := array.slice(path, 0, count(path) - 1) if {
	trailing_side(path)
}

metric_path(path) := path if {
	not trailing_side(path)
}

# A range is met only when the metric exists, is a number, and lies within it.
# A missing metric leaves the comparison undefined, which fails the enclosing
# every, so an absent metric is non-compliant rather than silently ignored.
within(path, range) if {
	value := object.get(metrics, path, null)
	is_number(value)
	value >= range.min
	value <= range.max
}

# Params naming no bounds at all would allow everything, so a misconfigured or
# empty params file must not read as compliant.
some_bound_is_set if {
	count(ranges) > 0
}

# The lower bounds exist to stop an empty or absent report passing vacuously:
# with upper bounds alone, a report of all zeros satisfies every one of them.
within_bounds if {
	some_bound_is_set
	count(malformed) == 0
	every path, range in ranges {
		within(path, range)
	}
}

# allow is a positive assertion that every bound is met, never the absence of
# violations, so a failure to build a diagnostic can only lose a message and
# cannot yield a compliant result.
allow if within_bounds

violations contains msg if {
	some path, range in ranges
	value := object.get(metrics, path, null)
	is_number(value)
	value > range.max
	msg := sprintf("%v is %v, above its maximum of %v", [concat(".", path), value, range.max])
}

violations contains msg if {
	some path, range in ranges
	value := object.get(metrics, path, null)
	is_number(value)
	value < range.min
	msg := sprintf("%v is %v, below its minimum of %v", [concat(".", path), value, range.min])
}

# A metric the report lacks breaches no side in particular, so its message
# names the range it was required to lie in.
violations contains msg if {
	some path, range in ranges
	not is_number(object.get(metrics, path, null))
	msg := sprintf("%v is %v, and must be between %v and %v", [
		concat(".", path),
		object.get(metrics, path, "absent"),
		range.min,
		range.max,
	])
}

violations contains msg if {
	some path in malformed
	msg := sprintf("%v does not name both a min and a max", [concat(".", path)])
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
