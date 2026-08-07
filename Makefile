# Runs the rego policy test suite. The tests/ dir (shunit2 helpers, fixtures,
# runner) exercises metrics-compliance.rego with `kosli evaluate input`, which
# reads a local json file and makes no API calls, so the suite needs no Kosli
# credentials and no network.
#
#   make test

.PHONY: test

test:
	./tests/run_tests.sh
