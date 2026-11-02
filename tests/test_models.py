from policy_engine.models import PolicyResult, PolicyViolation, severity_rank


def test_severity_rank_orders_known_severities():
    assert severity_rank("LOW") < severity_rank("MEDIUM")
    assert severity_rank("MEDIUM") < severity_rank("HIGH")
    assert severity_rank("HIGH") < severity_rank("CRITICAL")


def test_severity_rank_defaults_unknown_to_lowest():
    assert severity_rank("") == severity_rank("UNKNOWN")
    assert severity_rank(None) == severity_rank("UNKNOWN")


def test_severity_rank_is_case_insensitive():
    assert severity_rank("critical") == severity_rank("CRITICAL")


def test_policy_result_passes_with_no_violations():
    assert PolicyResult(violations=[]).passed is True


def test_policy_result_fails_with_violations():
    result = PolicyResult(violations=[PolicyViolation(category="secret", message="found one")])
    assert result.passed is False
