from bouncer import models as m
from bouncer.models import ValidationResult
from bouncer.validators import get_validator
from bouncer.validators.base import ValidatorContext


def _finding(base, true_p="1 AND 1=1", false_p="1 AND 1=2"):
    return m.Finding(
        id=1, program="demo", vuln_class="sqli_boolean",
        target_url=f"{base}/item?id=1",
        request={
            "method": "GET", "inject_param": "id", "base_value": "1",
            "true_payload": true_p, "false_payload": false_p, "repeats": 3,
        },
    )


def test_confirmed_boolean_differential(mock_server, http, settings):
    v = get_validator("sqli_boolean")
    ctx = ValidatorContext(http=http, settings=settings)
    res = v.validate(_finding(mock_server), ctx)
    assert res.verdict == ValidationResult.CONFIRMED
    assert res.confidence_delta > 0.5


def test_no_differential_when_both_true(mock_server, http, settings):
    # Both payloads evaluate TRUE => FALSE response won't differ => refuted.
    v = get_validator("sqli_boolean")
    ctx = ValidatorContext(http=http, settings=settings)
    res = v.validate(_finding(mock_server, false_p="1 AND 2=2"), ctx)
    assert res.verdict == ValidationResult.REFUTED


def test_forbidden_payload_refused(mock_server, http, settings):
    v = get_validator("sqli_boolean")
    ctx = ValidatorContext(http=http, settings=settings)
    res = v.validate(_finding(mock_server, true_p="1; DROP TABLE users"), ctx)
    assert res.verdict == ValidationResult.REFUTED
    assert "benign" in res.reason
