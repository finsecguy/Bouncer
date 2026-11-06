import pytest

from bouncer import models as m
from bouncer.config import Settings
from bouncer.models import ValidationResult
from bouncer.validators import get_validator
from bouncer.validators.base import ValidatorContext


def _settings_with_sessions():
    return Settings(
        _env_file=None,
        idor_session_a={"Cookie": "session=alice"},
        idor_session_b={"Cookie": "session=bob"},
    )


def _finding(base, method="GET"):
    return m.Finding(
        id=1, program="demo", vuln_class="idor",
        target_url=f"{base}/api/orders/1001",
        request={
            "method": method,
            "url_template": f"{base}/api/orders/{{id}}",
            "object_id_a": "1001", "object_id_b": "1002",
        },
    )


def test_confirmed_idor(mock_server, http):
    v = get_validator("idor")
    ctx = ValidatorContext(http=http, settings=_settings_with_sessions())
    res = v.validate(_finding(mock_server), ctx)
    assert res.verdict == ValidationResult.CONFIRMED
    assert res.confidence_delta > 0.5


def test_missing_sessions_inconclusive(mock_server, http, settings):
    v = get_validator("idor")
    ctx = ValidatorContext(http=http, settings=settings)  # no sessions
    res = v.validate(_finding(mock_server), ctx)
    assert res.verdict == ValidationResult.INCONCLUSIVE
    assert res.confidence_delta == 0.0


def test_unsafe_method_refused(mock_server, http):
    v = get_validator("idor")
    ctx = ValidatorContext(http=http, settings=_settings_with_sessions())
    res = v.validate(_finding(mock_server, method="POST"), ctx)
    assert res.verdict == ValidationResult.REFUTED
