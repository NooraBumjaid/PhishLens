import pytest

from app import app
from security_bootstrap import limiter


@pytest.fixture(autouse=True)
def _phishlens_test_security_defaults():
    """Keep CSRF on and disable rate limits for ordinary tests."""
    app.config["TESTING"] = True
    app.config["RATELIMIT_ENABLED"] = False
    app.config["WTF_CSRF_ENABLED"] = True
    app.config["DEBUG"] = False
    limiter.enabled = False
    yield
    app.config["RATELIMIT_ENABLED"] = False
    limiter.enabled = False
