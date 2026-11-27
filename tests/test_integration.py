"""Integration unit tests that do not need a running Flask server."""
import pytest
from integration import _create_cases, ScanError, scan_target
from scope import validate_target


FORM_HTML = '<form><input name="q" type="text"><button>Submit</button></form>'


def test_form_discovery_creates_inert_probe():
    cases = _create_cases("http://127.0.0.1:5000/vulnerable", FORM_HTML, 5)
    assert len(cases) == 1
    assert cases[0]["parameter"] == "q"
    assert "%3Cb%3E" in cases[0]["test_url"]
    assert validate_target(cases[0]["test_url"])


def test_parameter_url_creates_probe():
    cases = _create_cases("http://127.0.0.1:5000/vulnerable?q=hello", "", 5)
    assert len(cases) == 1
    assert cases[0]["probe_input"].startswith("<b>")


def test_external_host_blocked():
    assert not validate_target("https://example.com")
    with pytest.raises(ScanError):
        scan_target("https://example.com")


def test_max_test_limit():
    with pytest.raises(ScanError):
        scan_target("http://127.0.0.1:5000/safe", max_tests=50)
