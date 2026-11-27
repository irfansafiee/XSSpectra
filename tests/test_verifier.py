from verifier import is_local_target, check_marker


def test_accepts_local_lab_url():
    assert is_local_target("http://127.0.0.1:5000")


def test_accepts_localhost():
    assert is_local_target("http://localhost:5000")


def test_rejects_external_url():
    assert not is_local_target("https://example.com")


def test_rejects_wrong_port():
    assert not is_local_target("http://127.0.0.1:8000")


def test_marker_found():
    assert check_marker("Hello XSSpectra", "XSSpectra")


def test_marker_not_found():
    assert not check_marker("Hello world", "XSSpectra")


def test_empty_marker_rejected():
    assert not check_marker("Hello world", "")