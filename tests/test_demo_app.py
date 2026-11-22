from demo_app.app import app


def test_vulnerable_page_reflects_input():
    client = app.test_client()

    response = client.get("/vulnerable?q=<b>hello</b>")

    assert response.status_code == 200
    assert b"<b>hello</b>" in response.data


def test_safe_page_escapes_input():
    client = app.test_client()

    response = client.get("/safe?q=<b>hello</b>")

    assert response.status_code == 200
    assert b"&lt;b&gt;hello&lt;/b&gt;" in response.data


def test_homepage_loads():
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200
    assert b"XSSpectra Local Testing Lab" in response.data

def test_vulnerable_page_handles_empty_input():
    client = app.test_client()

    response = client.get("/vulnerable")

    assert response.status_code == 200


def test_safe_page_handles_empty_input():
    client = app.test_client()

    response = client.get("/safe")

    assert response.status_code == 200
    assert b"Protected Reflection Demo" in response.data