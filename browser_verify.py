"""Optional, isolated Chromium check of a harmless script marker on the local lab.

Used only for http://127.0.0.1:5000; no outbound requests are permitted.
"""
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4

from scope import validate_target


def verify_local_execution(url, parameter="q"):
    if not validate_target(url):
        return {"status": "out_of_scope"}
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as BrowserTimeout
    except ImportError:
        return {"status": "playwright_missing"}

    marker = f"XSSPECTRA_{uuid4().hex[:12]}"
    probe = f'<script>window.__xsspectra_demo = "{marker}"</script>'
    parsed = urlsplit(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    for index, (name, _) in enumerate(params):
        if name == parameter:
            params[index] = (name, probe)
            replaced = True
            break
    if not replaced:
        params.append((parameter, probe))
    verification_url = urlunsplit(parsed._replace(query=urlencode(params), fragment=""))
    if not validate_target(verification_url):
        return {"status": "out_of_scope"}

    try:
        with sync_playwright() as automation:
            browser = automation.chromium.launch(headless=True)
            try:
                context = browser.new_context(service_workers="block")
                try:
                    # Refuse all requests except to the approved localhost lab.
                    def enforce_route(route):
                        if validate_target(route.request.url):
                            route.continue_()
                        else:
                            route.abort()
                    context.route("**/*", enforce_route)
                    page = context.new_page()
                    response = page.goto(verification_url, wait_until="domcontentloaded", timeout=8000)
                    if response is None or 300 <= response.status < 400:
                        return {"status": "navigation_failed"}
                    executed = page.evaluate(
                        "(token) => window.__xsspectra_demo === token", marker
                    )
                    return {"status": "confirmed_execution" if executed else "not_confirmed"}
                finally:
                    context.close()
            finally:
                browser.close()
    except BrowserTimeout:
        return {"status": "timeout"}
    except Exception as error:
        return {"status": "browser_error", "reason": str(error)[:160]}
