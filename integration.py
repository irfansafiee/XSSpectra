"""Connect Harris's scanner, Imelia's analyzer and Irfan's verification helpers.

This adapter is restricted to the team's own Flask lab, 127.0.0.1:5000.
It uses inert HTML markup for the reflection/encoding comparison, not
executable JavaScript. Optional browser verification is a separate check.
"""
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from analyzer import analyze_response
from scanner import (
    build_parameter_test_cases,
    classify_input_field,
    create_session,
    discover_html_forms,
    make_marker,
    send_test_request,
)
from scope import validate_target
from verifier import check_marker, is_local_target

MAX_RESPONSE_BYTES = 250_000


class ScanError(Exception):
    """A controlled scan could not proceed."""


def _read_baseline(session, target, timeout):
    """Download at most MAX_RESPONSE_BYTES; never follow redirects."""
    try:
        with session.get(
            target, stream=True, timeout=timeout, allow_redirects=False
        ) as response:
            if 300 <= response.status_code < 400:
                raise ScanError("Redirect refused; only the approved local lab is allowed")
            if response.status_code >= 400:
                raise ScanError(f"Test website returned HTTP {response.status_code}")
            body = bytearray()
            for piece in response.iter_content(chunk_size=8192):
                if not piece:
                    continue
                remaining = MAX_RESPONSE_BYTES - len(body)
                if remaining <= 0:
                    break
                body.extend(piece[:remaining])
            return bytes(body).decode(response.encoding or "utf-8", errors="replace")
    except (requests.ConnectionError, requests.Timeout) as exc:
        raise ScanError("Cannot reach Flask lab. Start demo_app/app.py first") from exc
    except requests.RequestException as exc:
        raise ScanError(f"HTTP error: {type(exc).__name__}") from exc


def _replace_parameter(url, index, value):
    parsed = urlsplit(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    name, _ = params[index]
    params[index] = (name, value)
    return urlunsplit(parsed._replace(query=urlencode(params)))


def _create_cases(target, baseline_html, max_tests):
    """Use Harris's URL/HTML-form discovery, then add a non-executable HTML probe."""
    cases = []
    existing_params = parse_qsl(urlsplit(target).query, keep_blank_values=True)

    if existing_params:
        for candidate in build_parameter_test_cases(target):
            marker = candidate["marker"]
            harmless_input = f"<b>{marker}</b>"
            test_url = candidate["test_url"]
            params = parse_qsl(urlsplit(test_url).query, keep_blank_values=True)
            # Only replace the marker generated for this individual test case.
            index = next((i for i, (_, v) in enumerate(params) if v == marker), None)
            if index is None:
                continue
            test_url = _replace_parameter(test_url, index, harmless_input)
            if validate_target(test_url):
                cases.append({**candidate, "test_url": test_url,
                              "probe_input": harmless_input})
            if len(cases) >= max_tests:
                break
    else:
        # Irfan's demo uses an empty-action GET form with a field named q.
        for form in discover_html_forms(target, baseline_html):
            if form["method"] != "GET" or not validate_target(form["action"]):
                continue
            for field in form["inputs"]:
                if not classify_input_field(field)["testable"]:
                    continue
                marker = make_marker()
                harmless_input = f"<b>{marker}</b>"
                action = form["action"]
                parsed = urlsplit(action)
                params = parse_qsl(parsed.query, keep_blank_values=True)
                params.append((field["name"], harmless_input))
                test_url = urlunsplit(parsed._replace(query=urlencode(params)))
                if not validate_target(test_url):
                    continue
                cases.append({
                    "parameter": field["name"], "original_value": "",
                    "marker": marker, "test_url": test_url,
                    "probe_input": harmless_input,
                })
                if len(cases) >= max_tests:
                    break
            if len(cases) >= max_tests:
                break
    return cases


def scan_target(target, max_tests=5, timeout=5, verify_browser=False):
    """Return a report suitable for Huwaina's JSON and TXT reporters."""
    if not validate_target(target) or not is_local_target(target):
        raise ScanError("Only http://127.0.0.1:5000 is approved")
    if not (1 <= max_tests <= 10):
        raise ScanError("Maximum tests must be between 1 and 10")

    tests, findings = [], []
    with create_session() as session:
        html = _read_baseline(session, target, timeout)
        cases = _create_cases(target, html, max_tests)
        if not cases:
            raise ScanError("No testable GET parameters or text form fields were found")
        for case in cases:
            # Harris's code limits response sizes and does not follow redirects.
            result = send_test_request(
                session, case, timeout=timeout,
                max_response_size=MAX_RESPONSE_BYTES,
            )
            test = {
                "parameter": case["parameter"],
                "http_status": result.get("status_code"),
                "elapsed_seconds": result.get("elapsed_seconds"),
                "error": result.get("error"),
                "marker_reflected": False,
                "risk": "Not assessed",
                "verification": "not_requested",
            }
            if result.get("error"):
                tests.append(test)
                continue
            if 300 <= (result.get("status_code") or 0) < 400:
                test["error"] = "Redirect refused"
                tests.append(test)
                continue
            if result.get("response_truncated"):
                test["error"] = "Response too large; analysis skipped"
                tests.append(test)
                continue

            analysis = analyze_response(
                case["marker"], case["probe_input"], result["response_text"]
            )
            # Reuse Irfan's harmless marker checker, without claiming it verifies execution.
            test["marker_reflected"] = check_marker(result["response_text"], case["marker"])
            test["risk"] = analysis["risk"]
            test["contexts"] = analysis["contexts"]
            test["encoded"] = analysis["encoding"]["encoded"]
            is_unescaped = analysis["encoding"]["raw_reflected"]

            if is_unescaped:
                finding = {
                    "type": "Potential HTML injection / XSS exposure",
                    "severity": analysis["risk"],
                    "status": "Not browser-verified",
                    "parameter": case["parameter"],
                    "contexts": analysis["contexts"],
                    "confidence": analysis["confidence"],
                    "explanation": analysis["explanation"],
                }
                if verify_browser:
                    from browser_verify import verify_local_execution
                    verification = verify_local_execution(target, case["parameter"])
                    test["verification"] = verification["status"]
                    if verification["status"] == "confirmed_execution":
                        finding["status"] = "Confirmed in local browser"
                        finding["severity"] = "High"
                    else:
                        finding["status"] = f"Not confirmed ({verification['status']})"
                findings.append(finding)
            tests.append(test)

    # The report omits submitted input values and HTML response bodies.
    parsed = urlsplit(target)
    display_target = urlunsplit(parsed._replace(query="", fragment=""))
    return {
        "tool": "XSSpectra",
        "target": display_target,
        "date_utc": datetime.now(timezone.utc).isoformat(),
        "total_tests": len(tests),
        "total_findings": len(findings),
        "findings": findings,
        "tests": tests,
        "note": "HTML reflection and encoding are indicators, not proof of XSS execution. "
                "Browser confirmation is reported only when explicitly requested and successful.",
    }
