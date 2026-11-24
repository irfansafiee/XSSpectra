
"""
XSSpectra - Context-Aware XSS Fuzzer
Member 1: Core Scanner Foundation

This module provides local-only URL validation,
HTTP session setup, and harmless test marker generation.f
"""

from urllib.parse import urlsplit, parse_qsl, urlencode
import uuid
import requests
import time
from bs4 import BeautifulSoup
import json
from analyzer import analyze_response, display_result

# --------------------------------------------------
# 1. SAFETY CONFIGURATION
# --------------------------------------------------

ALLOWED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1"
}

USER_AGENT = "XSSpectra/1.0 (Authorized Local Testing)"


# --------------------------------------------------
# 2. LOCAL URL VALIDATION
# --------------------------------------------------

def validate_local_url(url: str) -> str:
    """
    Accept only HTTP/HTTPS URLs pointing to localhost.
    Reject external websites and URLs containing credentials.
    """

    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL cannot be empty.")

    url = url.strip()

    if any(character.isspace() for character in url):
        raise ValueError("URL must not contain whitespace.")

    parsed = urlsplit(url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are allowed.")

    if not parsed.hostname:
        raise ValueError("Invalid URL: hostname is missing.")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing login credentials are not allowed.")

    try:
        _ = parsed.port
    except ValueError:
        raise ValueError("Invalid port number.")

    hostname = parsed.hostname.lower()

    if hostname not in ALLOWED_HOSTS:
        raise ValueError(
            "Blocked: XSSpectra only scans localhost addresses."
        )

    return url


# --------------------------------------------------
# 3. HTTP SESSION SETUP
# --------------------------------------------------

def create_session() -> requests.Session:
    """
    Create an HTTP session for local testing.
    Environment proxy settings are disabled.
    """

    session = requests.Session()

    session.trust_env = False

    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml"
    })

    return session


# --------------------------------------------------
# 4. HARMLESS TEST MARKER GENERATION
# --------------------------------------------------

def make_marker() -> str:
    """
    Generate a unique harmless marker.
    This is used to identify reflected input in responses.
    """

    unique_id = uuid.uuid4().hex[:12].upper()

    return f"XSSPECTRA_{unique_id}"


# --------------------------------------------------
# 5. INITIAL SELF-TEST
# --------------------------------------------------

# --------------------------------------------------
# URL PARAMETER DETECTION
# --------------------------------------------------

def discover_url_parameters(url: str) -> list[tuple[str, str]]:
    """
    Discover query parameter names and values.
    Example: ?q=hello&page=2
    """

     # Validate that the URL is within local scope.
    validated_url = validate_local_url(url)

     # Separate the URL into components.
    parsed_url = urlsplit(validated_url)

     # Extract query parameters.
    parameters = parse_qsl(
        parsed_url.query,
        keep_blank_values=True
    )

     # Ignore parameters with empty names.
    parameters = [
        (name, value)
        for name, value in parameters
        if name
    ]

    return parameters
    
# --------------------------------------------------
     # URL PARAMETER TEST CASE GENERATION
# --------------------------------------------------

def build_parameter_test_cases(url: str) -> list[dict[str, str]]:
    """
    Create one harmless marker test URL for each
    discovered URL parameter.

    Only one parameter is changed per test.
    """

    # Validate the target URL.
    validated_url = validate_local_url(url)

    # Separate URL components.
    parsed_url = urlsplit(validated_url)

    # Extract the original parameters.
    parameters = parse_qsl(
        parsed_url.query,
        keep_blank_values=True
    )

    test_cases = []

    # Create one test for each parameter.
    for index, (name, original_value) in enumerate(parameters):

        if not name:
            continue

    # Generate a unique harmless marker.
        marker = make_marker()

    # Copy the original parameters.
        modified_parameters = parameters.copy()

     # Replace only the current parameter.
        modified_parameters[index] = (name, marker)

    # Convert parameters back into a query string.
        modified_query = urlencode(modified_parameters)

    # Construct the modified test URL.
        test_url = parsed_url._replace(
            query=modified_query
        ).geturl()

        test_cases.append({
            "parameter": name,
            "original_value": original_value,
            "marker": marker,
            "test_url": test_url
        })

    return test_cases

# --------------------------------------------------
     # 7. HTTP REQUEST AND RESPONSE COLLECTION
# --------------------------------------------------

def send_test_request(
    session: requests.Session,
    test_case: dict,
    timeout: int = 5,
    max_response_size: int = 1_000_000
) -> dict:
    """
    Send one harmless GET test request to a local target.

    Collect:
    - HTTP status code
    - Response headers
    - Response HTML
    - Response time
    - Marker reflection result
    - Connection errors
    """

    test_url = validate_local_url(test_case["test_url"])
    marker = test_case["marker"]

    start_time = time.perf_counter()

    try:
    # Send GET request without following redirects.
        with session.get(
            test_url,
            timeout=timeout,
            allow_redirects=False,
            stream=True
        ) as response:

            response_body = bytearray()

    # Read response in chunks with a size limit.
            for chunk in response.iter_content(chunk_size=8192):

                if not chunk:
                    continue

                remaining = max_response_size - len(response_body)

                if len(chunk) > remaining:
                    response_body.extend(chunk[:remaining])
                    break

                response_body.extend(chunk)

            elapsed = time.perf_counter() - start_time

    # Decode response using the server's encoding.
            encoding = response.encoding or "utf-8"

            response_text = bytes(response_body).decode(
                encoding,
                errors="replace"
            )

            return {
                "method": "GET",
                "url": test_url,
                "parameter": test_case["parameter"],
                "marker": marker,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "response_text": response_text,
                "elapsed_seconds": round(elapsed, 4),
                "marker_reflected": marker in response_text,
                "response_truncated": len(response_body) >= max_response_size,
                "original_value": test_case["original_value"],
                "error": None
                
            }

    except requests.Timeout:
        error = "Request timed out"

    except requests.ConnectionError:
        error = "Could not connect to local application"

    except requests.RequestException as exception:
        error = str(exception)

    except ValueError as exception:
        error = str(exception)

    elapsed = time.perf_counter() - start_time

    return {
        "method": "GET",
        "url": test_url,
        "parameter": test_case["parameter"],
        "marker": marker,
        "status_code": None,
        "headers": {},
        "response_text": "",
        "elapsed_seconds": round(elapsed, 4),
        "marker_reflected": False,
        "response_truncated": False,
        "error": error
    }

# --------------------------------------------------
     # 8. HTML FORM DISCOVERY
# --------------------------------------------------

def discover_html_forms(url: str, html_content: str) -> list[dict]:
    """
    Analyse HTML and discover forms and their input fields.

    Extracts:
    - Form action
    - Form method
    - Input names
    - Input types
    - Textarea fields
    - Select fields

    Does not submit any forms.
    """

    # Validate the target URL.
    validated_url = validate_local_url(url)

    # Parse the HTML response.
    soup = BeautifulSoup(html_content, "html.parser")

    discovered_forms = []

    # Find all HTML forms.
    forms = soup.find_all("form")

    for form_number, form in enumerate(forms, start=1):

    # Get the form action.
        action = form.get("action", "").strip()

    # Resolve relative form actions.
        from urllib.parse import urljoin

        if action:
            form_action = urljoin(validated_url, action)
        else:
            form_action = validated_url

    # Only retain local form actions.
        try:
            form_action = validate_local_url(form_action)
        except ValueError:
            continue

    # Get the form method.
        method = form.get("method", "GET").upper()

        if method not in {"GET", "POST"}:
            method = "GET"

        input_fields = []

    # Discover input elements.
        for element in form.find_all(["input", "textarea", "select"]):

            field_name = element.get("name")

            if not field_name:
                continue

            field_type = (
                element.get("type", "text")
                if element.name == "input"
                else element.name
            )

            input_fields.append({
                "name": field_name,
                "type": field_type.lower()
            })

        discovered_forms.append({
            "form_number": form_number,
            "action": form_action,
            "method": method,
            "inputs": input_fields
        })

    return discovered_forms

# 9. INPUT CLASSIFICATION AND SAFETY FILTERING
# --------------------------------------------------

def classify_input_field(field: dict) -> dict:
    """
    Classify discovered HTML fields and determine
    whether they are suitable for safe test preparation.
    """

    name = field.get("name", "").strip().lower()
    field_type = field.get("type", "text").strip().lower()

    # Field names commonly associated with sensitive data.
    sensitive_keywords = [
        "password",
        "passwd",
        "secret",
        "token",
        "csrf",
        "auth",
        "session",
        "api_key",
        "apikey",
        "credit_card"
    ]

    if any(keyword in name for keyword in sensitive_keywords):
        return {
            "classification": "Sensitive/Security Field",
            "testable": False,
            "reason": "Field name indicates sensitive information"
        }

    # Sensitive or non-user-text input types.
    excluded_types = {
        "hidden",
        "password",
        "submit",
        "button",
        "reset",
        "file",
        "image"
    }

    if field_type in excluded_types:
        return {
            "classification": "Excluded Input",
            "testable": False,
            "reason": "Input type is excluded from automatic testing"
        }

    # Email fields may contain personal information.
    if field_type == "email":
        return {
            "classification": "Personal Data Field",
            "testable": False,
            "reason": "Email fields are excluded by default"
        }

    # Ordinary text fields.
    if field_type in {"text", "search", "textarea"}:
        return {
            "classification": "Text Input",
            "testable": True,
            "reason": "Suitable for harmless marker preparation"
        }

    # Other fields are not automatically tested.
    return {
        "classification": "Other Input",
        "testable": False,
        "reason": "Input type is not enabled for automatic testing"
    }

# --------------------------------------------------
# 10. JSON RESULTS EXPORT
# --------------------------------------------------

def export_results(results, filename="xsspectra_results.json"):
    """
    Export scanner findings into a JSON file.
    """

    report = {
        "project": "XSSpectra",
        "version": "1.0.0",
        "total_tests": len(results),
        "successful_requests": sum(
            1 for item in results
            if item.get("status_code") is not None
        ),
        "results": results
    }

    try:
        with open(filename, "w", encoding="utf-8") as file:
            json.dump(
                report,
                file,
                indent=4,
                ensure_ascii=False
            )

        print(f"[+] Results exported to {filename}")

    except (OSError, TypeError, ValueError) as error:
        print("[-] JSON export failed:", error)

def main():

    print("=" * 45)
    print("       XSSPECTRA SCANNER")
    print("       Member 1 - Core Scanner")
    print("=" * 45)

    test_url = "http://127.0.0.1:5000/vulnerable?q=hello"

    try:
        validated_url = validate_local_url(test_url)
        print("[+] Local URL validation successful")
        print("[+] Test URL:", validated_url)
        parameters = discover_url_parameters(validated_url)

        print("\n[+] URL parameters discovered:")

        if parameters:
             for name, value in parameters:
                  print(f"    Parameter: {name} | Value: {value}")

        else:
             print("    No URL parameters found.")
    # Generate harmless marker test cases
        test_cases = build_parameter_test_cases(validated_url)

        print("\n[+] Generated parameter test cases:")

        for number, case in enumerate(test_cases, start=1):
            print(f"\n    Test {number}")
            print(f"    Parameter: {case['parameter']}")
            print(f"    Original value: {case['original_value']}")
            print(f"    Marker: {case['marker']}")
            print(f"    Test URL: {case['test_url']}")

    except ValueError as error:
        print("[-] URL validation failed:", error)
        return

    marker = make_marker()
    print("[+] Harmless test marker generated:", marker)

    
    # Execute HTTP tests and collect responses
    print("\n[+] Starting HTTP request tests...")

    results = []

    with create_session() as session:

        print("[+] HTTP session created successfully")
        print("[+] Environment proxy settings disabled")

        for number, case in enumerate(test_cases, start=1):

            print(f"\n[+] Sending test {number}")
            print(f"    Parameter: {case['parameter']}")

            result = send_test_request(session, case)

            results.append(result)


            # Discover HTML forms in the response
            if result["response_text"]:

                forms = discover_html_forms(
                    result["url"],
                    result["response_text"]
                )
                
                # Save discovered forms into scan results
                result["forms"] = forms

                print(f"    [+] Forms discovered: {len(forms)}")

                for form in forms:

                    print(f"        Form action: {form['action']}")
                    print(f"        Form method: {form['method']}")

                    
                    for field in form["inputs"]:

                        classification = classify_input_field(field)

                        field.update(classification)

                        print(
                            f"        Input: {field['name']} "
                            f"| Type: {field['type']}"
                        )

                        print(
                            f"        Classification: "
                            f"{field['classification']}"
                        )

                        print(
                            f"        Automatic testing: "
                            f"{'Allowed' if field['testable'] else 'Skipped'}"
                        )

                        print(
                            f"        Reason: {field['reason']}"
                        )

            if result["error"]:
                print("    [-] Request failed:", result["error"])
                continue

            # Perform XSS response analysis
            print("\n    [+] Starting XSS analysis...")

            analysis = analyze_response(
                result["marker"],
                result["original_value"],
                result["response_text"]
            )

            display_result(analysis)

            # Store analysis results
            result["analysis"] = analysis

            print("    [+] HTTP Status:", result["status_code"])
            print("    [+] Response Time:",
                  result["elapsed_seconds"], "seconds")

            print("    [+] Marker Reflected:",
                  result["marker_reflected"])

            print("    [+] Response Size:",
                  len(result["response_text"]), "characters")

            if result["response_truncated"]:
                print("    [!] Response was truncated")

    print("\n[+] HTTP testing completed")
    print("[+] Total test cases:", len(results))

    # Export collected results
    print("\n[+] Exporting scan results...")

    export_results(results)

    # Confirm that external websites are blocked.
    try:
        validate_local_url("https://example.com")
        print("[-] Unexpected: external URL was accepted.")

    except ValueError:
        print("[+] External URL correctly blocked")

    print("=" * 45)
    print("[+] XSSpectra foundation is ready!")
    print("=" * 45)


    print("\n[+] Testing input classification:")

    sample_fields = [
        {"name": "search", "type": "text"},
        {"name": "password", "type": "password"},
        {"name": "csrf_token", "type": "hidden"},
        {"name": "email", "type": "email"},
        {"name": "comment", "type": "textarea"}
    ]

    for field in sample_fields:

        result = classify_input_field(field)

        print(
            f"    {field['name']}: "
            f"{result['classification']} | "
            f"Testable: {result['testable']}"
        )


if __name__ == "__main__":
    main()
