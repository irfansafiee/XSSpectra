
import html
from html.parser import HTMLParser


def detect_reflection(marker, response_text):
    """
    Check whether the test marker appears in the HTTP response.
    """

    if not marker or not response_text:
        return False

    return marker in response_text


def identify_context(marker, response_text):
    """
    Identify where the test marker appears in HTML.
    """

    contexts = []

    class ContextParser(HTMLParser):

        def __init__(self):
            super().__init__()
            self.inside_script = False

        def handle_starttag(self, tag, attrs):

            if tag == "script":
                self.inside_script = True

            for name, value in attrs:
                if value and marker in value:
                    contexts.append("html_attribute")

        def handle_startendtag(self, tag, attrs):
            for name, value in attrs:
                if value and marker in value:
                    contexts.append("html_attribute")

        def handle_endtag(self, tag):

            if tag == "script":
                self.inside_script = False

        def handle_data(self, data):

            if marker in data:

                if self.inside_script:
                    contexts.append("javascript")

                else:
                    contexts.append("html_text")

    parser = ContextParser()

    try:
        parser.feed(response_text)
        parser.close()
    except Exception:
        pass

    return list(dict.fromkeys(contexts))


def check_encoding(test_input, response_text):
    """
    Check whether special characters are HTML-encoded.
    """

    if not test_input or not response_text:
        return {
            "encoded": False,
            "raw_reflected": False,
            "encoded_reflected": False
        }

    encoded_input = html.escape(test_input, quote=True)

    raw_reflected = test_input in response_text
    encoded_reflected = encoded_input in response_text

    return {
        "encoded": encoded_reflected and not raw_reflected,
        "raw_reflected": raw_reflected,
        "encoded_reflected": encoded_reflected
    }



def classify_finding(reflected, contexts, encoding_result):
    """
    Classify potential XSS findings based on reflection,
    context, and encoding.
    """

    if not reflected:
        return {
            "risk": "Informational",
            "confidence": "High",
            "explanation": "No test marker was reflected in the response."
        }

    if "javascript" in contexts:
        return {
            "risk": "High",
            "confidence": "Medium",
            "explanation": "The test marker was reflected inside a JavaScript context."
        }

    if "html_attribute" in contexts:
        return {
            "risk": "High",
            "confidence": "Medium",
            "explanation": "The test marker was reflected inside an HTML attribute."
        }

    if "html_text" in contexts:
        if encoding_result["encoded"]:
            return {
                "risk": "Low",
                "confidence": "Medium",
                "explanation": "The test input appears to be HTML-encoded in an HTML text context."
            }

        return {
            "risk": "Medium",
            "confidence": "Medium",
            "explanation": "The test marker was reflected inside HTML text without detected encoding."
        }

    return {
        "risk": "Informational",
        "confidence": "Low",
        "explanation": "Reflection was detected, but its context could not be identified."
    }


def analyze_response(marker, test_input, response_text):
    """
    Perform complete XSS reflection and response analysis.
    """

    # Step 1: Check whether the marker is reflected
    reflected = detect_reflection(marker, response_text)

    # Step 2: Identify the reflection context
    contexts = identify_context(marker, response_text)

    # Step 3: Check whether the input is encoded
    encoding_result = check_encoding(test_input, response_text)

    # Step 4: Classify the potential finding
    classification = classify_finding(
        reflected,
        contexts,
        encoding_result
    )

    # Step 5: Return all analysis results
    return {
        "reflected": reflected,
        "contexts": contexts,
        "encoding": encoding_result,
        "risk": classification["risk"],
        "confidence": classification["confidence"],
        "explanation": classification["explanation"]
    }


if __name__ == "__main__":

    marker = "XSS_TEST_123"

    response = """
    <html>
        <body>
            <p>Search result: XSS_TEST_123</p>
        </body>
    </html>
    """

    result = detect_reflection(marker, response)

    print("Reflection detected:", result)

    print("\n--- Context Detection Tests ---")

    html_response = "<p>TEST123</p>"
    attribute_response = '<input value="TEST123">'
    script_response = '<script>var x = "TEST123";</script>'

    print("HTML text:", identify_context("TEST123", html_response))
    print("HTML attribute:", identify_context("TEST123", attribute_response))
    print("JavaScript:", identify_context("TEST123", script_response))


    print("\n--- Encoding Detection Tests ---")

    original_input = "<XSS_TEST>"

    safe_response = "<p>&lt;XSS_TEST&gt;</p>"

    unsafe_response = "<p><XSS_TEST></p>"

    print("Safe response:",
          check_encoding(original_input, safe_response))

    print("Raw response:",
          check_encoding(original_input, unsafe_response))


    print("\n--- Risk Classification Tests ---")

    test_result = classify_finding(
        True,
        ["html_attribute"],
        {
            "encoded": False,
            "raw_reflected": True,
            "encoded_reflected": False
        }
    )

    print("Classification:", test_result)


    print("\n--- Complete Analysis Test ---")

    final_result = analyze_response(
        "TEST123",
        "<TEST123>",
        '<input value="<TEST123>">'
    )

    print("Final Analysis:", final_result)


    print("\n--- No Reflection Test ---")

    no_reflection_result = analyze_response(
        "TEST123",
        "<TEST123>",
        "<html><body>Welcome to the website!</body></html>"
    )

    print("No Reflection Analysis:", no_reflection_result)


    print("\n--- Encoded Reflection Analysis Test ---")

    encoded_result = analyze_response(
        "TEST123",
        "<TEST123>",
        "<html><body>&lt;TEST123&gt;</body></html>"
    )

    print("Encoded Analysis:", encoded_result)


    print("\n--- JavaScript Context Analysis Test ---")

    javascript_result = analyze_response(
        "TEST123",
        "<TEST123>",
        '<html><script>var message = "TEST123";</script></html>'
    )

    print("JavaScript Analysis:", javascript_result)
