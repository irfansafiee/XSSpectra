
import html
from html.parser import HTMLParser
from colorama import Fore, Style, init

init(autoreset=True)

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

    # Validate input types
    if not all(isinstance(value, str) for value in
               [marker, test_input, response_text]):
        raise TypeError(
            "Marker, test input, and response must be strings."
        )

    # Validate empty marker and test input
    if not marker.strip() or not test_input.strip():
        raise ValueError(
            "Marker and test input cannot be empty."
        )

    # Step 1: Check reflection
    reflected = detect_reflection(marker, response_text)

    # Step 2: Identify context
    contexts = identify_context(marker, response_text)

    # Step 3: Check encoding
    encoding_result = check_encoding(test_input, response_text)

    # Step 4: Classify finding
    classification = classify_finding(
        reflected,
        contexts,
        encoding_result
    )

    # Step 5: Return analysis
    return {
        "reflected": reflected,
        "contexts": contexts,
        "encoding": encoding_result,
        "risk": classification["risk"],
        "confidence": classification["confidence"],
        "explanation": classification["explanation"]
    }

def display_result(result):
    """
    Display XSS analysis results with terminal colours.
    """

    risk = result["risk"]

    if risk == "High":
        risk_color = Fore.RED
    elif risk == "Medium":
        risk_color = Fore.YELLOW
    elif risk == "Low":
        risk_color = Fore.GREEN
    else:
        risk_color = Fore.CYAN

    print("\n" + "=" * 45)
    print(Fore.CYAN + Style.BRIGHT + "          XSSpectra - ANALYSIS REPORT")
    print("=" * 45)

    print(f"Reflection       : {'Detected' if result['reflected'] else 'Not Detected'}")
    print(f"Context          : {', '.join(result['contexts']) if result['contexts'] else 'Unknown'}")
    print(f"Encoding         : {'Detected' if result['encoding']['encoded'] else 'Not Detected'}")

    print("-" * 45)
    print(f"Risk Level       : {risk_color}{Style.BRIGHT}{risk}")
    print(f"Confidence       : {result['confidence']}")
    print("-" * 45)

    print("Explanation:")
    print(result["explanation"])

    print("=" * 45)



if __name__ == "__main__":

    marker = "TEST123"
    test_input = "<TEST123>"

    response = '<input value="<TEST123>">'

    result = analyze_response(
        marker,
        test_input,
        response
    )

    display_result(result)
