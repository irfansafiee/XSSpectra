
import unittest

from analyzer import (
    detect_reflection,
    identify_context,
    check_encoding,
    classify_finding,
    analyze_response
)


class TestXSSAnalyzer(unittest.TestCase):

    def test_reflection_detected(self):
        result = detect_reflection(
            "TEST123",
            "<p>TEST123</p>"
        )
        self.assertTrue(result)

    def test_no_reflection(self):
        result = detect_reflection(
            "TEST123",
            "<p>Welcome!</p>"
        )
        self.assertFalse(result)

    def test_html_text_context(self):
        result = identify_context(
            "TEST123",
            "<p>TEST123</p>"
        )
        self.assertIn("html_text", result)

    def test_html_attribute_context(self):
        result = identify_context(
            "TEST123",
            '<input value="TEST123">'
        )
        self.assertIn("html_attribute", result)

    def test_javascript_context(self):
        result = identify_context(
            "TEST123",
            '<script>var message = "TEST123";</script>'
        )
        self.assertIn("javascript", result)

    def test_html_encoding(self):
        result = check_encoding(
            "<TEST123>",
            "<p>&lt;TEST123&gt;</p>"
        )
        self.assertTrue(result["encoded"])

    def test_high_risk_classification(self):
        result = classify_finding(
            True,
            ["html_attribute"],
            {
                "encoded": False,
                "raw_reflected": True,
                "encoded_reflected": False
            }
        )
        self.assertEqual(result["risk"], "High")

    def test_complete_analysis(self):
        result = analyze_response(
            "TEST123",
            "<TEST123>",
            '<input value="<TEST123>">'
        )

        self.assertTrue(result["reflected"])
        self.assertIn("html_attribute", result["contexts"])
        self.assertEqual(result["risk"], "High")


    def test_empty_marker(self):
        with self.assertRaises(ValueError):
            analyze_response(
                "",
                "<TEST123>",
                "<p>TEST123</p>"
            )

    def test_empty_test_input(self):
        with self.assertRaises(ValueError):
            analyze_response(
                "TEST123",
                "",
                "<p>TEST123</p>"
            )

    def test_invalid_input_type(self):
        with self.assertRaises(TypeError):
            analyze_response(
                123,
                "<TEST123>",
                "<p>TEST123</p>"
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
