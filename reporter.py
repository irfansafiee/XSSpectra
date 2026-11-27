
import json
from datetime import datetime, timezone
from pathlib import Path


def save_json_report(report_data):
    if not isinstance(report_data, dict):
        raise TypeError("Report data must be a dictionary.")

    output_folder = Path(__file__).resolve().parent / "output"
    output_folder.mkdir(exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    filename = f"xsspectra_report_{timestamp}.json"
    file_path = output_folder / filename

    with file_path.open("w", encoding="utf-8") as file:
        json.dump(report_data, file, indent=4)

    print(f"[+] JSON report saved: {file_path}")

    return file_path


def save_txt_report(report_data):
    if not isinstance(report_data, dict):
        raise TypeError("Report data must be a dictionary.")

    output_folder = Path(__file__).resolve().parent / "output"
    output_folder.mkdir(exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    filename = f"xsspectra_report_{timestamp}.txt"
    file_path = output_folder / filename

    with file_path.open("w", encoding="utf-8") as file:
        file.write("=" * 50 + "\n")
        file.write("XSSPECTRA - SECURITY SCAN REPORT\n")
        file.write("=" * 50 + "\n\n")

        file.write(f"Target: {report_data.get('target', 'Unknown')}\n")
        file.write(
            f"Total Findings: {report_data.get('total_findings', 0)}\n"
        )
        file.write("\n")

        findings = report_data.get("findings", [])

        if not findings:
            file.write("No findings recorded.\n")
        else:
            for index, finding in enumerate(findings, start=1):
                file.write(f"Finding #{index}\n")
                file.write("-" * 30 + "\n")
                file.write(f"Type: {finding.get('type', 'Unknown')}\n")
                file.write(
                    f"Severity: {finding.get('severity', 'Unknown')}\n"
                )
                file.write(
                    f"Status: {finding.get('status', 'Unknown')}\n"
                )
                file.write("\n")

        file.write("TEST SUMMARY\n")
        file.write("-" * 30 + "\n")
        for test in report_data.get("tests", []):
            field = test.get("parameter", "Unknown")
            risk = test.get("risk", "Not assessed")
            encoded = test.get("encoded", False)
            error = test.get("error")
            file.write(
                f"Parameter: {field} | Risk: {risk} | "
                f"HTML encoded: {encoded}"
            )
            if error:
                file.write(f" | Error: {error}")
            file.write("\n")

        if report_data.get("note"):
            file.write("\nLIMITATION\n")
            file.write(report_data["note"] + "\n")

    print(f"[+] TXT report saved: {file_path}")

    return file_path

