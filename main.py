"""Member 4 command-line interface, ethical controls, and report generation."""
import argparse

from scope import show_legal_disclaimer, confirm_authorization, validate_target
from reporter import save_json_report, save_txt_report
from integration import ScanError, scan_target


def generate_reports(report_data, report_format):
    """Use the reporting functions already written by Member 4."""
    if report_format == "json":
        return [save_json_report(report_data)]
    if report_format == "txt":
        return [save_txt_report(report_data)]
    if report_format == "both":
        return [save_json_report(report_data), save_txt_report(report_data)]
    raise ValueError("Invalid report format selected.")


def main():
    parser = argparse.ArgumentParser(
        description="XSSpectra - Context-Aware XSS Testing Tool"
    )
    parser.add_argument(
        "--target", default="http://127.0.0.1:5000/vulnerable",
        help="Authorized local Flask target URL (default: /vulnerable)",
    )
    parser.add_argument(
        "--report-format", choices=["json", "txt", "both"], default="both",
        help="Local report format (default: both)",
    )
    parser.add_argument(
        "--max-tests", type=int, default=5,
        help="Maximum harmless test requests, 1 to 10 (default: 5)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Validate configuration without making network requests",
    )
    parser.add_argument(
        "--verify-browser", action="store_true",
        help="Optional Playwright confirmation on the approved local Flask lab",
    )
    args = parser.parse_args()

    print("=" * 55)
    print("XSSPECTRA - LOCAL AUTHORIZED TESTING")
    print("=" * 55)
    show_legal_disclaimer()
    if not validate_target(args.target):
        print("[-] Target outside approved scope: 127.0.0.1:5000 only")
        return 2
    if not (1 <= args.max_tests <= 10):
        print("[-] --max-tests must be between 1 and 10")
        return 2
    print(f"[+] Target: {args.target}")
    print(f"[+] Report format: {args.report_format}")
    print(f"[+] Maximum tests: {args.max_tests}")
    if not confirm_authorization():
        return 2
    if args.dry_run:
        print("[+] Dry run completed; no HTTP requests were sent")
        return 0

    print("[+] Running harmless reflection/encoding tests...")
    try:
        report = scan_target(
            args.target, max_tests=args.max_tests,
            verify_browser=args.verify_browser,
        )
    except KeyboardInterrupt:
        print("\n[!] Emergency stop (Ctrl+C): scan cancelled cleanly")
        return 130
    except ScanError as error:
        print(f"[-] Scan could not complete: {error}")
        return 1
    except Exception as error:
        print(f"[-] Unexpected scan error: {type(error).__name__}: {error}")
        return 1

    print(f"[+] Tests completed: {report['total_tests']}")
    print(f"[+] Potential findings: {report['total_findings']}")
    for finding in report["findings"]:
        print(f"    [{finding['severity']}] {finding['parameter']}: {finding['status']}")
    for test in report["tests"]:
        if test["error"]:
            print(f"    [!] {test['parameter']}: {test['error']}")
        elif test["encoded"]:
            print(f"    [SAFE INDICATOR] {test['parameter']}: HTML-encoded reflection")
    generate_reports(report, args.report_format)
    print("[+] Note: A potential finding is not automatically confirmed XSS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
