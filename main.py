import argparse

from scope import (
    show_legal_disclaimer,
    confirm_authorization,
    validate_target,
)

from reporter import save_json_report, save_txt_report


def generate_reports(report_data, report_format):
    if report_format == "json":
        save_json_report(report_data)

    elif report_format == "txt":
        save_txt_report(report_data)

    elif report_format == "both":
        save_json_report(report_data)
        save_txt_report(report_data)

    else:
        raise ValueError("Invalid report format selected.")


def main():
    parser = argparse.ArgumentParser(
        description="XSSpectra - Context-Aware XSS Testing Tool"
    )

    parser.add_argument(
        "--target",
        default="http://127.0.0.1:5000/vulnerable",
        help="Authorized target URL (default: local Flask test website)"
    )

    parser.add_argument(
        "--report-format",
        choices=["json", "txt", "both"],
        default="both",
        help="Report output format (default: both)"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("XSSPECTRA - COMMAND LINE INTERFACE")
    print("=" * 60)

    show_legal_disclaimer()

    if not validate_target(args.target):
        print("[-] Target is outside the approved local testing scope.")
        print("[-] Operation cancelled.")
        return

    print(f"[+] Target approved: {args.target}")
    print(f"[+] Report format selected: {args.report_format}")

    if not confirm_authorization():
        return

    print("[+] CLI initialized successfully.")
    print("[+] Ready for authorized local testing.")
    print("[+] No scan has been started.")


if __name__ == "__main__":
    main()
