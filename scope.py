
from urllib.parse import urlsplit


def show_legal_disclaimer():
    print("=" * 60)
    print("XSSPECTRA - ETHICAL HACKING TOOL")
    print("=" * 60)
    print("LEGAL DISCLAIMER")
    print()
    print("This tool is intended for authorized security testing only.")
    print("Unauthorized access or testing may violate Malaysia's")
    print("Computer Crimes Act 1997 (Act 563).")
    print()
    print("You must have explicit permission from the system owner")
    print("before conducting any security tests.")
    print()
    print("The developers are not responsible for misuse.")
    print("=" * 60)


def confirm_authorization():
    answer = input("Do you have authorization to test? (yes/no): ")
    answer = answer.strip().lower()

    if answer == "yes":
        print("[+] Authorization acknowledged.")
        return True

    print("[-] Authorization not confirmed. Operation cancelled.")
    return False


def validate_target(url):
    if not isinstance(url, str) or url != url.strip():
        return False

    if any(ord(char) < 32 or ord(char) == 127 for char in url):
        return False

    try:
        parsed = urlsplit(url)

        if parsed.scheme != "http":
            return False

        if parsed.hostname != "127.0.0.1":
            return False

        if parsed.port != 5000:
            return False

        if parsed.username is not None or parsed.password is not None:
            return False

        return True

    except ValueError:
        return False


if __name__ == "__main__":
    show_legal_disclaimer()

    if confirm_authorization():
        print("[+] Ready for authorized testing.")
        print("[+] No scan has been started.")
