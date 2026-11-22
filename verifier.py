from urllib.parse import urlparse


ALLOWED_HOSTS = {"127.0.0.1", "localhost"}


def is_local_target(url):
    """Allow verification of local lab targets only."""
    parsed = urlparse(url)

    return (
        parsed.scheme == "http"
        and parsed.hostname in ALLOWED_HOSTS
        and parsed.port == 5000
    )


def check_marker(response_text, marker):
    """Check whether a harmless test marker exists in a response."""
    if not marker:
        return False

    return marker in response_text