import hashlib


def generate_sha256(data):
    """
    Generate SHA-256 hash for data.
    """

    if isinstance(data, str):
        data = data.encode("utf-8")

    return hashlib.sha256(data).hexdigest()


def generate_hash(data):
    """
    Generate SHA-256 hash.
    Kept for compatibility with the application.
    """

    return generate_sha256(data)


def verify_sha256(data, expected_hash):
    """
    Verify SHA-256 hash.
    """

    actual_hash = generate_sha256(data)

    return actual_hash == expected_hash


def verify_hash(data, expected_hash):
    """
    Verify the hash of the supplied data.
    Kept for compatibility with the application.
    """

    return verify_sha256(data, expected_hash)