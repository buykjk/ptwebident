import random
import string
from hashlib import md5

def random_string(length: int = 10) -> str:
    """Provide a random string of letters"""
    return "".join(random.choices(string.ascii_letters, k = length))


def random_number(length: int = 6) -> str:
    """Provide a random string of digits"""
    return "".join(random.choices(string.digits, k = length))


def hash_bytes(bytes_: bytes) -> str:
    """Provide a hash of given bytes"""
    return md5(bytes_).hexdigest()