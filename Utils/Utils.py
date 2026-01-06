import string
import random

def generate_refresh_token(length=32):
    """Generate a random refresh token."""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))