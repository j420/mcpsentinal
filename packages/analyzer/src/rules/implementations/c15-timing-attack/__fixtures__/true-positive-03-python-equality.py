# True positive: Python `==` between a server-side secret and a
# request-supplied value. Python's `==` short-circuits the same way
# as JavaScript's `===` on string operands.
import os

API_KEY = os.environ.get("API_KEY", "")

def check_auth(provided_token):
    if API_KEY == provided_token:
        return True
    return False
