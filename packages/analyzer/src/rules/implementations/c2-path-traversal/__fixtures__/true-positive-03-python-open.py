# True positive: Python open() on a user-controlled path. Caught by
# the lightweight taint fallback.
import os


def serve(request):
    filename = request.args
    with open(filename, "rb") as f:
        return f.read()
