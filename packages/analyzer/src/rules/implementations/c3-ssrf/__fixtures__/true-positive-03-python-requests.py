# True positive (Python lightweight-taint): request.args["target"] flows
# directly into urllib.request.urlopen() with zero propagation hops. The
# obfuscation pattern: the URL value is a variable named `target_host`
# rather than a string literal, defeating a naive
# `urlopen("http` regex. The lightweight taint engine still tracks the
# data flow from the source assignment to the sink call.
import urllib.request
from flask import request

def fetch_external():
    target_host = request.args["target"]
    response = urllib.request.urlopen(target_host)
    return response.read()
