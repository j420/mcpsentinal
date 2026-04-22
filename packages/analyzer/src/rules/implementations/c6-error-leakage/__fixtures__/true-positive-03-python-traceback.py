# True positive: Python flask handler that returns the full traceback
# (file paths, line numbers, surrounding code context) in the response
# body. Defeats a naive grep for `error.stack` because Python uses a
# completely different API surface (traceback.format_exc).
import traceback
from flask import jsonify

def handler(req):
    try:
        process(req)
    except Exception:
        return jsonify({"error": traceback.format_exc()})
