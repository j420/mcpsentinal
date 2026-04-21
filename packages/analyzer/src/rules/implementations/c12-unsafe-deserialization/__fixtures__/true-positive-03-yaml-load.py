# True positive: yaml.load without SafeLoader — !!python/object in the
# payload yields arbitrary code execution during reconstruction.
import yaml

def parse_config(request):
    content = request.form["config"]
    config = yaml.load(content)
    return config
