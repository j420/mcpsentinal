# True negative: yaml.safe_load — SafeLoader rejects !!python/object
# and related object-construction tags.
import yaml

def parse_config(request):
    content = request.form["config"]
    config = yaml.safe_load(content)
    return config
