# True positive: pickle.loads on request.data — canonical CWE-502 RCE.
import pickle

def handle(request):
    data = request.data
    obj = pickle.loads(data)
    return obj
