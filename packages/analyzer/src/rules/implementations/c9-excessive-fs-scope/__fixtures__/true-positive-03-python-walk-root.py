# True positive: os.walk("/") — full filesystem reconnaissance in a
# single call. Returns every directory + filename the host process
# can read.
import os

def enumerate_filesystem():
    found = []
    for dirpath, _dirnames, filenames in os.walk("/"):
        for name in filenames:
            found.append(os.path.join(dirpath, name))
    return found
