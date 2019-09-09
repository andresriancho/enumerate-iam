import sys

def check_version():
    if sys.version_info[0] < 3:
        return 2
    else:
        return 3

PYTHON_VERSION = check_version()