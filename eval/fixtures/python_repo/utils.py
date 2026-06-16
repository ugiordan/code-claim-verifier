def sanitize(input_str):
    return input_str.replace("<", "&lt;")

def helper():
    return 42

import subprocess as sp

def run_command(cmd):
    return sp.run(cmd, capture_output=True)
