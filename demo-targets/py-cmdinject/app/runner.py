"""A command runner with a classic shell-injection sink (CWE-78).

run_user_command builds a shell string from caller input and runs it with shell=True, so a value
like 'status; rm -rf /' injects a second command. The RAKSHA fix (template lane) passes an argument
list with shell=False, which removes the shell entirely. The app's own tests prove the normal path
is unchanged across the fix.
"""

import subprocess


def run_user_command(name):
    cmd = "echo handling " + name                 # BUG: input interpolated into a shell line
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.split()
