# py-noharness — a Python target that ships no fuzz harness

`convert(spec)` builds a shell command from the operator's string (`shell=True`): a command
injection. No harness, no `if __name__`. Autofuzz discovers `convert`, synthesizes a harness, and
drives the find→fix→prove loop.
