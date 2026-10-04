"""`python -m raksha` — replay a finding's evidence, independently of the run that found it.

Every replay script in an evidence bundle ends in one command. For an exploit that is the target's own
harness fed the shipped reproducer; for a deterministic match it is one of these subcommands, which
re-read the target's file and re-run the same detector:

    python -m raksha match ECOSYSTEM PACKAGE VERSION --advisory ID [--manifest PATH]
    python -m raksha secret-match RULE PATH LINE
    python -m raksha spec-check ORACLE METHOD API_PATH --spec SPEC_PATH
    python -m raksha crypto-match RULE PATH LINE
    python -m raksha binary-match RULE PATH [OFFSET]

Exit status mirrors a crashing exploit: 1 = the finding REPRODUCED, 0 = it did not (e.g. the manifest
was bumped, the secret removed), 2 = the replay could not run. Run from the target's root.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPRODUCED, NOT_REPRODUCED, ERROR = 1, 0, 2


def _match(a: argparse.Namespace) -> int:
    from .lanes import supply, vulndb
    db = vulndb.load()
    adv = db.by_id(a.advisory)
    if adv is None:
        print(f"unknown advisory {a.advisory}")
        return ERROR
    version = a.version
    if a.manifest:
        path = Path(a.manifest)
        if not path.exists():
            print(f"manifest {path} not found")
            return ERROR
        deps = supply.parse_manifest(path.name, path.read_text(errors="replace"), str(path))
        mine = [d for d in deps if d.ecosystem == a.ecosystem
                and vulndb.normalise_package(a.ecosystem, d.package)
                == vulndb.normalise_package(a.ecosystem, a.package)]
        if not mine:
            print(f"NOT REPRODUCED: {a.package} is no longer pinned in {path}")
            return NOT_REPRODUCED
        version = mine[0].version
    hit = vulndb.affected_range(adv, version)
    if hit is None:
        print(f"NOT REPRODUCED: {a.package}@{version} is outside every affected range of {a.advisory}")
        return NOT_REPRODUCED
    print(f"REPRODUCED: {a.package}@{version} is in {a.advisory} affected range "
          f"[{hit.get('introduced')}, {hit.get('fixed') or 'unfixed'})")
    return REPRODUCED


def _secret(a: argparse.Namespace) -> int:
    from .lanes import secrets
    path = Path(a.path)
    if not path.exists():
        print(f"{path} not found")
        return ERROR
    lines = path.read_text(errors="replace").splitlines()
    if not 1 <= a.line <= len(lines):
        print(f"NOT REPRODUCED: {path} has no line {a.line}")
        return NOT_REPRODUCED
    hits = [f for f in secrets.scan_text(lines[a.line - 1], str(path)) if f.oracle == f"secrets:{a.rule}"]
    if hits:
        print(f"REPRODUCED: {a.rule} still matches at {path}:{a.line} ({hits[0].message.split(' — ')[-1]})")
        return REPRODUCED
    print(f"NOT REPRODUCED: {a.rule} no longer matches at {path}:{a.line}")
    return NOT_REPRODUCED


def _spec(a: argparse.Namespace) -> int:
    from .lanes import service
    spec = Path(a.spec)
    if not spec.exists():
        print(f"{spec} not found")
        return ERROR
    want = f"{a.method.upper()} {a.api_path}"
    hits = [f for f in service.scan_openapi(spec.read_text(errors="replace"), str(spec))
            if f.oracle == a.oracle and f.frames and f.frames[0].symbol == want]
    if hits:
        print(f"REPRODUCED: {a.oracle} on {want} in {spec}")
        return REPRODUCED
    print(f"NOT REPRODUCED: {a.oracle} on {want} no longer present in {spec}")
    return NOT_REPRODUCED


def _crypto(a: argparse.Namespace) -> int:
    from .lanes import crypto
    try:
        hit = crypto.replay(a.rule, a.path, a.line)      # root = cwd, like the other subcommands
    except (FileNotFoundError, ValueError) as e:
        print(e)
        return ERROR
    print(("REPRODUCED" if hit else "NOT REPRODUCED") + f": {a.rule} at {a.path}:{a.line}")
    return REPRODUCED if hit else NOT_REPRODUCED


def _iac(a: argparse.Namespace) -> int:
    from .lanes import iac
    try:
        hit = iac.replay(a.rule, a.path, a.line)
    except (FileNotFoundError, ValueError) as e:
        print(e); return ERROR
    print(("REPRODUCED" if hit else "NOT REPRODUCED") + f": {a.rule} at {a.path}:{a.line}")
    return REPRODUCED if hit else NOT_REPRODUCED


def _binary(a: argparse.Namespace) -> int:
    from .lanes import binary
    try:
        hit = binary.replay(a.rule, a.path, a.offset)
    except (FileNotFoundError, ValueError) as e:
        print(e); return ERROR
    where = f"{a.path}" + (f"+{a.offset}" if a.offset is not None else "")
    print(("REPRODUCED" if hit else "NOT REPRODUCED") + f": {a.rule} in {where}")
    return REPRODUCED if hit else NOT_REPRODUCED


def _githistory(a: argparse.Namespace) -> int:
    from .lanes import githistory
    try:
        hit = githistory.replay(a.rule, a.commit, a.path)
    except (FileNotFoundError, ValueError) as e:
        print(e); return ERROR
    print(("REPRODUCED" if hit else "NOT REPRODUCED") + f": {a.rule} in {a.commit}:{a.path}")
    return REPRODUCED if hit else NOT_REPRODUCED


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m raksha", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("match", help="re-check a dependency against its advisory")
    m.add_argument("ecosystem"); m.add_argument("package"); m.add_argument("version")
    m.add_argument("--advisory", required=True); m.add_argument("--manifest")
    m.set_defaults(fn=_match)
    s = sub.add_parser("secret-match", help="re-run a secret rule on one line of a file")
    s.add_argument("rule"); s.add_argument("path"); s.add_argument("line", type=int)
    s.set_defaults(fn=_secret)
    c = sub.add_parser("spec-check", help="re-run an OpenAPI exposure check")
    c.add_argument("oracle"); c.add_argument("method"); c.add_argument("api_path")
    c.add_argument("--spec", required=True)
    c.set_defaults(fn=_spec)
    cm = sub.add_parser("crypto-match", help="re-check a weak-crypto finding at a file:line")
    cm.add_argument("rule"); cm.add_argument("path"); cm.add_argument("line", type=int)
    cm.set_defaults(fn=_crypto)
    im = sub.add_parser("iac-match", help="re-check an IaC/config misconfiguration at a file:line")
    im.add_argument("rule"); im.add_argument("path"); im.add_argument("line", type=int)
    im.set_defaults(fn=_iac)
    bm = sub.add_parser("binary-match", help="re-check a binary-lane finding in a compiled artifact")
    bm.add_argument("rule"); bm.add_argument("path"); bm.add_argument("offset", type=int, nargs="?")
    bm.set_defaults(fn=_binary)
    gm = sub.add_parser("git-secret-match", help="re-check a secret in a past commit")
    gm.add_argument("rule"); gm.add_argument("commit"); gm.add_argument("path"); gm.add_argument("line", type=int)
    gm.set_defaults(fn=_githistory)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
