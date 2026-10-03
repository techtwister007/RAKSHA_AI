"""Dependency-bump patch lane — the cheapest provable patch there is.

For a confirmed vulnerable dependency with a known fixed version, this emits a real unified diff
that bumps the manifest to the fixed version. Zero inference. Supports the manifests the supply lane
parses. The gate then proves the bump: the project rebuilds, its own tests pass, and the dependency
no longer matches the advisory.

The confirming oracle for these findings is a deterministic match, so a bump patch's proof is itself
deterministic — re-scan the bumped manifest and the advisory no longer applies. That makes these
patches fast and certain, which is why they lead when patches and findings score equally.
"""

from __future__ import annotations

import difflib
import re


def _diff(before: str, after: str, path: str) -> str:
    if before == after:
        return ""
    return "".join(difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile=f"a/{path}", tofile=f"b/{path}"))


def bump_maven(text: str, package: str, fixed: str) -> str:
    """Bump a Maven dependency to `fixed`, following a `${prop}` indirection if present."""
    gid, _, aid = package.partition(":")
    block = re.search(
        rf"<dependency>\s*<groupId>{re.escape(gid)}</groupId>\s*"
        rf"<artifactId>{re.escape(aid)}</artifactId>\s*<version>([^<]+)</version>", text, re.S)
    if not block:
        return ""
    ver = block.group(1).strip()
    if ver.startswith("${") and ver.endswith("}"):
        prop = ver[2:-1]
        after = re.sub(rf"(<{re.escape(prop)}>)[^<]+(</{re.escape(prop)}>)",
                       rf"\g<1>{fixed}\g<2>", text, count=1)
    else:
        after = text[:block.start(1)] + fixed + text[block.end(1):]
    return _diff(text, after, "pom.xml")


def bump_requirements(text: str, package: str, fixed: str, path: str = "requirements.txt") -> str:
    pat = re.compile(rf"(?im)^({re.escape(package)}\s*==\s*)([A-Za-z0-9_.\-+]+)")
    after = pat.sub(rf"\g<1>{fixed}", text, count=1)
    return _diff(text, after, path)


def bump_package_json(text: str, package: str, fixed: str, path: str = "package.json") -> str:
    pat = re.compile(rf'("{re.escape(package)}"\s*:\s*")[~^]?[0-9][^"\n]*(")')
    after = pat.sub(rf"\g<1>{fixed}\g<2>", text, count=1)
    return _diff(text, after, path)


def bump_go_mod(text: str, package: str, fixed: str, path: str = "go.mod") -> str:
    pat = re.compile(rf"(?m)^(\s*{re.escape(package)}\s+v)[0-9][\w.\-+]*")
    after = pat.sub(rf"\g<1>{fixed}", text, count=1)
    return _diff(text, after, path)


_BUMPERS = {
    "Maven": bump_maven,
    "PyPI": bump_requirements,
    "npm": bump_package_json,
    "Go": bump_go_mod,
}


def bump(ecosystem: str, manifest_text: str, package: str, fixed: str) -> str:
    """Return a unified diff bumping `package` to `fixed`, or "" if it cannot be produced."""
    fn = _BUMPERS.get(ecosystem)
    return fn(manifest_text, package, fixed) if fn else ""
