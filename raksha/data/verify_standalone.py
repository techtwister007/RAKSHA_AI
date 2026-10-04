#!/usr/bin/env python3
"""RAKSHA verifier media — replay our findings on your own machine, with nothing installed but Python.

Usage (from anywhere):   python3 verify.py            (or ./verify.sh / verify.bat, which prefer the
                         portable runtime shipped under runtime/ when there is one)
Options:                 --key-file PATH   the deployment verification key (demo-key media need none)
                         --no-replay       check the seals only
                         --json            machine-readable result

What it does, in order — every step is code in this one file, standard library only:
  1. MEDIA   every file on this media is listed, with its sha256, in MEDIA.json, which is signed;
             a changed, missing or extra file fails.
  2. SEALS   each evidence bundle's manifest and signature are recomputed (the same check the
             console's Evidence Vault runs); each advisory's signature likewise.
  3. REPLAY  for each finding whose target ships on this media, the target is copied to a scratch
             directory and the shipped reproducer is run against it: it must FIRE (the oracle's own
             marker in the output, e.g. "AddressSanitizer", with a non-zero exit). Then the proven
             patch is applied (by a strict unified-diff applier in this file) and the same input is
             run again: it must be DEAD. A finding that needs a toolchain this machine lacks (e.g. a
             C compiler with AddressSanitizer) is reported as not replayed, never as passed.

Exit status 0 = every check that ran passed; 1 = something failed; 2 = the media is unreadable.
"""

import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEMO_KEY = b"raksha-demo-verification-key-v1"
REPLAY_TIMEOUT = 60


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sign_hashes(hashes, key):
    material = "\n".join("%s=%s" % (k, hashes[k]) for k in sorted(hashes)).encode()
    return hmac.new(key, material, hashlib.sha256).hexdigest()


# ---- 1. the media itself --------------------------------------------------------------------------
def check_media(key):
    try:
        with open(os.path.join(HERE, "MEDIA.json"), "rb") as fh:
            raw = fh.read()
        media = json.loads(raw)
        with open(os.path.join(HERE, "MEDIA.sig.json")) as fh:
            sig = json.load(fh)
    except (OSError, ValueError) as e:
        return None, ["MEDIA.json or its signature unreadable (%s)" % e]
    problems = []
    listed = media.get("files", {})
    for rel, want in sorted(listed.items()):
        p = os.path.join(HERE, *rel.split("/"))
        if not os.path.isfile(p):
            problems.append("MISSING " + rel)
        elif sha256_file(p) != want:
            problems.append("CHANGED " + rel)
    skip = {"MEDIA.json", "MEDIA.sig.json"}
    for root, dirs, files in os.walk(HERE):
        dirs[:] = [d for d in dirs if d != "__pycache__" and not (root == HERE and d == "runtime")]
        for f in files:
            rel = os.path.relpath(os.path.join(root, f), HERE).replace(os.sep, "/")
            if rel not in listed and rel not in skip and not rel.endswith(".pyc"):
                problems.append("UNEXPECTED " + rel)
    if hashlib.sha256(raw).hexdigest() != sig.get("media_sha256"):
        problems.append("CHANGED MEDIA.json")
    want = hmac.new(key, raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, str(sig.get("signature", ""))):
        problems.append("MEDIA SIGNATURE INVALID")
    return media, problems


# ---- 2. bundles and advisories --------------------------------------------------------------------
def check_bundle(d, key):
    problems = []
    try:
        with open(os.path.join(d, "bundle.json"), "rb") as fh:
            mbytes = fh.read()
        manifest = json.loads(mbytes)
        with open(os.path.join(d, "signature.json")) as fh:
            sig = json.load(fh)
    except (OSError, ValueError) as e:
        return ["bundle unreadable (%s)" % e]
    recomputed = {}
    for name, want in manifest.get("artifacts", {}).items():
        p = os.path.join(d, name)
        if os.path.basename(name) != name or not os.path.isfile(p):
            problems.append("MISSING " + name)
            continue
        recomputed[name] = sha256_file(p)
        if recomputed[name] != want:
            problems.append("CHANGED " + name)
    mh = hashlib.sha256(mbytes).hexdigest()
    if mh != sig.get("manifest_sha256"):
        problems.append("CHANGED bundle.json")
    recomputed["bundle.json"] = mh
    if not hmac.compare_digest(sign_hashes(recomputed, key), str(sig.get("signature", ""))):
        problems.append("SIGNATURE INVALID")
    return problems


def check_advisory(d, key):
    try:
        body = open(os.path.join(d, "advisory.json"), "rb").read()
        text = open(os.path.join(d, "advisory.md"), "rb").read()
        sig = json.load(open(os.path.join(d, "advisory.sig.json")))
    except (OSError, ValueError) as e:
        return ["advisory unreadable (%s)" % e]
    problems = []
    if hashlib.sha256(body).hexdigest() != sig.get("advisory_sha256"):
        problems.append("CHANGED advisory.json")
    if hashlib.sha256(text).hexdigest() != sig.get("text_sha256"):
        problems.append("CHANGED advisory.md")
    material = ("advisory.json=%s\nadvisory.md=%s" % (hashlib.sha256(body).hexdigest(),
                                                       hashlib.sha256(text).hexdigest())).encode()
    if not hmac.compare_digest(hmac.new(key, material, hashlib.sha256).hexdigest(), str(sig.get("signature", ""))):
        problems.append("SIGNATURE INVALID")
    return problems


def check_signed_doc(d, stem, key, expect_prev=None):
    """A Wave 5 signed document (report / certificate): body + text hashes, chain prev, HMAC."""
    try:
        body = open(os.path.join(d, stem + ".json"), "rb").read()
        text = open(os.path.join(d, stem + ".md"), "rb").read()
        sig_raw = open(os.path.join(d, stem + ".sig.json"), "rb").read()
        sig = json.loads(sig_raw)
    except (OSError, ValueError) as e:
        return ["document unreadable (%s)" % e], None
    problems = []
    hb, ht = hashlib.sha256(body).hexdigest(), hashlib.sha256(text).hexdigest()
    if hb != sig.get(stem + "_json_sha256"):
        problems.append("CHANGED %s.json" % stem)
    if ht != sig.get(stem + "_md_sha256"):
        problems.append("CHANGED %s.md" % stem)
    prev = str(sig.get("prev", "0" * 64))
    if expect_prev is not None and prev != expect_prev:
        problems.append("CHAIN BROKEN")
    material = ("%s.json=%s\n%s.md=%s\nprev=%s" % (stem, hb, stem, ht, prev)).encode()
    if not hmac.compare_digest(hmac.new(key, material, hashlib.sha256).hexdigest(), str(sig.get("signature", ""))):
        problems.append("SIGNATURE INVALID")
    return problems, hashlib.sha256(sig_raw).hexdigest()


# ---- 3. replay ---------------------------------------------------------------------------------
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def apply_unified(diff_text, tree):
    """Apply a unified diff to files under `tree`, strictly: every context and removed line must
    match exactly, or nothing is written. Returns None on success, else the reason."""
    files, cur = [], None
    for line in diff_text.splitlines(keepends=True):
        if line.startswith("--- "):
            cur = {"old": line[4:].split("\t")[0].strip(), "hunks": []}
            files.append(cur)
        elif line.startswith("+++ ") and cur is not None:
            cur["new"] = line[4:].split("\t")[0].strip()
        elif line.startswith("@@") and cur is not None:
            m = _HUNK.match(line)
            if not m:
                return "malformed hunk header"
            cur["hunks"].append({"start": int(m.group(1)), "lines": []})
        elif cur is not None and cur["hunks"] and line[:1] in (" ", "-", "+"):
            cur["hunks"][-1]["lines"].append(line)
        elif line.startswith("\\"):
            continue
    staged = {}
    for f in files:
        rel = f.get("new") or f["old"]
        rel = rel[2:] if rel.startswith(("a/", "b/")) else rel
        if rel.startswith("/") or ".." in rel.split("/"):
            return "refusing a path outside the tree: " + rel
        path = os.path.join(tree, *rel.split("/"))
        try:
            src = open(path, encoding="utf-8").read().splitlines(keepends=True)
        except OSError:
            return "patched file missing: " + rel
        out, pos = [], 0
        for h in f["hunks"]:
            start = h["start"] - 1 if h["start"] > 0 else 0
            out.extend(src[pos:start])
            pos = start
            for ln in h["lines"]:
                tag, body = ln[0], ln[1:]
                if tag in (" ", "-"):
                    if pos >= len(src) or src[pos].rstrip("\r\n") != body.rstrip("\r\n"):
                        return "context mismatch in %s at line %d" % (rel, pos + 1)
                    if tag == " ":
                        out.append(src[pos])
                    pos += 1
                else:
                    out.append(body if body.endswith("\n") else body + "\n")
        out.extend(src[pos:])
        staged[path] = "".join(out)
    for path, text in staged.items():
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    return None


def _argv(cmd):
    argv = list(cmd)
    if argv and argv[0] == "raksha":
        argv = [sys.executable, "-m", "raksha"] + argv[1:]
    elif argv and argv[0] in ("python3", "python"):
        argv = [sys.executable] + argv[1:]
    return argv


def _run(argv, cwd):
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": os.path.join(HERE, "lib"),
           "PYTHONDONTWRITEBYTECODE": "1", "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}
    try:
        r = subprocess.run(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=REPLAY_TIMEOUT)
        return r.returncode, r.stdout.decode("utf-8", "replace")
    except FileNotFoundError as e:
        return None, "toolchain missing: %s" % e
    except subprocess.TimeoutExpired:
        return None, "timed out"


def replay(entry, bundle):
    proof = json.load(open(os.path.join(bundle, "proof.json")))
    cmd = (proof.get("reproducer") or {}).get("replay_cmd") or []
    if not cmd:
        return {"result": "not-replayed", "why": "no replay command in the record"}
    needs = entry.get("needs")
    if needs and shutil.which(needs) is None:
        return {"result": "not-replayed", "why": "needs %s, absent on this machine" % needs}
    target = os.path.join(HERE, *entry["target"].split("/"))
    out = {"cmd": " ".join(cmd)}
    with tempfile.TemporaryDirectory(prefix="raksha-verify-") as tmp:
        work = os.path.join(tmp, "t")
        shutil.copytree(target, work)
        if os.path.isfile(os.path.join(bundle, "repro")):
            shutil.copy(os.path.join(bundle, "repro"), os.path.join(work, "repro"))
        marker = entry.get("marker") or "REPRODUCED:"
        rc, text = _run(_argv(cmd), work)
        if rc is None:
            return {"result": "not-replayed", "why": text, **out}
        out["vulnerable_exit"] = rc
        out["marker"] = marker
        out["fired"] = marker in text and rc != 0
        patch = os.path.join(bundle, "patch.diff")
        if os.path.isfile(patch) and entry.get("patch_replay", True):
            why = apply_unified(open(patch, encoding="utf-8").read(), work)
            if why:
                out["patched"] = "patch did not apply: " + why
            else:
                rc2, text2 = _run(_argv(cmd), work)
                out["patched_exit"] = rc2
                out["dead_after_patch"] = rc2 is not None and marker not in text2
    ok = out["fired"] and out.get("dead_after_patch", True) is True and "patched" not in out
    out["result"] = "pass" if ok else "FAIL"
    return out


def main(argv):
    as_json = "--json" in argv
    key = DEMO_KEY
    if "--key-file" in argv:
        key = open(argv[argv.index("--key-file") + 1], "rb").read().strip()
    t0 = time.monotonic()
    report = {"media": None, "bundles": {}, "advisories": {}, "replays": {}}
    media, problems = check_media(key)
    report["media"] = problems or "ok"
    if media is None:
        print(json.dumps(report, indent=2) if as_json else "media unreadable: " + "; ".join(problems))
        return 2
    failed = bool(problems)
    for fid, entry in sorted(media.get("findings", {}).items()):
        b = os.path.join(HERE, *entry["bundle"].split("/"))
        p = check_bundle(b, key)
        report["bundles"][fid] = p or "ok"
        failed |= bool(p)
        if not p and entry.get("target") and "--no-replay" not in argv:
            r = replay(entry, b)
            report["replays"][fid] = r
            failed |= r["result"] == "FAIL"
    for adv in media.get("advisories", []):
        p = check_advisory(os.path.join(HERE, *adv.split("/")), key)
        report["advisories"][adv] = p or "ok"
        failed |= bool(p)
    report["documents"] = {}
    chains = {}
    for doc in media.get("documents", []):
        prev = chains.get(doc.get("chain")) if doc.get("chain") else None
        expect = prev if (doc.get("chain") and doc["chain"] in chains) else (
            doc.get("first_prev") if doc.get("chain") else None)
        p, h = check_signed_doc(os.path.join(HERE, *doc["path"].split("/")), doc["stem"], key, expect)
        if doc.get("chain"):
            chains[doc["chain"]] = h
        report["documents"][doc["path"]] = p or "ok"
        failed |= bool(p)
    report["seconds"] = round(time.monotonic() - t0, 2)
    report["ok"] = not failed
    if as_json:
        print(json.dumps(report, indent=2))
    else:
        print("RAKSHA verifier media — %s" % ("ALL CHECKS PASSED" if not failed else "FAILURES FOUND"))
        print("  media integrity: %s" % ("ok" if report["media"] == "ok" else "; ".join(report["media"])))
        for fid, v in report["bundles"].items():
            print("  bundle %s: %s" % (fid[:8], v if v == "ok" else "; ".join(v)))
            r = report["replays"].get(fid)
            if r:
                if r["result"] == "not-replayed":
                    print("    replay: not replayed (%s)" % r["why"])
                else:
                    print("    replay: vulnerable %s (exit %s); patched %s -> %s" % (
                        "FIRED" if r.get("fired") else "did not fire", r.get("vulnerable_exit"),
                        "dead" if r.get("dead_after_patch") else r.get("patched", "still fires")
                        if "dead_after_patch" in r or "patched" in r else "n/a", r["result"]))
        for a, v in report["advisories"].items():
            print("  advisory %s: %s" % (a.split("/")[-1], v if v == "ok" else "; ".join(v)))
        for d, v in report["documents"].items():
            print("  document %s: %s" % (d, v if v == "ok" else "; ".join(v)))
        print("  %.1fs" % report["seconds"])
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
