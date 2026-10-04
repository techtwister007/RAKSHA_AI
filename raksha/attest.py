"""D11 — provenance as a standard in-toto / SLSA attestation.

An evidence bundle already carries a signed manifest of content-addressed artifacts. This module
expresses *who built those artifacts, in what environment, from what materials* in the format the
supply-chain world already reads: an in-toto Statement (v1) whose predicate is a SLSA Provenance
(v1). A verifier that knows nothing about RAKSHA can still parse the subject digests, the builder
id, and the materials — because the envelope is the standard one cosign/in-toto consume.

Mapping from a bundle manifest:

  * ``subject``  ← ``manifest["artifacts"]`` ({name: sha256}); each becomes a ResourceDescriptor
    ``{"name", "digest": {"sha256": ...}}``. The manifest itself is added as a subject too.
  * ``predicate.buildDefinition.externalParameters`` ← the finding this bundle proves (id, class,
    target, status, ROE level) — the *inputs* that determined the build.
  * ``predicate.buildDefinition.resolvedDependencies`` ← the environment toolchains (gcc, go, …),
    the materials the proof was produced against.
  * ``predicate.runDetails.builder`` ← RAKSHA, with the interpreter/platform from ``environment``.

Real vs fallback: this is a pure structural transform — no signing, no network, no optional
library. The statement is *signed* exactly like the bundle (HMAC today, ``pqsign`` / cosign when
provisioned); signing lives in ``bundle.py``, this module only produces the payload. Deterministic:
no timestamp is emitted unless ``built_at`` is passed.
"""

from __future__ import annotations

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
BUILD_TYPE = "https://github.com/techtwister007/RAKSHA_AI/evidence-bundle/v1"
BUILDER_ID = "https://github.com/techtwister007/RAKSHA_AI"


def _subjects(manifest: dict) -> list[dict]:
    """ResourceDescriptors for every artifact in the manifest, sorted by name (deterministic)."""
    artifacts = manifest.get("artifacts", {})
    subjects = []
    if isinstance(artifacts, dict):
        for name in sorted(artifacts):
            digest = artifacts[name]
            if isinstance(digest, str) and digest:
                subjects.append({"name": name, "digest": {"sha256": digest}})
    msum = manifest.get("manifest_sha256")
    if isinstance(msum, str) and msum:
        subjects.append({"name": "bundle.json", "digest": {"sha256": msum}})
    return subjects


def _dependencies(environment: dict) -> list[dict]:
    """The environment toolchains as SLSA resolvedDependencies (materials the proof ran against)."""
    deps: list[dict] = []
    toolchains = environment.get("toolchains", {}) if isinstance(environment, dict) else {}
    if isinstance(toolchains, dict):
        for name in sorted(toolchains):
            deps.append({
                "uri": f"toolchain:{name}",
                "annotations": {"version": str(toolchains[name])},
            })
    return deps


def attestation_for(manifest: dict, environment: dict) -> dict:
    """Produce an in-toto Statement v1 (SLSA Provenance v1 predicate) over a bundle manifest.

    ``manifest`` is the dict ``bundle.build_bundle`` writes to ``bundle.json`` (it carries
    ``artifacts``, ``finding_id``, ``target``, ``roe_level``, …); ``environment`` is
    ``bundle.environment()``. Returns a well-formed Statement; ``validate_statement`` checks shape.
    """
    manifest = manifest or {}
    environment = environment or {}
    external = {
        k: manifest.get(k)
        for k in ("finding_id", "bug_class", "status", "target", "roe_level", "tool", "version")
        if manifest.get(k) is not None
    }
    build_metadata: dict = {"invocationId": manifest.get("finding_id")}

    builder: dict = {
        "id": BUILDER_ID,
        "builderDependencies": [
            {"uri": "python", "annotations": {"version": environment.get("python")}},
        ],
        "version": {"raksha": str(manifest.get("version", "0.0.0"))},
    }

    predicate = {
        "buildDefinition": {
            "buildType": BUILD_TYPE,
            "externalParameters": external,
            "internalParameters": {
                "platform": environment.get("platform"),
                "machine": environment.get("machine"),
            },
            "resolvedDependencies": _dependencies(environment),
        },
        "runDetails": {
            "builder": builder,
            "metadata": build_metadata,
        },
    }

    return {
        "_type": STATEMENT_TYPE,
        "subject": _subjects(manifest),
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


def validate_statement(statement: dict) -> tuple[bool, list[str]]:
    """Structurally validate an in-toto Statement. Returns (ok, problems). No schema library needed;
    checks the required envelope: ``_type``, a non-empty ``subject`` of {name, digest.sha256},
    ``predicateType``, and an object ``predicate``."""
    problems: list[str] = []
    if not isinstance(statement, dict):
        return False, ["not a JSON object"]
    if statement.get("_type") != STATEMENT_TYPE:
        problems.append(f"_type is not {STATEMENT_TYPE!r}")
    if not isinstance(statement.get("predicateType"), str) or not statement.get("predicateType"):
        problems.append("missing predicateType")
    if not isinstance(statement.get("predicate"), dict):
        problems.append("predicate is not an object")
    subject = statement.get("subject")
    if not isinstance(subject, list) or not subject:
        problems.append("subject is missing or empty")
    else:
        for i, s in enumerate(subject):
            if not isinstance(s, dict) or not s.get("name"):
                problems.append(f"subject[{i}] missing name")
                continue
            digest = s.get("digest")
            if not isinstance(digest, dict) or not isinstance(digest.get("sha256"), str) \
                    or len(digest.get("sha256", "")) != 64:
                problems.append(f"subject[{i}] missing a sha256 digest")
    return (not problems), problems
