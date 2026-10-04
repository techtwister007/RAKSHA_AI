"""A10 — machine-checked bound proofs for the bound-clamp repair templates.

A bound-clamp template (``c_bound_copy``, ``go_bound_slice``, ``rust_bound_index``) rewrites an
unbounded copy/index into a clamped one, e.g. ``n -> min(n, cap)`` where ``cap`` is the destination
buffer's size. The five-check gate already decides *empirically* whether that candidate is safe
(it compiles, the PoV dies, the corpus agrees, coverage holds, a fresh campaign finds nothing).
This module adds an *analytic* layer on top: it emits the proof obligation the clamp is supposed to
satisfy and discharges it with an SMT solver when one is importable.

What is proved vs. assumed
--------------------------
For a clamp writing a length ``clamped_len_expr`` into a buffer of size ``dst_size_expr``, over
inputs whose types bound each variable to ``var_ranges``, the obligation is::

    for all integer assignments within var_ranges:  0 <= clamped_len <= dst_size

If the solver shows this holds for every modelled assignment, the clamp **provably** never writes
past the buffer and never writes a negative length -- for the modelled ranges. We PROVE the
arithmetic. We ASSUME two things the templates must get right and that this module takes on trust:

  * ``dst_size_expr`` really is the destination buffer's size (the C template uses ``sizeof(dst)``,
    which is only the buffer size when ``dst`` is a fixed-size array -- that premise is the gate's
    differential/coverage job, not ours), and
  * ``var_ranges`` really is the inputs' type range (a ``size_t`` is ``0..2**64-1``; a signed
    ``int`` is ``-2**31..2**31-1``, and a clamp that forgets a negative length is then *correctly*
    refuted here).

So a "proved" result is "the clamp arithmetic is sound under these premises", never "the fix is
correct" in the gate's full sense. The two layers are independent and complementary.

Offline / optional solver
--------------------------
The solver (``z3-solver``) ships as an optional wheel in the sealed bundle. When ``import z3`` fails
this module degrades honestly: :func:`prove_bound` returns ``status="unavailable"`` and NEVER
claims a proof. Nothing here imports z3 at module load; the import is attempted per call so the
absence is always a value, never an exception.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any


class ExprError(ValueError):
    """The claim carried an expression outside the small arithmetic language we accept."""


@dataclass(frozen=True)
class BoundClaim:
    """A structured description of a bound-clamp, handed over by the template that produced it.

    The template knows exactly what it wrote, so it populates this directly rather than making us
    re-parse C/Go/Rust. During integration a template returns one of these alongside its diff; for
    now tests construct it directly.

    Fields
    ------
    dst_size_expr:
        The destination buffer's size, as an expression over the variables, e.g. ``"cap"`` or
        ``"64"`` or ``"sizeof_buf"``. (No ``sizeof`` syntax -- hand us the symbol/number it resolves
        to; the obligation is pure integer arithmetic.)
    clamped_len_expr:
        The clamped length actually written, as an expression, e.g. ``"min(n, cap)"``. A deliberately
        wrong clamp that forgot the cap is just ``"n"`` and will be refuted.
    var_ranges:
        Inclusive integer range ``{name: (lo, hi)}`` for every free variable, modelling the input
        type's range. A fixed constant (a known buffer size) is given as ``(k, k)``.

    The accepted expression language is: integer literals, the variables named in ``var_ranges``,
    ``+ - *``, integer ``// `` and ``%``, unary ``+ -``, parentheses, and the n-ary ``min(...)`` /
    ``max(...)``. Anything else raises :class:`ExprError` when the claim is checked.
    """

    dst_size_expr: str
    clamped_len_expr: str
    var_ranges: dict[str, tuple[int, int]]


@dataclass(frozen=True)
class ProofResult:
    """The verdict on a :class:`BoundClaim`.

    status:
        ``"proved"``      -- the obligation holds for every modelled assignment (solver: unsat core).
        ``"refuted"``     -- an in-range assignment violates it; see ``counterexample``.
        ``"unknown"``     -- the solver could not decide (timeout / incomplete), or the claim did
                             not parse. Never asserts safety.
        ``"unavailable"`` -- no SMT solver importable; the bound was NOT proved. Never a proof.
    detail:
        A human-readable one-liner describing the verdict.
    counterexample:
        For ``"refuted"`` only: the variable assignment that breaks the bound, plus the resulting
        ``_clamped_len`` and ``_dst_size``. ``None`` otherwise.
    """

    status: str
    detail: str
    counterexample: dict[str, int] | None = None

    @property
    def proved(self) -> bool:
        """True only for a machine-checked proof. A convenience the gate can trust."""
        return self.status == "proved"


# ---------------------------------------------------------------- solver loading

def _load_z3() -> Any | None:
    """Return the ``z3`` module, or ``None`` when it is not importable.

    Attempted per call (not at import) so the solver's absence is a value a caller can branch on,
    never an exception that propagates. Tests monkeypatch this to force the no-solver path.
    """
    try:
        import z3  # type: ignore
    except Exception:
        return None
    return z3


def z3_available() -> bool:
    """Whether an SMT solver is importable on this node, right now."""
    return _load_z3() is not None


# ---------------------------------------------------------------- expression -> z3

_UNARY = (ast.UAdd, ast.USub)


def _to_z3(expr: str, env: dict, z3: Any):
    """Translate one claim expression into a z3 integer term over ``env`` (name -> z3.Int)."""
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        raise ExprError(f"could not parse {expr!r}: {e}") from e
    return _walk(tree.body, env, z3)


def _walk(node: ast.AST, env: dict, z3: Any):
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool) or not isinstance(node.value, int):
            raise ExprError(f"non-integer literal {node.value!r}")
        return z3.IntVal(node.value)
    if isinstance(node, ast.Name):
        if node.id not in env:
            raise ExprError(f"unknown variable {node.id!r}")
        return env[node.id]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, _UNARY):
        operand = _walk(node.operand, env, z3)
        return operand if isinstance(node.op, ast.UAdd) else -operand
    if isinstance(node, ast.BinOp):
        left = _walk(node.left, env, z3)
        right = _walk(node.right, env, z3)
        op = node.op
        if isinstance(op, ast.Add):
            return left + right
        if isinstance(op, ast.Sub):
            return left - right
        if isinstance(op, ast.Mult):
            return left * right
        if isinstance(op, ast.FloorDiv):
            return left / right          # z3 Int division is integer (floor-toward-zero) division
        if isinstance(op, ast.Mod):
            return left % right
        raise ExprError(f"unsupported operator {type(op).__name__}")
    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name) or node.func.id not in ("min", "max"):
            raise ExprError("only min(...) and max(...) calls are allowed")
        if node.keywords or not node.args:
            raise ExprError(f"{node.func.id}() needs one or more positional args")
        args = [_walk(a, env, z3) for a in node.args]
        acc = args[0]
        for a in args[1:]:
            acc = z3.If(acc <= a, acc, a) if node.func.id == "min" else z3.If(acc >= a, acc, a)
        return acc
    raise ExprError(f"unsupported expression node {type(node).__name__}")


# ---------------------------------------------------------------- the obligation

def bound_obligation(claim: BoundClaim) -> str:
    """The proof obligation this claim must satisfy, as human-readable text (no solver needed).

    This is what we hand to the solver and what goes in the evidence bundle so a reader can see the
    exact statement that was discharged (or not).
    """
    ranges = ", ".join(f"{lo} <= {n} <= {hi}" for n, (lo, hi) in sorted(claim.var_ranges.items()))
    return (f"forall [{ranges}]: "
            f"0 <= ({claim.clamped_len_expr}) <= ({claim.dst_size_expr})")


def prove_bound(claim: BoundClaim, *, timeout_ms: int = 5000) -> ProofResult:
    """Discharge the bound obligation for ``claim`` with an SMT solver, honestly.

    Obligation (see module docstring): for every integer assignment within ``claim.var_ranges``,
    ``0 <= clamped_len_expr <= dst_size_expr``. We assert its *negation* under the range constraints
    and ask the solver for a model:

      * ``unsat``  -> no violating input exists -> **proved**.
      * ``sat``    -> the model is a violating input -> **refuted** with that counterexample.
      * otherwise  -> **unknown** (timeout / incomplete).

    With no solver importable, returns **unavailable** -- never a proof. A claim whose expressions
    fall outside the accepted language returns **unknown** with the parse error (we do not guess).
    """
    z3 = _load_z3()
    if z3 is None:
        return ProofResult(
            "unavailable",
            "no SMT solver importable (z3-solver not installed in this bundle); bound NOT proved",
            None,
        )
    try:
        env = {name: z3.Int(name) for name in claim.var_ranges}
        dst = _to_z3(claim.dst_size_expr, env, z3)
        clamped = _to_z3(claim.clamped_len_expr, env, z3)
    except ExprError as e:
        return ProofResult("unknown", f"claim did not parse: {e}", None)

    solver = z3.Solver()
    solver.set("timeout", int(timeout_ms))
    for name, (lo, hi) in claim.var_ranges.items():
        solver.add(env[name] >= lo, env[name] <= hi)
    # negate the obligation: a length that escapes [0, dst_size] is a buffer under/overflow witness.
    solver.add(z3.Or(clamped < 0, clamped > dst))

    verdict = solver.check()
    if verdict == z3.unsat:
        return ProofResult("proved", f"solver: {bound_obligation(claim)}", None)
    if verdict == z3.sat:
        model = solver.model()

        def val(term: Any) -> int:
            return model.eval(term, model_completion=True).as_long()

        cex: dict[str, int] = {name: val(env[name]) for name in claim.var_ranges}
        cex["_clamped_len"] = val(clamped)
        cex["_dst_size"] = val(dst)
        where = "below 0" if cex["_clamped_len"] < 0 else "past the buffer"
        return ProofResult(
            "refuted",
            f"clamped length {cex['_clamped_len']} is {where} (dst_size={cex['_dst_size']})",
            cex,
        )
    return ProofResult("unknown", f"solver returned {verdict} (timeout or incomplete)", None)
