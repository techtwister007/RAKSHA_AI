"""G2: grammar-constrained repair output — request shape, strict parse, tolerant fallback, counters.

A loopback stub stands in for the model server. With a schema in the request it answers the way a
constrained decoder must (one JSON object of the schema's shape); without one it answers the way a
free-running model does on our fixed prompt set: prose, fences, a truncated hunk. The test proves
the client asks correctly, parses strictly, falls back tolerantly and counts both; it does not
claim to test a real decoder.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from raksha import guided
from raksha.inference import InferenceClient, InferenceConfig

DIFF = "--- a/s.c\n+++ b/s.c\n@@ -1,2 +1,2 @@\n int f(void) {\n-  return 1; }\n+  return 2; }\n"

#: what an unconstrained model returned on the fixed prompt set
FREE_RUNNING = [
    "Here is the fix:\n```diff\n" + DIFF + "```\nThis bounds the copy.",
    DIFF,
    "Sure! I changed the return value.\n" + DIFF + "\nLet me know if you need anything else.",
    "--- a/s.c\n+++ b/s.c\n@@ -1,2 +1,2 @@\n int f(void) {\n-  return 1; }",   # truncated mid-hunk
    "I cannot see the full file; please send more context.",
]


class _Stub(BaseHTTPRequestHandler):
    seen: list = []

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _Stub.seen.append(body)
        i = len(_Stub.seen) - 1
        if "response_format" in body or "guided_json" in body:
            content = json.dumps({"diff": DIFF, "regression_test": None})
        else:
            content = FREE_RUNNING[i % len(FREE_RUNNING)]
        out = json.dumps({"choices": [{"message": {"content": content}}],
                          "usage": {"completion_tokens": 10}}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)

    def log_message(self, *a):
        pass


@pytest.fixture
def endpoint():
    srv = HTTPServer(("127.0.0.1", 0), _Stub)
    th = threading.Thread(target=srv.serve_forever, daemon=True); th.start()
    _Stub.seen = []
    guided.reset_counters()
    yield f"http://127.0.0.1:{srv.server_address[1]}/v1"
    srv.shutdown()
    srv.server_close()


def _run(base_url, style, prompts=5):
    client = InferenceClient(InferenceConfig(base_url=base_url, guided=style))
    results = []
    for _ in range(prompts):
        text = client.complete([{"role": "user", "content": "fix"}], extra=guided.request_fields(style))[0]
        results.append(guided.parse(text, style))
    return results


@pytest.mark.parametrize("style,key", [("json_schema", "response_format"), ("vllm", "guided_json")])
def test_guided_requests_carry_the_schema_and_never_fail_to_parse(endpoint, style, key):
    results = _run(endpoint, style)
    assert all(key in body for body in _Stub.seen)
    assert all(d == DIFF for d, _ in results)
    c = guided.counters()
    assert c["guided_failed"] == 0 and c["guided_ok"] == 5


def test_unguided_falls_back_to_the_tolerant_parser_and_counts_failures(endpoint):
    results = _run(endpoint, "off")
    assert not any("response_format" in b or "guided_json" in b for b in _Stub.seen)
    c = guided.counters()
    assert c["tolerant_ok"] >= 3                        # fenced, bare and prose-wrapped diffs recovered
    assert c["tolerant_failed"] >= 1                    # the refusal yields nothing
    assert sum(1 for d, _ in results if d) == c["tolerant_ok"]


def test_a_guided_reply_with_a_malformed_diff_is_rejected():
    bad = json.dumps({"diff": "--- a/s.c\n+++ b/s.c\n@@ -1,3 +1,3 @@\n x\n", "regression_test": None})
    guided.reset_counters()
    assert guided.parse(bad, "json_schema") == (None, None)
    assert guided.parse("not json", "json_schema") == (None, None)
    assert guided.counters()["guided_failed"] == 2


def test_wellformed_diff():
    assert guided.wellformed_diff(DIFF)
    assert not guided.wellformed_diff(FREE_RUNNING[3])        # hunk shorter than it declares
    assert not guided.wellformed_diff("just prose")


def test_style_from_env():
    assert guided.style({"RAKSHA_GUIDED_DECODING": "JSON_SCHEMA"}) == "json_schema"
    assert guided.style({"RAKSHA_GUIDED_DECODING": "bogus"}) == "off"
    assert InferenceConfig.from_env({"RAKSHA_GUIDED_DECODING": "vllm"}).guided == "vllm"
