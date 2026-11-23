import unittest

from interceptor.identity import (bearer_token, claim_list, claim_value, jwt_claims,
                                  resolve_principal)
from interceptor.trace import (parse_traceparent, resolve_thread, resolve_trace, span_id,
                               traceparent_header)

from .support import TRACE, bearer, make_jwt, settings, traceparent


class Jwt(unittest.TestCase):
    def test_claims_of_a_valid_token(self):
        self.assertEqual(jwt_claims(make_jwt({"sub": "u1"})), {"sub": "u1"})

    def test_anything_else_is_empty(self):
        for token in ("", "abc", "a.b", "a.b.c.d", "a.!!!.c", make_jwt({}) + "x" * 20000):
            self.assertEqual(jwt_claims(token), {}, token[:20])
        import base64
        not_object = base64.urlsafe_b64encode(b'["list"]').decode().rstrip("=")
        self.assertEqual(jwt_claims(f"a.{not_object}.c"), {})

    def test_bearer_token_is_case_insensitive_on_the_scheme(self):
        self.assertEqual(bearer_token({"authorization": "bearer abc"}), "abc")
        self.assertEqual(bearer_token({"authorization": "Basic abc"}), "")
        self.assertEqual(bearer_token({}), "")

    def test_claim_lookup_literal_key_then_dotted_path(self):
        claims = {"cognito:username": "alice", "act": {"sub": "agent-7"}, "n": 42,
                  "flag": True, "a.b": "literal"}
        self.assertEqual(claim_value(claims, "cognito:username"), "alice")
        self.assertEqual(claim_value(claims, "act.sub"), "agent-7")
        self.assertEqual(claim_value(claims, "n"), "42")
        self.assertEqual(claim_value(claims, "a.b"), "literal")
        self.assertIsNone(claim_value(claims, "flag"))
        self.assertIsNone(claim_value(claims, "missing.deep"))

    def test_claim_list(self):
        claims = {"cognito:groups": ["a", "b", 3, True, ""], "single": "g", "realm": {"roles": ["r"]}}
        self.assertEqual(claim_list(claims, "cognito:groups"), ["a", "b", "3"])
        self.assertEqual(claim_list(claims, "single"), ["g"])
        self.assertEqual(claim_list(claims, "realm.roles"), ["r"])
        self.assertEqual(claim_list(claims, ""), [])


class Principal(unittest.TestCase):
    def test_default_claim_and_groups(self):
        cfg = settings(REVA_GROUPS_CLAIM="cognito:groups")
        headers = {"authorization": bearer({"sub": "u1", "cognito:groups": ["admins"]})}
        self.assertEqual(resolve_principal(headers, cfg), ("u1", ["admins"], ""))

    def test_custom_claim(self):
        cfg = settings(REVA_USER_CLAIM="email")
        headers = {"authorization": bearer({"sub": "u1", "email": "a@b.c"})}
        self.assertEqual(resolve_principal(headers, cfg)[0], "a@b.c")

    def test_failures_are_coded_and_there_is_no_fallback_claim(self):
        cfg = settings()
        self.assertEqual(resolve_principal({}, cfg)[2], "missing_authorization")
        self.assertEqual(resolve_principal({"authorization": "Bearer junk"}, cfg)[2],
                         "invalid_authorization")
        self.assertEqual(resolve_principal({"authorization": bearer({"email": "x"})}, cfg)[2],
                         "principal_unresolved")


class Trace(unittest.TestCase):
    def test_traceparent(self):
        self.assertEqual(parse_traceparent(traceparent()), TRACE)
        for bad in ("", "garbage", "00-" + "0" * 32 + "-" + "b" * 16 + "-01",
                    "00-" + "a" * 32 + "-" + "0" * 16 + "-01", "ff-" + "a" * 32 + "-" + "b" * 16 + "-01",
                    "00-" + "a" * 31 + "-" + "b" * 16 + "-01"):
            self.assertIsNone(parse_traceparent(bad), bad)

    def test_resolution_order(self):
        cfg = settings(REVA_TRACE_HEADER="X-Trace-Id")
        self.assertEqual(resolve_trace({"traceparent": traceparent()}, cfg, "s"),
                         (TRACE, "traceparent"))
        self.assertEqual(resolve_trace({"x-trace-id": "B" * 32}, cfg, "s"),
                         ("b" * 32, "header"))
        trace, source = resolve_trace({}, cfg, "seed")
        self.assertEqual(source, "minted")
        self.assertEqual(resolve_trace({}, cfg, "seed")[0], trace)       # deterministic
        self.assertNotEqual(resolve_trace({}, cfg, "other")[0], trace)

    def test_trace_header_forms(self):
        cfg = settings(REVA_TRACE_HEADER="x-amzn-trace-id")
        xray = "Root=1-5759e988-bd862e3fe1be46a994272793;Parent=53995c3f42cd8ad8"
        self.assertEqual(resolve_trace({"x-amzn-trace-id": xray}, cfg, "s")[0],
                         "5759e988bd862e3fe1be46a994272793")
        hashed, source = resolve_trace({"x-amzn-trace-id": "any stable id"}, cfg, "s")
        self.assertEqual((len(hashed), source), (32, "header"))

    def test_missing_traceparent_can_deny(self):
        cfg = settings(REVA_ON_MISSING_TRACEPARENT="deny")
        self.assertEqual(resolve_trace({}, cfg, "s"), (None, "missing"))

    def test_span_is_deterministic_per_call(self):
        self.assertEqual(span_id(TRACE, "k"), span_id(TRACE, "k"))
        self.assertNotEqual(span_id(TRACE, "k"), span_id(TRACE, "k2"))
        self.assertEqual(len(span_id(TRACE, "k")), 16)
        self.assertEqual(traceparent_header(TRACE, "b" * 16), traceparent())

    def test_thread_precedence_and_fallback(self):
        headers = {"x-reva-session-id": "from-session", "mcp-session-id": "from-mcp"}
        self.assertEqual(resolve_thread(headers, "ctx", TRACE), ("from-session", "header"))
        legacy = {"x-reva-thread-id": "from-thread", "mcp-session-id": "from-mcp"}
        self.assertEqual(resolve_thread(legacy, "ctx", TRACE), ("from-thread", "header"))
        self.assertEqual(resolve_thread({"mcp-session-id": "m"}, "ctx", TRACE),
                         ("ctx", "contextId"))
        self.assertEqual(resolve_thread({"mcp-session-id": "m"}, "", TRACE),
                         ("m", "mcp-session-id"))
        self.assertEqual(resolve_thread({}, "", TRACE), (TRACE, "trace"))


if __name__ == "__main__":
    unittest.main()
