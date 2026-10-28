import unittest

from interceptor.identity import (bearer_token, claim_list, claim_value, jwt_claims,
                                  resolve_agent, resolve_principal, subject_for)
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


class Agent(unittest.TestCase):
    def headers(self, claims=None, **extra):
        headers = {"authorization": bearer(claims or {"sub": "u1"})}
        headers.update(extra)
        return headers

    def test_switch_off_ignores_everything(self):
        cfg = settings(REVA_AUTHORIZE_AGENT="false")
        self.assertEqual(resolve_agent(self.headers(**{"x-reva-agent-id": "a"}), cfg),
                         (None, "authorize_agent_off"))

    def test_header_is_the_fallback(self):
        cfg = settings()
        self.assertEqual(resolve_agent(self.headers(**{"x-reva-agent-id": " agent-a "}), cfg),
                         ("agent-a", "header:x-reva-agent-id"))

    def test_token_claim_beats_the_header(self):
        cfg = settings()
        headers = self.headers({"sub": "u1", "act": {"sub": "from-token"}},
                               **{"x-reva-agent-id": "from-header"})
        self.assertEqual(resolve_agent(headers, cfg), ("from-token", "claim:act.sub"))

    def test_client_id_is_opt_in(self):
        headers = self.headers({"sub": "u1", "client_id": "ui-app"})
        self.assertEqual(resolve_agent(headers, settings())[0], None)
        cfg = settings(REVA_AGENT_CLAIMS="act.sub,client_id")
        self.assertEqual(resolve_agent(headers, cfg), ("ui-app", "claim:client_id"))

    def test_no_claims_configured_means_the_token_is_not_decoded(self):
        cfg = settings(REVA_AGENT_CLAIMS="")
        headers = self.headers({"sub": "u1", "act": {"sub": "ignored"}})
        self.assertEqual(resolve_agent(headers, cfg), (None, "user_fallback"))

    def test_custom_header_and_id_map(self):
        cfg = settings(REVA_AGENT_HEADER="X-Caller-Agent",
                       REVA_AGENT_ID_MAP='{"orchestrator": "acme-orchestrator"}')
        self.assertEqual(resolve_agent(self.headers(**{"x-caller-agent": "orchestrator"}), cfg)[0],
                         "acme-orchestrator")
        self.assertEqual(resolve_agent(self.headers(**{"x-caller-agent": "other"}), cfg)[0], "other")

    def test_unresolved_falls_back_to_the_user(self):
        self.assertEqual(resolve_agent(self.headers(), settings()), (None, "user_fallback"))
        self.assertEqual(subject_for("u1", None), {"type": "User", "id": "u1"})
        self.assertEqual(subject_for("u1", "agent-a"), {"type": "Agent", "id": "agent-a"})


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
        headers = {"x-reva-thread-id": "from-header", "mcp-session-id": "from-mcp"}
        self.assertEqual(resolve_thread(headers, "ctx", TRACE), ("from-header", "header"))
        self.assertEqual(resolve_thread({"mcp-session-id": "m"}, "ctx", TRACE),
                         ("ctx", "contextId"))
        self.assertEqual(resolve_thread({"mcp-session-id": "m"}, "", TRACE),
                         ("m", "mcp-session-id"))
        self.assertEqual(resolve_thread({}, "", TRACE), (TRACE, "trace"))


if __name__ == "__main__":
    unittest.main()
