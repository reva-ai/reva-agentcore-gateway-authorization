import unittest
from dataclasses import replace
from unittest import mock

from interceptor import rtg
from interceptor.classify import Call
from interceptor.rtg import (ALLOW, CONDITIONAL, OPERATIONAL, POLICY_DENY, REJECTED,
                             build_request, evaluate, interpret, request_headers,
                             summarize_headers)

from .support import TOKEN, TRACE, FakeRTG, settings


def tool_call(**arguments):
    return Call(kind="tool", action="invokeTool",
                resource={"type": "Tool", "id": "srv/tool", "name": "tool"},
                prompt='{"q":1}', target="srv", span_key="k", arguments=arguments)


USER = {"type": "User", "id": "u1"}


def body_for(cfg, **overrides):
    args = dict(call=tool_call(), principal="u1", subject=USER, role="assistant", groups=[])
    args.update(overrides)
    return build_request(cfg, **args)


class BuildRequest(unittest.TestCase):
    def test_shape_for_a_tool_call(self):
        body = body_for(settings(), thread_id="chat-1")
        a2a = body["rtg/a2a"]
        self.assertEqual(body["content"], '{"q":1}')
        self.assertEqual(a2a["subject"], USER)
        self.assertEqual(a2a["principal"], USER)
        self.assertEqual(a2a["action"], {"name": "invokeTool"})
        self.assertEqual(a2a["resource"]["id"], "srv/tool")
        self.assertEqual(a2a["transmission"], {
            "promptKey": "content", "content": '{"q":1}', "role": "assistant",
            "contentType": "text/plain"})
        self.assertEqual(a2a["threadId"], "chat-1")
        self.assertEqual(a2a["session"], {"id": "chat-1"})
        # RTG owns hops: body carries neither hops nor a root session duplicate.
        self.assertNotIn("session", body)
        self.assertNotIn("context", a2a)
        self.assertNotIn("entities", a2a)

    def test_custom_prompt_key(self):
        body = body_for(settings(REVA_PROMPT_KEY="userQuery"))
        a2a = body["rtg/a2a"]
        self.assertEqual(a2a["transmission"]["promptKey"], "userQuery")
        self.assertEqual(a2a["transmission"]["userQuery"], '{"q":1}')
        self.assertEqual(body["userQuery"], '{"q":1}')
        self.assertNotIn("content", a2a["transmission"])

    def test_omit_subject_for_nested_txn_hop(self):
        body = body_for(settings(), omit_subject=True, thread_id="t1")
        a2a = body["rtg/a2a"]
        self.assertNotIn("subject", a2a)
        self.assertNotIn("principal", a2a)
        self.assertEqual(a2a["threadId"], "t1")

    def test_context_map_lifts_arguments_and_drops_empty_values(self):
        cfg = settings(REVA_CONTEXT_MAP='{"countries": "Org_req_countries", "years": "Org_req_years",'
                                        ' "clients": "Org_req_clients", "n": "Org_n"}')
        call = tool_call(countries=["ES", "FR"], years=[], clients="", n=0)
        context = body_for(cfg, call=call)["rtg/a2a"]["context"]
        self.assertEqual(context["Org_req_countries"], ["ES", "FR"])
        self.assertEqual(context["Org_n"], 0)                 # zero is a value, not empty
        self.assertNotIn("Org_req_years", context)            # an empty set fails validation
        self.assertNotIn("Org_req_clients", context)

    def test_groups_become_a_user_entity_with_group_parents(self):
        body = body_for(settings(), groups=["admins", "eu"])
        self.assertEqual(body["rtg/a2a"]["entities"], [{"uid": USER, "parents": [
            {"type": "UserGroup", "id": "admins"}, {"type": "UserGroup", "id": "eu"}]}])


class Headers(unittest.TestCase):
    def names(self, **env):
        return dict(request_headers(settings(**env), TRACE, "b" * 16, "chat"))

    def test_api_token_mode(self):
        headers = self.names()
        self.assertEqual(headers["X-API-Token"], f"Bearer {TOKEN}")
        self.assertEqual(headers["X-Reva-Token-Request"], "transaction")
        self.assertEqual(headers["traceparent"], f"00-{TRACE}-{'b' * 16}-01")
        self.assertEqual(headers["X-Reva-Thread-Id"], "chat")
        self.assertEqual(headers["x-ms-correlation-id"], TRACE)
        for absent in ("Authorization", "policyStoreId", "X-API-Origin-App"):
            self.assertNotIn(absent, headers)

    def test_api_token_mode_forwards_user_jwt_and_txn_token(self):
        headers = dict(request_headers(
            settings(), TRACE, "b" * 16, "chat",
            user_bearer="user.jwt.here", txn_token="txn.jwt.here"))
        self.assertEqual(headers["X-API-Token"], f"Bearer {TOKEN}")
        self.assertEqual(headers["Authorization"], "Bearer user.jwt.here")
        self.assertEqual(headers["X-Transaction-Token"], "txn.jwt.here")

    def test_the_thread_header_is_sent_only_when_there_is_a_thread(self):
        # a nested hop carries the prior transaction token and no thread id
        headers = dict(request_headers(settings(), TRACE, "b" * 16, "", txn_token="txn.jwt.here"))
        self.assertNotIn("X-Reva-Thread-Id", headers)
        self.assertEqual(headers["X-Transaction-Token"], "txn.jwt.here")

    def test_summarize_authenticates_with_authorization_bearer_in_both_modes(self):
        for mode in ("api-token", "bearer"):
            headers = dict(summarize_headers(settings(REVA_AUTH_MODE=mode), "chat"))
            self.assertEqual(headers["Authorization"], f"Bearer {TOKEN}", mode)
            self.assertEqual(headers["X-Reva-Thread-Id"], "chat")
            self.assertNotIn("X-API-Token", headers)
            self.assertNotIn("X-API-Origin-App", headers)
        origin = dict(summarize_headers(settings(REVA_ORIGIN_APP="aws-agentcore")))
        self.assertEqual(origin["X-API-Origin-App"], "aws-agentcore")

    def test_bearer_mode_sends_the_policy_store_id_only_when_set(self):
        headers = self.names(REVA_AUTH_MODE="bearer", REVA_POLICY_STORE_ID="store-1")
        self.assertEqual(headers["Authorization"], f"Bearer {TOKEN}")
        self.assertEqual(headers["policyStoreId"], "store-1")
        self.assertNotIn("X-API-Token", headers)
        self.assertNotIn("policyStoreId", self.names(REVA_AUTH_MODE="bearer"))

    def test_user_scope_verification_headers_are_opt_in(self):
        headers = self.names(REVA_VERIFY_USER_SCOPE="true", REVA_ORIGIN_APP="aws-agentcore")
        self.assertEqual(headers["X-API-Origin-App"], "aws-agentcore")
        self.assertEqual(headers["X-Reva-Verification-Codes"], "CODE_USER_SCOPE")


class Interpret(unittest.TestCase):
    def test_status_table(self):
        cases = [
            (200, '{"decision": true}', ALLOW),
            (200, '{}', POLICY_DENY),                       # a 2xx without decision:true is no allow
            (200, '{"token": "t"}', POLICY_DENY),
            (200, '{"decision": false, "context": {"reason": "nope"}}', POLICY_DENY),
            (200, '{"guardrails": {"outcome": "conditional_allow", "reason": "review"}}', CONDITIONAL),
            (200, 'not json', OPERATIONAL),
            (403, '{"decision": false, "context": {"reason": "forbid matched"}}', POLICY_DENY),
            (403, '{"decision": false}', POLICY_DENY),
            (403, '{"error_type": "POLICY_DENIED"}', POLICY_DENY),
            (403, '', OPERATIONAL),                         # an edge or proxy refusing: no verdict
            (403, '{"message": "Forbidden"}', OPERATIONAL),
            (401, '{"error_type": "USER_NOT_FOUND"}', POLICY_DENY),
            (401, '{"error_type": "USER_DISABLED"}', POLICY_DENY),
            (401, '{"error_type": "UNAUTHORIZED"}', OPERATIONAL),
            (400, '{"context": {"reason": "invalid session"}}', REJECTED),
            (422, '{}', REJECTED),
            (404, '{}', OPERATIONAL), (413, '{}', OPERATIONAL), (424, '{}', OPERATIONAL),
            (429, '{}', OPERATIONAL), (500, '{}', OPERATIONAL), (503, 'down', OPERATIONAL),
        ]
        for status, text, expected in cases:
            self.assertEqual(interpret(status, text).outcome, expected, (status, text))

    def test_reason_and_error_type_are_captured_for_the_log_only(self):
        decision = interpret(403, '{"error_type": "POLICY_DENIED", "context": {"reason": "x" }}')
        self.assertEqual((decision.error_type, decision.reason), ("POLICY_DENIED", "x"))
        self.assertLessEqual(len(interpret(500, "e" * 5000).reason), 300)


class Evaluate(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(rtg, "_sleep", lambda _: None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_against(self, server, cfg=None, **kwargs):
        cfg = replace(cfg or settings(), base_url=server.url)
        headers = request_headers(cfg, TRACE, "b" * 16, "chat")
        return evaluate(cfg, {"x": 1}, headers, **kwargs)

    def test_header_names_reach_the_wire_exactly_as_written(self):
        with FakeRTG() as server:
            cfg = replace(settings(REVA_AUTH_MODE="bearer", REVA_POLICY_STORE_ID="store-1"))
            self.run_against(server, cfg)
            names = server.header_names()
        self.assertIn("policyStoreId", names)            # not "Policystoreid"
        self.assertIn("Authorization", names)
        self.assertIn("traceparent", names)
        self.assertIn("X-Reva-Thread-Id", names)

    def test_request_goes_to_the_evaluation_path_as_json(self):
        with FakeRTG() as server:
            decision = self.run_against(server)
            self.assertEqual(server.requests[0]["path"], "/pdp/ai/access/ai/evaluation")
            self.assertEqual(server.requests[0]["json"], {"x": 1})
            self.assertEqual(server.header("X-API-Token"), f"Bearer {TOKEN}")
        self.assertEqual((decision.outcome, decision.status, decision.attempts), (ALLOW, 200, 1))

    def test_a_transient_fault_is_retried_once(self):
        with FakeRTG() as server:
            server.queue(503, {}).queue(200, {"decision": True})
            decision = self.run_against(server)
            self.assertEqual(len(server.requests), 2)
        self.assertEqual((decision.outcome, decision.attempts), (ALLOW, 2))

    def test_a_persistent_fault_stays_operational(self):
        with FakeRTG() as server:
            server.default = {"status": 500, "body": {}}
            decision = self.run_against(server)
            self.assertEqual(len(server.requests), 2)
        self.assertEqual((decision.outcome, decision.status), (OPERATIONAL, 500))

    def test_decisions_and_our_own_errors_are_never_retried(self):
        for status, expected, body in ((403, POLICY_DENY, {"decision": False}), (403, OPERATIONAL, {}),
                                       (400, REJECTED, {}), (404, OPERATIONAL, {}),
                                       (413, OPERATIONAL, {})):
            with FakeRTG() as server:
                server.default = {"status": status, "body": body}
                decision = self.run_against(server)
                self.assertEqual(len(server.requests), 1, status)
            self.assertEqual(decision.outcome, expected, status)

    def test_an_unreachable_engine_is_operational(self):
        cfg = replace(settings(), base_url="http://127.0.0.1:9", timeout_seconds=1.0)
        decision = evaluate(cfg, {}, request_headers(cfg, TRACE, "b" * 16, "chat"))
        self.assertEqual((decision.outcome, decision.status), (OPERATIONAL, 0))
        self.assertIn("unreachable", decision.reason)

    def test_a_dropped_connection_is_retried(self):
        with FakeRTG() as server:
            server.queue(200, drop=True).queue(200, {"decision": True})
            decision = self.run_against(server)
        self.assertEqual((decision.outcome, decision.attempts), (ALLOW, 2))

    def test_a_slow_engine_times_out_inside_the_budget(self):
        cfg = replace(settings(), timeout_seconds=0.3, retries=0)
        with FakeRTG() as server:
            server.queue(200, {"decision": True}, delay=1.5)
            decision = self.run_against(server, cfg)
        self.assertEqual(decision.outcome, OPERATIONAL)

    def test_no_time_left_means_no_call(self):
        with FakeRTG() as server:
            decision = self.run_against(server, remaining_ms=2500)   # 500 ms after the margin
            self.assertEqual(server.requests, [])
        self.assertEqual(decision.outcome, OPERATIONAL)
        self.assertEqual(decision.attempts, 0)

    def test_the_per_attempt_timeout_is_capped_by_the_time_left(self):
        seen = []

        def fake_post(url, data, headers, timeout):
            seen.append(timeout)
            return 200, '{"decision": true}'

        with mock.patch.object(rtg, "_post", fake_post):
            evaluate(settings(), {}, [], remaining_ms=7000)           # 5 s after the margin
        self.assertLessEqual(seen[0], 5.0)
        self.assertGreater(seen[0], 4.0)


if __name__ == "__main__":
    unittest.main()
