import base64
import contextlib
import dataclasses
import io
import json
import unittest
from unittest import mock

from interceptor import decide, rtg
from interceptor.secret import SecretError

from .support import (TOKEN, TRACE, FakeRTG, a2a_payload, bearer, http_event,
                      make_jwt, mcp_event, settings, traceparent)


class Harness:
    """The pipeline against a fake RTG."""

    def __init__(self, **env):
        self.env = env
        self.server = FakeRTG()

    def __enter__(self):
        self.server.__enter__()
        self.cfg = settings(REVA_BASE_URL=self.server.url, **self.env)
        self._sleep = mock.patch.object(rtg, "_sleep", lambda _: None)
        self._sleep.start()
        return self

    def __exit__(self, *exc):
        self._sleep.stop()
        self.server.__exit__(*exc)

    def run(self, event):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            out = decide.handle(event, None, self.cfg)
        return out, buffer.getvalue()

    @property
    def body(self):
        """The `rtg/a2a` envelope (token-evaluation shape)."""
        return self.server.requests[-1]["json"]["rtg/a2a"]

    @property
    def root_body(self):
        return self.server.requests[-1]["json"]

    def log(self, logs, event="decision"):
        lines = [json.loads(line) for line in logs.splitlines() if line.strip()]
        return [line for line in lines if line.get("event") == event][-1]


def headers(authorization=True, trace=TRACE, **extra):
    out = {"traceparent": traceparent(trace), "Mcp-Session-Id": "chat-1"}
    if authorization:
        out["Authorization"] = bearer({"sub": "u1"})
    out.update(extra)
    return out


def tool_event(name="srv___tool", args=None, **header_kwargs):
    return mcp_event(name, args or {"q": 1}, headers=headers(**header_kwargs))


def passed(out):
    return "transformedGatewayRequest" in json.dumps(out)


def denied(out):
    return "transformedGatewayResponse" in json.dumps(out)


def deny_code(out):
    block = out["mcp"]["transformedGatewayResponse"]
    return block["body"]["error"]["data"]["code"]


class Evaluation(unittest.TestCase):
    def test_mcp_call_is_evaluated(self):
        with Harness() as h:
            out, logs = h.run(tool_event())
            self.assertTrue(passed(out))
            body = h.body
            self.assertEqual(body["principal"], {"type": "User", "id": "u1"})
            self.assertEqual(body["subject"], {"type": "User", "id": "u1"})
            self.assertEqual(body["action"], {"name": "invokeTool"})
            self.assertEqual(body["resource"]["id"], "srv/tool")
            self.assertEqual(body["session"], {"id": "chat-1"})
            self.assertEqual(body["context"], {"q": 1})     # the tool's arguments, by name
            self.assertIn("rtg/a2a", h.root_body)
            self.assertEqual(h.server.header("X-Reva-Thread-Id"), "chat-1")
            self.assertEqual(h.server.header("X-Reva-Token-Request"), "transaction")
            self.assertTrue(h.server.header("traceparent").startswith(f"00-{TRACE}-"))
            entry = h.log(logs)
            self.assertEqual((entry["decision"], entry["traceSource"]),
                             ("permit", "traceparent"))

    def test_a_later_hop_needs_the_jwt_and_sends_no_hops(self):
        with Harness() as h:
            h.run(tool_event("srv___first"))
            later = mcp_event("srv___second", {"q": 2},
                              headers={"traceparent": traceparent()})
            self.assertEqual(deny_code(h.run(later)[0]), "missing_authorization")
            h.run(mcp_event("srv___second", {"q": 2}, headers=headers()))
            self.assertEqual(h.body["principal"]["id"], "u1")
            self.assertEqual(h.body["session"], {"id": "chat-1"})
            self.assertEqual(h.body["context"], {"q": 2})   # each hop describes its own call
            self.assertEqual(h.server.header("X-Reva-Thread-Id"), "chat-1")

    def test_groups_are_read_from_the_jwt_on_every_hop(self):
        with Harness(REVA_GROUPS_CLAIM="cognito:groups") as h:
            auth = headers(authorization=False,
                           Authorization=bearer({"sub": "u1", "cognito:groups": ["admins"]}))
            h.run(mcp_event("srv___a", {"q": 1}, headers=auth))
            h.run(mcp_event("srv___b", {"q": 2}, headers=auth))
            self.assertEqual(h.body["entities"][0]["parents"],
                             [{"type": "UserGroup", "id": "admins"}])

    def test_no_thread_id_anywhere_makes_the_prompt_its_own_chat(self):
        with Harness() as h:
            event = mcp_event("srv___t", {"q": 1}, headers={
                "traceparent": traceparent(), "Authorization": bearer()})
            _, logs = h.run(event)
            self.assertEqual(h.server.header("X-Reva-Thread-Id"), TRACE)
            self.assertEqual(h.log(logs, "warn")["code"], "thread_missing")

    def test_call_without_a_token_is_denied_locally_and_the_rtg_is_not_asked(self):
        with Harness() as h:
            out, logs = h.run(tool_event(authorization=False))
            self.assertTrue(denied(out))
            self.assertEqual(deny_code(out), "missing_authorization")
            self.assertEqual(out["mcp"]["transformedGatewayResponse"]["statusCode"], 403)
            self.assertEqual(h.server.requests, [])
            self.assertIn("passRequestHeaders", h.log(logs, "local_deny")["reason"])

    def test_a_token_without_the_user_claim_is_denied(self):
        with Harness() as h:
            event = mcp_event("srv___t", {}, headers=headers(
                authorization=False, Authorization=bearer({"email": "x@y"})))
            self.assertEqual(deny_code(h.run(event)[0]), "principal_unresolved")


class Enforcement(unittest.TestCase):
    def test_a_policy_deny_is_enforced(self):
        with Harness() as h:
            h.server.queue(403, {"decision": False, "context": {"reason": "forbid matched"}})
            out, logs = h.run(tool_event("srv___second"))
            self.assertTrue(denied(out))
            self.assertEqual(deny_code(out), "policy_denied")
            message = out["mcp"]["transformedGatewayResponse"]["body"]["error"]["message"]
            self.assertEqual(message, "Blocked by your organization's security policy.")
            self.assertNotIn("forbid matched", json.dumps(out))
            self.assertEqual(h.log(logs)["reason"], "forbid matched")

    def test_monitor_mode_logs_the_denial_and_lets_the_call_through(self):
        with Harness(REVA_MONITOR_MODE="true") as h:
            h.server.queue(403, {"decision": False})
            out, logs = h.run(tool_event())
            self.assertTrue(passed(out))
            self.assertEqual(h.log(logs)["decision"], "monitor_would_deny")

    def test_dependency_failure_fails_closed_by_default(self):
        with Harness() as h:
            h.server.default = {"status": 500, "body": {}}
            out, _ = h.run(tool_event())
            self.assertEqual(deny_code(out), "rtg_unavailable")
            self.assertEqual(len(h.server.requests), 2)

    def test_fail_open_passes_on_a_dependency_failure(self):
        with Harness(REVA_FAIL_OPEN="true") as h:
            h.server.default = {"status": 503, "body": {}}
            out, logs = h.run(tool_event())
            self.assertTrue(passed(out))
            self.assertEqual(h.log(logs)["decision"], "permit_fail_open")

    def test_fail_open_never_covers_a_policy_deny_or_an_invalid_request(self):
        with Harness(REVA_FAIL_OPEN="true") as h:
            h.server.queue(403, {"decision": False})
            self.assertEqual(deny_code(h.run(tool_event())[0]), "policy_denied")
            # The call carries context, so a 400 is retried without it: both are refused.
            h.server.queue(400, {"context": {"reason": "invalid session"}})
            h.server.queue(400, {"context": {"reason": "invalid session"}})
            self.assertEqual(deny_code(h.run(tool_event("srv___other"))[0]), "rtg_rejected")

    def test_a_request_refused_because_of_its_context_is_evaluated_again_without_it(self):
        with Harness() as h:
            h.server.queue(400, {"context": {"reason": "invalid Cedar context"}})
            out, logs = h.run(tool_event(args={"channel": "web"}))
            self.assertTrue(passed(out))
            first, second = (r["json"]["rtg/a2a"] for r in h.server.requests[-2:])
            self.assertEqual(first["context"], {"channel": "web"})
            self.assertNotIn("context", second)
            self.assertEqual(second["resource"], first["resource"])
            self.assertEqual(h.log(logs, "warn")["code"], "context_refused")

    def test_a_400_without_context_is_not_retried(self):
        with Harness() as h:
            h.server.queue(400, {"context": {"reason": "invalid session"}})
            out, _ = h.run(mcp_event("srv___tool", {}, headers=headers()))
            self.assertEqual(deny_code(out), "rtg_rejected")
            self.assertEqual(len(h.server.requests), 1)

    def test_what_context_left_out_is_logged_by_name_in_debug_only(self):
        args = {"password": "hunter2", "q": 1}
        with Harness(REVA_DEBUG="true") as h:
            _, logs = h.run(tool_event(args=args))
            self.assertEqual(h.body["context"], {"q": 1})
            self.assertEqual(h.log(logs, "debug_context_left_out")["pairs"],
                             ["password (name looks like a credential)"])
        with Harness() as h:
            _, logs = h.run(tool_event(args=args))
            self.assertNotIn("debug_context_left_out", logs)
            self.assertNotIn("hunter2", logs)

    def test_a_200_without_an_allow_decision_is_a_deny(self):
        with Harness() as h:
            h.server.default = {"status": 200, "body": {"token": "t"}}
            out, _ = h.run(tool_event())
            self.assertEqual(deny_code(out), "policy_denied")

    def test_a_403_that_is_not_a_verdict_is_a_dependency_failure_not_a_policy_deny(self):
        refusal = {"status": 403, "body": {"message": "Forbidden"}}      # an edge or proxy, no decision
        with Harness() as h:
            h.server.default = refusal
            out, _ = h.run(tool_event())
            self.assertEqual(deny_code(out), "rtg_unavailable")
        with Harness(REVA_MONITOR_MODE="true") as h:                     # monitor mode must not wave it through
            h.server.default = refusal
            self.assertTrue(denied(h.run(tool_event())[0]))
        with Harness(REVA_FAIL_OPEN="true") as h:                        # fail-open covers it
            h.server.default = refusal
            self.assertTrue(passed(h.run(tool_event())[0]))

    def test_conditional_allow_is_denied_unless_configured(self):
        body = {"guardrails": {"outcome": "conditional_allow", "reason": "review"}}
        with Harness() as h:
            h.server.queue(200, body)
            self.assertEqual(deny_code(h.run(tool_event())[0]), "policy_denied")
        with Harness(REVA_CONDITIONAL_ALLOW="allow") as h:
            h.server.queue(200, body)
            self.assertTrue(passed(h.run(tool_event())[0]))

    def test_custom_deny_message_and_status(self):
        with Harness(REVA_DENY_MESSAGE="No.", REVA_DENY_STATUS="451") as h:
            h.server.queue(403, {"decision": False})
            block = h.run(tool_event())[0]["mcp"]["transformedGatewayResponse"]
            self.assertEqual(block["statusCode"], 451)
            self.assertEqual(block["body"]["error"]["message"], "No.")
            self.assertEqual(block["body"]["jsonrpc"], "2.0")
            self.assertEqual(block["body"]["id"], 1)


class SubjectAndTxnToken(unittest.TestCase):
    def test_entry_hop_subject_is_always_the_user(self):
        with Harness() as h:
            _, logs = h.run(tool_event(**{"x-reva-agent-id": "ignored-agent"}))
            self.assertEqual(h.body["subject"], {"type": "User", "id": "u1"})
            self.assertEqual(h.log(logs)["subjectSource"], "user")

    def test_the_first_call_of_a_turn_is_role_user_whatever_it_is(self):
        with Harness() as h:
            h.run(tool_event())                                # an MCP tool call as the first call
            self.assertEqual(h.body["transmission"]["role"], "user")

    def test_a_nested_hop_sends_no_thread_even_if_the_call_carries_one(self):
        with Harness() as h:
            _, logs = h.run(tool_event(**{"x-transaction-token": "prior.txn.jwt",
                                          "X-Reva-Thread-Id": "chat-7", "Mcp-Session-Id": "chat-7"}))
            self.assertNotIn("session", h.body)
            self.assertNotIn("threadId", h.body)
            self.assertIsNone(h.server.header("X-Reva-Thread-Id"))
            self.assertEqual(h.log(logs)["threadSource"], "nested_hop")
            self.assertEqual(h.body["transmission"]["role"], "agent")

    def test_a_transaction_token_sent_with_a_bearer_prefix_is_forwarded_bare(self):
        with Harness() as h:
            h.run(tool_event(**{"x-transaction-token": "Bearer prior.txn.jwt"}))
            self.assertEqual(h.server.header("X-Transaction-Token"), "prior.txn.jwt")

    def test_nested_hop_omits_subject_when_txn_token_present(self):
        with Harness() as h:
            h.server.default = {"status": 200, "body": {"decision": True, "token": "minted.txn"}}
            out, logs = h.run(tool_event(**{"x-transaction-token": "prior.txn.jwt"}))
            self.assertTrue(passed(out))
            self.assertNotIn("subject", h.body)
            self.assertNotIn("principal", h.body)
            self.assertEqual(h.server.header("X-Transaction-Token"), "prior.txn.jwt")
            self.assertEqual(h.log(logs)["subjectSource"], "transaction_token")


class A2aAndRuntime(unittest.TestCase):
    def a2a(self, **kwargs):
        return http_event("/agent-a/invocations",
                          a2a_payload(**kwargs), headers=headers())

    def test_an_a2a_call_is_an_invoke_agent_hop_by_the_user(self):
        with Harness() as h:
            event = self.a2a(text="Which projects are at risk?", context_id="ctx-7")
            event["http"]["gatewayRequest"]["headers"].pop("Mcp-Session-Id")
            out, _ = h.run(event)
            self.assertEqual(out["http"]["transformedGatewayRequest"]["body"],
                             event["http"]["gatewayRequest"]["body"])
            body = h.body
            self.assertEqual(h.root_body["content"], "Which projects are at risk?")
            self.assertEqual(body["action"], {"name": "invokeAgent"})
            self.assertEqual(body["resource"]["type"], "Agent")
            self.assertEqual(body["resource"]["id"], "agent-a")
            self.assertEqual(body["subject"], {"type": "User", "id": "u1"})
            self.assertEqual(body["transmission"]["role"], "user")
            self.assertEqual(body["transmission"]["content"], "Which projects are at risk?")
            self.assertEqual(h.server.header("X-Reva-Thread-Id"), "ctx-7")
            self.assertEqual(body["session"], {"id": "ctx-7"})

    def test_a2a_metadata_reaches_the_context_by_name_and_through_the_map(self):
        with Harness(REVA_CONTEXT_MAP='{"countries": "Org_req_countries", "years": "Org_req_years"}'
                     ) as h:
            event = http_event("/agent-a/invocations", a2a_payload(), headers=headers())
            payload = json.loads(base64.b64decode(event["http"]["gatewayRequest"]["body"]))
            payload["params"]["message"]["metadata"] = {
                "countries": ["ES", "PT"], "years": [], "traceNote": "stays here"}
            event = http_event("/agent-a/invocations", payload, headers=headers())
            h.run(event)
            context = h.body["context"]
            self.assertEqual(context["Org_req_countries"], ["ES", "PT"])   # renamed by the map
            self.assertEqual(context["countries"], ["ES", "PT"])           # and under its own name
            self.assertEqual(context["traceNote"], "stays here")
            self.assertNotIn("Org_req_years", context)                     # an empty set
            self.assertNotIn("years", context)

    def test_the_body_context_can_be_turned_off_and_the_map_still_works(self):
        with Harness(REVA_CONTEXT_FROM_BODY="false",
                     REVA_CONTEXT_MAP='{"countries": "Org_req_countries"}') as h:
            payload = a2a_payload()
            payload["params"]["message"]["metadata"] = {
                "countries": ["ES"], "traceNote": "stays here"}
            h.run(http_event("/agent-a/invocations", payload, headers=headers()))
            self.assertEqual(h.body["context"], {"Org_req_countries": ["ES"]})
            self.assertNotIn("traceNote", json.dumps(h.body))

    def test_an_a2a_deny_is_a_jsonrpc_error_with_the_request_id_base64_encoded(self):
        with Harness() as h:
            h.server.queue(403, {"decision": False})
            out, _ = h.run(self.a2a())
            block = out["http"]["transformedGatewayResponse"]
            self.assertEqual((block["statusCode"], block["contentType"]), (403, "application/json"))
            payload = json.loads(base64.b64decode(block["body"]))
            self.assertEqual(payload["id"], "req-1")
            self.assertEqual(payload["error"]["data"]["code"], "policy_denied")

    def test_a_plain_runtime_deny_is_a_plain_error_object(self):
        with Harness() as h:
            h.server.queue(403, {"decision": False})
            event = http_event("/my-agent/invocations", {"prompt": "hi"}, headers=headers())
            payload = json.loads(base64.b64decode(
                h.run(event)[0]["http"]["transformedGatewayResponse"]["body"]))
            self.assertEqual(payload["error"]["type"], "permission_denied")
            self.assertEqual(payload["error"]["code"], "policy_denied")

    def test_agent_to_agent_hop_uses_txn_token_not_agent_header(self):
        with Harness() as h:
            h.server.default = {"status": 200, "body": {"decision": True, "token": "t1"}}
            h.run(http_event("/orchestrator/invocations", a2a_payload("question"),
                             headers=headers()))
            h.run(http_event("/analytics/invocations", a2a_payload("sub question"),
                             headers={**headers(), "x-transaction-token": "t1"}))
            body = h.body
            self.assertNotIn("subject", body)
            self.assertNotIn("principal", body)
            # Nested hop with txn token uses role=agent (speaker is the agent).
            self.assertEqual(body["transmission"]["role"], "agent")
            self.assertNotIn("context", body)
            self.assertEqual(h.server.header("X-Transaction-Token"), "t1")


class PassThroughAndLocalDenies(unittest.TestCase):
    def test_traffic_that_is_not_a_call_passes_without_asking(self):
        with Harness() as h:
            for event in (mcp_event(method="tools/list"), mcp_event(method="initialize"),
                          mcp_event(http_method="GET", body=None),
                          http_event("/health", {"x": 1})):
                self.assertTrue(passed(h.run(event)[0]), event)
            self.assertEqual(h.server.requests, [])

    def test_inference_chat_completions_is_evaluated_as_invoke_model(self):
        with Harness() as h:
            event = http_event(
                "/inference/v1/chat/completions",
                {"model": "gpt-4o",
                 "messages": [{"role": "user", "content": "say hi"}]},
                headers=headers())
            out, _ = h.run(event)
            self.assertTrue(passed(out))
            self.assertEqual(h.body["action"]["name"], "invokeModel")
            self.assertEqual(h.body["resource"],
                             {"type": "Model", "id": "gpt-4o", "name": "gpt-4o"})
            self.assertEqual(h.root_body.get("userQuery") or h.root_body.get("content"),
                             "say hi")

    def test_a_bodiless_passthrough_echoes_an_empty_object_not_null(self):
        with Harness() as h:
            out, _ = h.run(mcp_event(http_method="GET", body=None))
            self.assertEqual(out["mcp"]["transformedGatewayRequest"], {"body": {}})

    def test_unclassified_traffic_can_be_denied(self):
        with Harness(REVA_UNCLASSIFIED="deny") as h:
            out, _ = h.run(http_event("/health", {"x": 1}))
            payload = json.loads(base64.b64decode(out["http"]["transformedGatewayResponse"]["body"]))
            self.assertEqual(payload["error"]["code"], "unclassified_traffic")

    def test_a_batch_hiding_a_tool_call_is_denied(self):
        with Harness() as h:
            batch = [{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "s___t"}}]
            out, _ = h.run(mcp_event(body=batch, headers=headers()))
            self.assertEqual(deny_code(out), "batch_unsupported")
            self.assertEqual(h.server.requests, [])

    def test_a_response_leg_is_returned_untouched_even_with_a_broken_config(self):
        with Harness() as h:
            h.cfg = settings(REVA_AUTH_MODE="nonsense")
            response = {"statusCode": 200, "body": {"jsonrpc": "2.0", "id": 1,
                                                    "result": {"content": []}}}
            out, _ = h.run(mcp_event(response=response))
            self.assertEqual(out["mcp"]["transformedGatewayResponse"],
                             {"body": response["body"], "statusCode": 200})
            http_response = {"http": {"gatewayRequest": None,
                                      "gatewayResponse": {"statusCode": 200, "body": "e30="}}}
            self.assertEqual(h.run(http_response)[0],
                             {"interceptorOutputVersion": "1.0", "http": {}})

    def test_a_bad_config_denies_every_request(self):
        with Harness() as h:
            h.cfg = settings(REVA_AUTH_MODE="nonsense")
            out, logs = h.run(tool_event())
            self.assertEqual(deny_code(out), "config_error")
            self.assertIn("REVA_AUTH_MODE", h.log(logs, "local_deny")["reason"])

    def test_not_a_gateway_event_is_denied_not_raised(self):
        with Harness() as h:
            for bad in (None, [], "text", {}, {"mcp": "x"}):
                out, _ = h.run(bad)
                self.assertIn("transformedGatewayResponse", json.dumps(out))


class Trace(unittest.TestCase):
    def test_no_traceparent_mints_a_trace(self):
        with Harness() as h:
            event = mcp_event("srv___t", {"q": 1}, headers={"Authorization": bearer(),
                                                            "Mcp-Session-Id": "chat-1"})
            out, logs = h.run(event)
            self.assertTrue(passed(out))
            self.assertEqual(h.log(logs)["traceSource"], "minted")
            self.assertTrue(h.server.header("traceparent"))
            self.assertEqual(h.body["session"], {"id": "chat-1"})

    def test_no_traceparent_can_be_denied(self):
        with Harness(REVA_ON_MISSING_TRACEPARENT="deny") as h:
            out, _ = h.run(mcp_event("srv___t", {}, headers={"Authorization": bearer()}))
            self.assertEqual(deny_code(out), "traceparent_missing")

    def test_trace_header_fallback_for_callers_that_cannot_send_traceparent(self):
        with Harness(REVA_TRACE_HEADER="X-Trace-Id") as h:
            event = mcp_event("srv___t", {}, headers={
                "Authorization": bearer(), "Mcp-Session-Id": "c", "X-Trace-Id": "d" * 32})
            _, logs = h.run(event)
            self.assertEqual((h.log(logs)["trace"], h.log(logs)["traceSource"]),
                             ("d" * 32, "header"))


class Secrecy(unittest.TestCase):
    def test_no_token_ever_reaches_the_logs_even_in_debug(self):
        with Harness(REVA_DEBUG="true") as h:
            jwt = make_jwt({"sub": "u1"})
            event = mcp_event("srv___t", {"q": 1}, headers=headers())
            _, logs = h.run(event)
            h.server.queue(500, {})
            h.server.queue(500, {})
            _, failure_logs = h.run(tool_event("srv___other"))
            for text in (logs, failure_logs):
                self.assertNotIn(TOKEN, text)
                self.assertNotIn(jwt, text)
                self.assertNotIn("Bearer", text)
            shape = h.log(logs, "debug_event")
            self.assertIn("authorization", shape["headers"])


class RtgCredential(unittest.TestCase):
    """The RTG token comes from Secrets Manager, and only when a call is actually evaluated."""

    def test_the_token_comes_from_the_secret(self):
        with Harness() as h:
            h.cfg = dataclasses.replace(h.cfg, token="")
            with mock.patch("interceptor.secret.get_token", return_value="from-the-secret"):
                out, _ = h.run(tool_event())
            self.assertTrue(passed(out))
            self.assertEqual(h.server.header("X-API-Token"), "Bearer from-the-secret")

    def test_an_unreadable_secret_denies_before_the_rtg_is_touched(self):
        for env in ({}, {"REVA_FAIL_OPEN": "true"}):
            with self.subTest(env=env), Harness(**env) as h:
                h.cfg = dataclasses.replace(h.cfg, token="")
                failure = SecretError("cannot read secret 'reva/secrets': AccessDenied")
                with mock.patch("interceptor.secret.get_token", side_effect=failure):
                    out, logs = h.run(tool_event())
                self.assertEqual(deny_code(out), "token_unavailable")
                self.assertEqual(h.server.requests, [])
                self.assertIn("cannot read secret", h.log(logs, "local_deny")["reason"])

    def test_calls_that_are_not_evaluated_never_read_the_secret(self):
        with Harness() as h:
            h.cfg = dataclasses.replace(h.cfg, token="")
            with mock.patch("interceptor.secret.get_token", side_effect=SecretError("down")) as get:
                self.assertTrue(passed(h.run(mcp_event(method="tools/list",
                                                       headers=headers()))[0]))
                h.run(mcp_event(response={"statusCode": 200, "body": {}}))
            get.assert_not_called()


class LambdaHandler(unittest.TestCase):
    def setUp(self):
        import handler
        self.handler = handler
        self.addCleanup(setattr, handler, "_SETTINGS", handler._SETTINGS)

    def test_lambda_handler_never_raises(self):
        self.handler._SETTINGS = settings()
        for bad in (None, [], "x", 5, {}, {"mcp": 5}, {"http": {"gatewayRequest": 5}},
                    {"mcp": {"gatewayRequest": {"body": {"method": ["x"]}}}}):
            with contextlib.redirect_stdout(io.StringIO()):
                out = self.handler.lambda_handler(bad, None)
            self.assertEqual(out["interceptorOutputVersion"], "1.0")

    def test_an_internal_error_is_a_deny_shaped_for_the_transport(self):
        self.handler._SETTINGS = settings()
        with mock.patch.object(decide, "handle", side_effect=RuntimeError("boom")):
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                mcp = self.handler.lambda_handler(mcp_event(), None)
                http = self.handler.lambda_handler(http_event(payload={}), None)
        self.assertEqual(mcp["mcp"]["transformedGatewayResponse"]["statusCode"], 403)
        self.assertEqual(mcp["mcp"]["transformedGatewayResponse"]["body"]["error"]["data"]["code"],
                         "internal_error")
        self.assertEqual(http["http"]["transformedGatewayResponse"]["statusCode"], 403)
        self.assertIn("RuntimeError", buffer.getvalue())

    def test_settings_are_built_once_per_container(self):
        self.handler._SETTINGS = None
        with mock.patch.dict("os.environ", {"REVA_BASE_URL": "https://example.test"}):
            first = self.handler._settings()
            self.assertIs(first, self.handler._settings())


if __name__ == "__main__":
    unittest.main()
