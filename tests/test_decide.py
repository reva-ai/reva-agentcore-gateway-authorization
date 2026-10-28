import base64
import contextlib
import dataclasses
import io
import json
import threading
import unittest
from unittest import mock

from interceptor import decide, rtg
from interceptor.history import MemoryStore, StoreError
from interceptor.secret import SecretError

from .support import (OTHER_TRACE, TOKEN, TRACE, FakeRTG, a2a_payload, bearer, http_event,
                      make_jwt, mcp_event, settings, traceparent)


class Harness:
    """The pipeline against a fake RTG and an in-memory store."""

    def __init__(self, **env):
        self.env = env
        self.server = FakeRTG()

    def __enter__(self):
        self.server.__enter__()
        self.cfg = settings(REVA_BASE_URL=self.server.url, **self.env)
        self.store = MemoryStore(self.cfg)
        self._sleep = mock.patch.object(rtg, "_sleep", lambda _: None)
        self._sleep.start()
        return self

    def __exit__(self, *exc):
        self._sleep.stop()
        self.server.__exit__(*exc)

    def run(self, event, store="default"):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            out = decide.handle(event, None, self.cfg,
                                self.store if store == "default" else store)
        return out, buffer.getvalue()

    @property
    def body(self):
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


class FirstCallAndLaterHops(unittest.TestCase):
    def test_first_mcp_call_is_evaluated_and_recorded(self):
        with Harness() as h:
            out, logs = h.run(tool_event())
            self.assertTrue(passed(out))
            body = h.body
            self.assertEqual(body["principal"], {"type": "User", "id": "u1"})
            self.assertEqual(body["subject"], {"type": "User", "id": "u1"})
            self.assertEqual(body["action"], {"name": "invokeTool"})
            self.assertEqual(body["resource"]["id"], "srv/tool")
            self.assertEqual(body["session"]["id"], "chat-1")
            self.assertEqual(body["session"]["turn"], 1)
            self.assertEqual(body["context"], {"hops": []})
            self.assertEqual(h.server.header("X-Reva-Thread-Id"), "chat-1")
            self.assertTrue(h.server.header("traceparent").startswith(f"00-{TRACE}-"))
            record = h.store.get_trace(TRACE)
            self.assertEqual((record["principal"], record["thread_id"]), ("u1", "chat-1"))
            self.assertEqual(record["hops"][0]["resource"], {"type": "Tool", "id": "srv/tool"})
            entry = h.log(logs)
            self.assertEqual((entry["decision"], entry["firstCall"], entry["traceSource"]),
                             ("permit", True, "traceparent"))

    def test_a_later_hop_needs_no_jwt_and_sees_the_history(self):
        with Harness() as h:
            h.run(tool_event("srv___first"))
            # No user JWT, no thread id, no session: only the traceparent.
            h.run(mcp_event("srv___second", {"q": 2},
                            headers={"traceparent": traceparent()}))
            body = h.body
            self.assertEqual(body["principal"]["id"], "u1")           # read from the table
            self.assertEqual(body["session"]["id"], "chat-1")
            self.assertEqual(h.server.header("X-Reva-Thread-Id"), "chat-1")
            self.assertEqual(len(body["context"]["hops"]), 1)
            self.assertEqual(body["context"]["hops"][0]["resource"]["id"], "srv/first")
            self.assertEqual(len(body["context"]["conversation"]["messages"]), 1)
            self.assertEqual([m["seq"] for m in body["context"]["conversation"]["messages"]],
                             [h["seq"] for h in body["context"]["hops"]])

    def test_a_later_hop_may_carry_a_different_token_without_changing_the_principal(self):
        with Harness() as h:
            h.run(tool_event("srv___first"))
            other = headers(authorization=False, Authorization=bearer({"sub": "agent-client"}))
            h.run(mcp_event("srv___second", {"q": 2}, headers=other))
            self.assertEqual(h.body["principal"]["id"], "u1")

    def test_groups_are_stored_and_sent_on_later_hops(self):
        with Harness(REVA_GROUPS_CLAIM="cognito:groups") as h:
            first = headers(authorization=False,
                            Authorization=bearer({"sub": "u1", "cognito:groups": ["admins"]}))
            h.run(mcp_event("srv___a", {"q": 1}, headers=first))
            h.run(mcp_event("srv___b", {"q": 2}, headers={"traceparent": traceparent()}))
            self.assertEqual(h.body["entities"][0]["parents"],
                             [{"type": "UserGroup", "id": "admins"}])

    def test_a_second_prompt_in_the_same_chat_is_turn_two(self):
        with Harness() as h:
            h.run(tool_event(trace=TRACE))
            h.run(tool_event(trace=OTHER_TRACE))
            self.assertEqual(h.body["session"]["turn"], 2)
            self.assertEqual(h.body["context"], {"hops": []})          # a fresh prompt, no hops

    def test_startedAt_is_the_chats_and_stable(self):
        with Harness() as h:
            h.run(tool_event(trace=TRACE))
            first = h.body["session"]["startedAt"]
            h.run(tool_event(trace=OTHER_TRACE))
            self.assertEqual(h.body["session"]["startedAt"], first)

    def test_no_thread_id_anywhere_makes_the_prompt_its_own_chat(self):
        with Harness() as h:
            event = mcp_event("srv___t", {"q": 1}, headers={
                "traceparent": traceparent(), "Authorization": bearer()})
            _, logs = h.run(event)
            self.assertEqual(h.body["session"]["id"], TRACE)
            self.assertEqual(h.log(logs, "warn")["code"], "thread_missing")

    def test_first_call_without_a_token_is_denied_locally_and_the_rtg_is_not_asked(self):
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

    def test_gateway_retry_of_the_same_call_is_recorded_once_and_is_not_its_own_history(self):
        with Harness() as h:
            event = tool_event()
            h.run(event)
            h.run(event)
            self.assertEqual(len(h.store.get_trace(TRACE)["hops"]), 1)
            self.assertEqual(h.body["context"]["hops"], [])

    def test_parallel_first_calls_agree_on_one_principal(self):
        with Harness() as h:
            barrier = threading.Barrier(2)
            real = h.store.get_trace

            def synchronised(trace):
                result = real(trace)
                barrier.wait(timeout=5)       # both calls see "no record" before either writes
                return result

            h.store.get_trace = synchronised

            def call(sub):
                event = mcp_event("srv___t", {"q": sub}, headers=headers(
                    authorization=False, Authorization=bearer({"sub": sub})))
                decide.handle(event, None, h.cfg, h.store)

            threads = [threading.Thread(target=call, args=(s,)) for s in ("alice", "mallory")]
            with contextlib.redirect_stdout(io.StringIO()):    # one redirect: it is process-wide
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
            principals = {r["json"]["principal"]["id"] for r in h.server.requests}
            self.assertEqual(len(principals), 1)


class Enforcement(unittest.TestCase):
    def test_a_policy_deny_is_enforced_and_not_recorded(self):
        with Harness() as h:
            h.run(tool_event("srv___first"))
            h.server.queue(403, {"decision": False, "context": {"reason": "forbid matched"}})
            out, logs = h.run(tool_event("srv___second"))
            self.assertTrue(denied(out))
            self.assertEqual(deny_code(out), "policy_denied")
            message = out["mcp"]["transformedGatewayResponse"]["body"]["error"]["message"]
            self.assertEqual(message, "Blocked by your organization's security policy.")
            self.assertNotIn("forbid matched", json.dumps(out))          # reason stays in the log
            self.assertEqual(h.log(logs)["reason"], "forbid matched")
            self.assertEqual(len(h.store.get_trace(TRACE)["hops"]), 1)   # the denied call is absent
            h.run(tool_event("srv___third"))
            self.assertEqual([x["resource"]["id"] for x in h.body["context"]["hops"]],
                             ["srv/first"])

    def test_monitor_mode_logs_the_denial_and_lets_the_call_through(self):
        with Harness(REVA_MONITOR_MODE="true") as h:
            h.server.queue(403, {"decision": False})
            out, logs = h.run(tool_event())
            self.assertTrue(passed(out))
            self.assertEqual(h.log(logs)["decision"], "monitor_would_deny")
            self.assertEqual(len(h.store.get_trace(TRACE)["hops"]), 1)

    def test_dependency_failure_fails_closed_by_default(self):
        with Harness() as h:
            h.server.default = {"status": 500, "body": {}}
            out, _ = h.run(tool_event())
            self.assertEqual(deny_code(out), "rtg_unavailable")
            self.assertEqual(len(h.server.requests), 2)                  # one retry

    def test_fail_open_passes_on_a_dependency_failure_and_does_not_record_the_hop(self):
        with Harness(REVA_FAIL_OPEN="true") as h:
            h.server.default = {"status": 503, "body": {}}
            out, logs = h.run(tool_event())
            self.assertTrue(passed(out))
            self.assertEqual(h.log(logs)["decision"], "permit_fail_open")
            self.assertEqual(h.store.get_trace(TRACE)["hops"], [])

    def test_fail_open_never_covers_a_policy_deny_or_an_invalid_request(self):
        with Harness(REVA_FAIL_OPEN="true") as h:
            h.server.queue(403, {"decision": False})
            self.assertEqual(deny_code(h.run(tool_event())[0]), "policy_denied")
            h.server.queue(400, {"context": {"reason": "invalid session"}})
            self.assertEqual(deny_code(h.run(tool_event("srv___other"))[0]), "rtg_rejected")

    def test_conditional_allow_is_denied_unless_configured(self):
        body = {"guardrails": {"outcome": "conditional_allow", "reason": "review"}}
        with Harness() as h:
            h.server.queue(200, body)
            self.assertEqual(deny_code(h.run(tool_event())[0]), "policy_denied")
        with Harness(REVA_CONDITIONAL_ALLOW="allow") as h:
            h.server.queue(200, body)
            self.assertTrue(passed(h.run(tool_event())[0]))

    def test_a_denied_first_call_still_leaves_the_identity_for_parallel_hops(self):
        with Harness() as h:
            h.server.queue(403, {"decision": False})
            h.run(tool_event("srv___first"))
            record = h.store.get_trace(TRACE)
            self.assertEqual((record["principal"], record["hops"]), ("u1", []))
            h.run(mcp_event("srv___second", {"q": 2}, headers={"traceparent": traceparent()}))
            self.assertEqual(h.body["principal"]["id"], "u1")

    def test_custom_deny_message_and_status(self):
        with Harness(REVA_DENY_MESSAGE="No.", REVA_DENY_STATUS="451") as h:
            h.server.queue(403, {"decision": False})
            block = h.run(tool_event())[0]["mcp"]["transformedGatewayResponse"]
            self.assertEqual(block["statusCode"], 451)
            self.assertEqual(block["body"]["error"]["message"], "No.")
            self.assertEqual(block["body"]["jsonrpc"], "2.0")
            self.assertEqual(block["body"]["id"], 1)


class AgentSubject(unittest.TestCase):
    def test_default_without_an_agent_id_the_user_is_the_subject(self):
        with Harness() as h:
            _, logs = h.run(tool_event())
            self.assertEqual(h.body["subject"], {"type": "User", "id": "u1"})
            self.assertEqual(h.log(logs)["subjectSource"], "user_fallback")

    def test_the_agent_header_makes_the_agent_the_subject_and_is_remembered_in_the_hop(self):
        with Harness() as h:
            h.run(tool_event("srv___first", **{"x-reva-agent-id": "agent-a"}))
            self.assertEqual(h.body["subject"], {"type": "Agent", "id": "agent-a"})
            self.assertEqual(h.body["principal"], {"type": "User", "id": "u1"})
            h.run(tool_event("srv___second", **{"x-reva-agent-id": "agent-b"}))
            self.assertEqual(h.body["context"]["hops"][0]["subject"],
                             {"type": "Agent", "id": "agent-a"})

    def test_a_token_claim_beats_the_header(self):
        with Harness() as h:
            token = bearer({"sub": "u1", "act": {"sub": "from-token"}})
            event = mcp_event("srv___t", {"q": 1}, headers=headers(
                authorization=False, Authorization=token, **{"x-reva-agent-id": "from-header"}))
            h.run(event)
            self.assertEqual(h.body["subject"]["id"], "from-token")

    def test_switching_authorize_agent_off_ignores_any_agent_id(self):
        with Harness(REVA_AUTHORIZE_AGENT="false") as h:
            h.run(tool_event(**{"x-reva-agent-id": "agent-a"}))
            self.assertEqual(h.body["subject"], {"type": "User", "id": "u1"})

    def test_configured_header_and_id_map(self):
        with Harness(REVA_AGENT_HEADER="X-Caller-Agent",
                     REVA_AGENT_ID_MAP='{"orchestrator": "acme-orchestrator"}') as h:
            h.run(tool_event(**{"x-caller-agent": "orchestrator"}))
            self.assertEqual(h.body["subject"]["id"], "acme-orchestrator")


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
                             event["http"]["gatewayRequest"]["body"])   # the caller's own bytes
            body = h.body
            self.assertEqual(body["action"], {"name": "invokeAgent"})
            self.assertEqual(body["resource"]["type"], "Agent")
            self.assertEqual(body["resource"]["id"], "agent-a")
            self.assertEqual(body["subject"], {"type": "User", "id": "u1"})
            self.assertEqual(body["transmission"]["role"], "user")
            self.assertEqual(body["transmission"]["userQuery"], "Which projects are at risk?")
            self.assertEqual(body["session"]["id"], "ctx-7")             # the A2A contextId

    def test_a2a_metadata_reaches_the_context_only_through_the_map(self):
        with Harness(REVA_CONTEXT_MAP='{"countries": "Org_req_countries", "years": "Org_req_years"}'
                     ) as h:
            event = http_event("/agent-a/invocations", a2a_payload(), headers=headers())
            payload = json.loads(base64.b64decode(event["http"]["gatewayRequest"]["body"]))
            payload["params"]["message"]["metadata"] = {
                "countries": ["ES", "PT"], "years": [], "traceNote": "stays here"}
            event = http_event("/agent-a/invocations", payload, headers=headers())
            h.run(event)
            context = h.body["context"]
            self.assertEqual(context["Org_req_countries"], ["ES", "PT"])
            self.assertNotIn("Org_req_years", context)          # an empty set is dropped
            self.assertNotIn("traceNote", json.dumps(h.body))   # unmapped keys never leave

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

    def test_agent_to_agent_hop_after_the_entry_call_sees_the_entry_in_its_history(self):
        with Harness() as h:
            h.run(http_event("/orchestrator/invocations", a2a_payload("question"),
                             headers=headers()))
            h.run(http_event("/analytics/invocations", a2a_payload("sub question"),
                             headers={"traceparent": traceparent(),
                                      "x-reva-agent-id": "orchestrator"}))
            body = h.body
            self.assertEqual(body["subject"], {"type": "Agent", "id": "orchestrator"})
            self.assertEqual(body["transmission"]["role"], "assistant")
            hop = body["context"]["hops"][0]
            self.assertEqual((hop["subject"], hop["action"], hop["resource"]["id"]),
                             ({"type": "User", "id": "u1"}, "invokeAgent", "orchestrator"))
            self.assertEqual(body["context"]["conversation"]["messages"][0]["content"], "question")
            self.assertEqual(body["context"]["conversation"]["messages"][0]["role"], "user")


class PassThroughAndLocalDenies(unittest.TestCase):
    def test_traffic_that_is_not_a_call_passes_without_asking(self):
        with Harness() as h:
            for event in (mcp_event(method="tools/list"), mcp_event(method="initialize"),
                          mcp_event(http_method="GET", body=None),
                          http_event("/health", {"x": 1}),
                          http_event("/inference/v1/chat/completions",
                                     {"model": "m", "messages": []})):
                self.assertTrue(passed(h.run(event)[0]), event)
            self.assertEqual(h.server.requests, [])

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
            h.cfg = settings(REVA_AUTH_MODE="nonsense")      # config error
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


class TraceAndHistoryModes(unittest.TestCase):
    def test_no_traceparent_mints_a_trace_with_no_history(self):
        with Harness() as h:
            event = mcp_event("srv___t", {"q": 1}, headers={"Authorization": bearer(),
                                                            "Mcp-Session-Id": "chat-1"})
            out, logs = h.run(event)
            self.assertTrue(passed(out))
            self.assertEqual(h.log(logs)["traceSource"], "minted")
            self.assertEqual(h.store.traces, {})                  # nothing written
            self.assertTrue(h.server.header("traceparent"))

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

    def test_rtg_history_mode_sends_no_history_touches_no_table_and_needs_the_jwt_every_hop(self):
        with Harness(REVA_HISTORY="rtg", REVA_HISTORY_TABLE="") as h:
            self.assertEqual(h.cfg.errors, ())
            h.run(tool_event("srv___first"))
            self.assertNotIn("session", h.body)
            self.assertNotIn("context", h.body)
            self.assertEqual(h.server.header("X-Reva-Thread-Id"), "chat-1")
            self.assertEqual(h.store.traces, {})
            later = mcp_event("srv___second", {}, headers={"traceparent": traceparent()})
            self.assertEqual(deny_code(h.run(later)[0]), "missing_authorization")

    def test_an_unreadable_table_fails_closed_or_open(self):
        with Harness() as h:
            broken = mock.Mock(side_effect=StoreError("throttled"))
            h.store.get_trace = broken
            out, logs = h.run(tool_event())
            self.assertEqual(deny_code(out), "history_unavailable")
            self.assertEqual(h.server.requests, [])
        with Harness(REVA_FAIL_OPEN="true") as h:
            h.store.get_trace = mock.Mock(side_effect=StoreError("throttled"))
            out, _ = h.run(tool_event())
            self.assertTrue(passed(out))
            self.assertEqual(h.body["principal"]["id"], "u1")     # from the JWT, no history

    def test_a_failed_hop_write_does_not_fail_a_call_that_passed_policy(self):
        with Harness() as h:
            h.store.append_hop = mock.Mock(side_effect=StoreError("AccessDenied"))
            out, logs = h.run(tool_event())
            self.assertTrue(passed(out))
            self.assertEqual(h.log(logs, "error")["code"], "hop_write_failed")


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
            self.assertIn("authorization", shape["headers"])      # the NAME, never the value


class RtgCredential(unittest.TestCase):
    """The RTG token comes from Secrets Manager, and only when a call is actually evaluated."""

    def test_the_token_comes_from_the_secret(self):
        with Harness() as h:
            h.cfg = dataclasses.replace(h.cfg, token="")
            with mock.patch("interceptor.secret.get_token", return_value="from-the-secret"):
                out, _ = h.run(tool_event())
            self.assertTrue(passed(out))
            self.assertEqual(h.server.header("X-API-Token"), "from-the-secret")

    def test_an_unreadable_secret_denies_before_the_rtg_or_the_table_are_touched(self):
        for env in ({}, {"REVA_FAIL_OPEN": "true"}):          # a missing credential never fails open
            with self.subTest(env=env), Harness(**env) as h:
                h.cfg = dataclasses.replace(h.cfg, token="")
                failure = SecretError("cannot read secret 'reva/secrets': AccessDenied")
                with mock.patch("interceptor.secret.get_token", side_effect=failure):
                    out, logs = h.run(tool_event())
                self.assertEqual(deny_code(out), "token_unavailable")
                self.assertEqual(h.server.requests, [])
                self.assertEqual(h.store.traces, {})
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
        with mock.patch.dict("os.environ", {"REVA_HISTORY_TABLE": "x"}):
            first = self.handler._settings()
            self.assertIs(first, self.handler._settings())


if __name__ == "__main__":
    unittest.main()
