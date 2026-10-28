import base64
import json
import unittest

from interceptor.classify import Call, Reject, Skip, classify
from interceptor.event import EventError, parse_event

from .support import a2a_payload, http_event, mcp_event, settings


class Ctx:
    class client_context:  # noqa: N801
        custom = {"REQUEST_ID": "req-123"}


class ParseEvent(unittest.TestCase):
    def test_mcp_request(self):
        env = parse_event(mcp_event(headers={"Authorization": "Bearer x", "TraceParent": "t"}))
        self.assertEqual((env.transport, env.leg, env.http_method, env.path),
                         ("mcp", "request", "POST", "/mcp"))
        self.assertEqual(env.headers, {"authorization": "Bearer x", "traceparent": "t"})
        self.assertEqual(env.body["method"], "tools/call")

    def test_mcp_response_leg_is_detected_even_though_the_request_is_echoed(self):
        env = parse_event(mcp_event(response={"statusCode": 200, "body": {}}))
        self.assertEqual(env.leg, "response")
        self.assertEqual(env.response["statusCode"], 200)

    def test_http_body_is_decoded_and_the_raw_base64_is_kept(self):
        event = http_event(payload={"prompt": "hi"})
        env = parse_event(event)
        self.assertEqual((env.transport, env.leg), ("http", "request"))
        self.assertEqual(env.body, {"prompt": "hi"})
        self.assertEqual(env.raw_body, event["http"]["gatewayRequest"]["body"])

    def test_http_malformed_or_non_json_body_never_raises(self):
        env = parse_event(http_event(raw=b"plain text, not json"))
        self.assertIsNone(env.body)
        self.assertEqual(env.body_bytes, b"plain text, not json")
        event = http_event(payload={})
        event["http"]["gatewayRequest"]["body"] = "!!! not base64 !!!"
        self.assertEqual(parse_event(event).body_bytes, b"")

    def test_http_response_leg_has_no_request(self):
        event = {"http": {"gatewayRequest": None,
                          "gatewayResponse": {"statusCode": 200, "body": "e30="}}}
        env = parse_event(event)
        self.assertEqual(env.leg, "response")
        self.assertEqual(env.headers, {})

    def test_request_id_from_client_context(self):
        self.assertEqual(parse_event(http_event(payload={}), Ctx()).request_id, "req-123")
        self.assertEqual(parse_event(http_event(payload={}), object()).request_id, "")

    def test_not_a_gateway_event(self):
        for bad in (None, [], "x", {}, {"other": 1}):
            with self.assertRaises(EventError):
                parse_event(bad)


class McpClassification(unittest.TestCase):
    def classify(self, event, **env):
        return classify(parse_event(event), settings(**env))

    def test_tool_call(self):
        call = self.classify(mcp_event("acme-tools___query_payroll", {"countries": ["ES"]}))
        self.assertIsInstance(call, Call)
        self.assertEqual((call.kind, call.action), ("tool", "invokeTool"))
        self.assertEqual(call.resource, {"type": "Tool", "id": "acme-tools/query_payroll",
                                         "name": "query_payroll"})
        self.assertEqual(call.prompt, '{"countries":["ES"]}')
        self.assertEqual(call.arguments, {"countries": ["ES"]})

    def test_tool_without_arguments_uses_the_tool_name_as_prompt(self):
        self.assertEqual(self.classify(mcp_event("srv___ping_db")).prompt, "ping_db")

    def test_target_alias_and_exclusion(self):
        targets = '{"acme-tools": {"id": "acme-mcp"}, "public": {"kind": "skip"}}'
        self.assertEqual(self.classify(mcp_event("acme-tools___q"),
                                       REVA_TARGETS=targets).resource["id"], "acme-mcp/q")
        self.assertIsInstance(self.classify(mcp_event("public___q"), REVA_TARGETS=targets), Skip)

    def test_tool_parents_and_endpoint_are_opt_in(self):
        plain = self.classify(mcp_event("srv___t"))
        self.assertNotIn("parents", plain.resource)
        rich = self.classify(mcp_event("srv___t"), REVA_TOOL_PARENTS="true",
                             REVA_TARGETS='{"srv": {"endpoint": "https://mcp.example/x"}}')
        self.assertEqual(rich.resource["parents"], [{"type": "MCPServer", "id": "srv"}])
        self.assertEqual(rich.resource["properties"]["endpoint"],
                         {"url": "https://mcp.example/x", "type": "MCP"})

    def test_builtin_search_tool_is_skipped_unless_asked(self):
        name = "x_amz_bedrock_agentcore_search"
        self.assertIsInstance(self.classify(mcp_event(name)), Skip)
        call = self.classify(mcp_event(name), REVA_EVAL_BUILTIN_TOOLS="true")
        self.assertEqual(call.resource["id"], f"gateway/{name}")

    def test_lifecycle_methods_and_non_post_pass_untouched(self):
        for method in ("initialize", "tools/list", "ping", "notifications/initialized"):
            self.assertIsInstance(self.classify(mcp_event(method=method)), Skip, method)
        self.assertIsInstance(self.classify(mcp_event(http_method="GET", body=None)), Skip)
        self.assertIsInstance(self.classify(mcp_event(http_method="DELETE", body=None)), Skip)

    def test_malformed_bodies_fail_closed(self):
        for body in (None, "text", 7, {"jsonrpc": "2.0"}, {"method": "tools/call"},
                     {"method": "tools/call", "params": {"name": "  "}}):
            result = self.classify(mcp_event(body=body))
            self.assertIsInstance(result, Reject, body)
            self.assertEqual(result.code, "malformed_body")

    def test_batch_with_a_tool_call_is_rejected_batch_without_is_not(self):
        batch = [{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                  "params": {"name": "s___t"}}]
        self.assertEqual(self.classify(mcp_event(body=batch)).code, "batch_unsupported")
        self.assertIsInstance(
            self.classify(mcp_event(body=[{"jsonrpc": "2.0", "id": 1, "method": "ping"}])), Skip)

    def test_unresolvable_tool_name(self):
        self.assertEqual(self.classify(mcp_event("___tool")).code, "unresolvable_resource")
        self.assertEqual(self.classify(mcp_event("target___")).code, "unresolvable_resource")
        call = self.classify(mcp_event("target___"), REVA_UNKNOWN_RESOURCE="unknown")
        self.assertEqual(call.resource["id"], "target/unknown-tool")

    def test_prompt_is_clipped_in_bytes_not_characters(self):
        call = self.classify(mcp_event("s___t", {"q": "é" * 500}), REVA_PROMPT_MAX_BYTES="100")
        self.assertLessEqual(len(call.prompt.encode("utf-8")), 100)

    def test_span_key_is_stable_and_distinguishes_calls(self):
        a = self.classify(mcp_event("s___t", {"q": 1}, rpc_id=1)).span_key
        self.assertEqual(a, self.classify(mcp_event("s___t", {"q": 1}, rpc_id=1)).span_key)
        self.assertNotEqual(a, self.classify(mcp_event("s___t", {"q": 1}, rpc_id=2)).span_key)
        self.assertNotEqual(a, self.classify(mcp_event("s___t", {"q": 2}, rpc_id=1)).span_key)


class HttpClassification(unittest.TestCase):
    def classify(self, event, **env):
        return classify(parse_event(event), settings(**env))

    def test_a2a_message_send(self):
        call = self.classify(http_event("/acme-analytics/invocations",
                                        a2a_payload("Which projects?", context_id="chat-9")))
        self.assertEqual((call.kind, call.action), ("agent", "invokeAgent"))
        self.assertEqual(call.resource, {"type": "Agent", "id": "acme-analytics",
                                         "name": "acme-analytics"})
        self.assertEqual(call.prompt, "Which projects?")
        self.assertEqual(call.thread_hint, "chat-9")

    def test_a2a_text_parts_are_joined_and_blank_message_falls_back(self):
        payload = a2a_payload()
        payload["params"]["message"]["parts"] = [{"text": " one "}, {"data": {}}, {"text": "two"}]
        self.assertEqual(self.classify(http_event("/a/invocations", payload)).prompt,
                         "one\ntwo")
        payload["params"]["message"]["parts"] = []
        self.assertEqual(self.classify(http_event("/a/invocations", payload)).prompt,
                         "invokeAgent a")

    def test_a2a_is_recognised_on_any_path_and_other_methods_pass(self):
        self.assertEqual(self.classify(http_event("/agent-b/", a2a_payload())).resource["id"],
                         "agent-b")
        other = a2a_payload()
        other["method"] = "tasks/get"
        self.assertIsInstance(self.classify(http_event("/agent-b/invocations", other)), Skip)

    def test_a2a_metadata_is_the_calls_arguments(self):
        payload = a2a_payload()
        payload["metadata"] = {"countries": ["XX"], "from_request": 1}
        payload["params"]["metadata"] = {"countries": ["YY"], "from_params": 2}
        payload["params"]["message"]["metadata"] = {"countries": ["ES", "PT"], "clients": ["ACME"]}
        call = self.classify(http_event("/acme-analytics/invocations", payload))
        # all three holders are read; the most specific one wins a repeated key
        self.assertEqual(call.arguments, {"countries": ["ES", "PT"], "clients": ["ACME"],
                                          "from_request": 1, "from_params": 2})

    def test_a2a_without_usable_metadata_has_no_arguments(self):
        self.assertEqual(self.classify(http_event("/a/invocations", a2a_payload())).arguments, {})
        payload = a2a_payload()
        payload["params"]["message"]["metadata"] = "not an object"
        payload["params"]["metadata"] = ["nor", "this"]
        self.assertEqual(self.classify(http_event("/a/invocations", payload)).arguments, {})

    def test_a_plain_runtime_call_has_no_arguments(self):
        call = self.classify(http_event("/x/invocations", {"prompt": "hi", "metadata": {"a": 1}}))
        self.assertEqual(call.arguments, {})

    def test_plain_runtime_call(self):
        call = self.classify(http_event("/my-agent/invocations", {"prompt": "hi there"}))
        self.assertEqual((call.action, call.resource["id"], call.prompt),
                         ("invokeAgent", "my-agent", "hi there"))

    def test_plain_runtime_prompt_fallbacks(self):
        self.assertEqual(self.classify(http_event("/x/invocations", {"unknown": 1})).prompt,
                         '{"unknown":1}')
        self.assertEqual(self.classify(http_event("/x/invocations", raw=b" free text ")).prompt,
                         "free text")
        self.assertEqual(self.classify(http_event("/x/invocations", raw=b"")).prompt,
                         "invokeAgent x")

    def test_runtime_target_alias_exclusion_and_endpoint(self):
        targets = ('{"my-agent": {"id": "agent-entity", "endpoint": "https://rt.example/a"},'
                   ' "internal": {"kind": "skip"}}')
        call = self.classify(http_event("/my-agent/invocations", {"prompt": "x"}),
                             REVA_TARGETS=targets)
        self.assertEqual(call.resource["id"], "agent-entity")
        self.assertEqual(call.resource["properties"]["endpoint"],
                         {"url": "https://rt.example/a", "type": "Agent"})
        self.assertIsInstance(
            self.classify(http_event("/internal/invocations", {"prompt": "x"}),
                          REVA_TARGETS=targets), Skip)

    def test_inference_and_unknown_http_are_unclassified(self):
        chat = http_event("/inference/v1/chat/completions",
                          {"model": "m", "messages": [{"role": "user", "content": "hi"}]})
        invoke = http_event("/model/anthropic.x/invoke", {"messages": []})
        shaped = http_event("/v1/anything", {"model": "m", "input": "hi"})
        other = http_event("/health", {"x": 1})
        for event in (chat, invoke, shaped, other):
            self.assertIsInstance(self.classify(event), Skip)
            denied = self.classify(event, REVA_UNCLASSIFIED="deny")
            self.assertEqual(denied.code, "unclassified_traffic")

    def test_a_runtime_path_wins_over_an_inference_looking_body(self):
        call = self.classify(http_event("/my-agent/invocations",
                                        {"model": "m", "prompt": "hello"}))
        self.assertEqual(call.resource["id"], "my-agent")

    def test_no_target_in_the_path(self):
        result = self.classify(http_event("/", a2a_payload()))
        self.assertEqual(result.code, "unresolvable_resource")

    def test_span_key_prefers_the_gateway_request_id(self):
        event = http_event("/a/invocations", {"prompt": "x"})
        env = parse_event(event, Ctx())
        self.assertEqual(classify(env, settings()).span_key, "req-123")
        no_id = classify(parse_event(event), settings()).span_key
        self.assertIn("/a/invocations", no_id)


if __name__ == "__main__":
    unittest.main()
