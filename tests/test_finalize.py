import base64
import json
import unittest

from interceptor.finalize import assistant_text, from_envelope
from interceptor.event import parse_event


def _http_response(payload: dict, status: int = 200,
                   request_headers=None) -> dict:
    body = base64.b64encode(json.dumps(payload).encode()).decode()
    request = None
    if request_headers is not None:
        request = {"path": "/agent/invocations", "httpMethod": "POST",
                   "headers": request_headers, "body": ""}
    return {"interceptorInputVersion": "1.0",
            "http": {"gatewayRequest": request,
                     "gatewayResponse": {"statusCode": status, "body": body}}}


def _mcp_response(request_headers: dict, response_body: dict) -> dict:
    return {"interceptorInputVersion": "1.0", "mcp": {
        "gatewayRequest": {"path": "/mcp", "httpMethod": "POST",
                           "headers": request_headers,
                           "body": {"jsonrpc": "2.0", "id": 1, "method": "tools/call"}},
        "gatewayResponse": {"statusCode": 200, "body": response_body},
    }}


class FinalizeHint(unittest.TestCase):
    def test_http_reva_block_entry(self):
        env = parse_event(_http_response({
            "message": "done",
            "_reva": {"trace": "a" * 32, "thread": "t1", "summarize": True},
        }, request_headers={"X-Reva-Session-Id": "t1",
                            "traceparent": f"00-{'a' * 32}-{'b' * 16}-01"}))
        hint = from_envelope(env)
        self.assertTrue(hint.should_summarize)
        self.assertEqual(hint.trace_id, "a" * 32)
        self.assertEqual(hint.thread_id, "t1")
        self.assertEqual(hint.output, "done")

    def test_http_session_header_wins_over_agent_false(self):
        """Runtime often lacks Session-Id (allowlist) and sets summarize:false;
        interceptor still sees the UI header on RESPONSE and must summarize."""
        env = parse_event(_http_response({
            "message": "done",
            "_reva": {"trace": "a" * 32, "thread": "minted-local",
                      "summarize": False},
        }, request_headers={
            "X-Reva-Session-Id": "ui-thread",
            "traceparent": f"00-{'a' * 32}-{'b' * 16}-01",
            "X-Transaction-Token": "injected.by.interceptor",
        }))
        hint = from_envelope(env)
        self.assertTrue(hint.should_summarize)
        self.assertEqual(hint.thread_id, "ui-thread")

    def test_http_nested_skips(self):
        env = parse_event(_http_response({
            "message": "nested",
            "_reva": {"trace": "b" * 32, "thread": "t2", "summarize": False},
        }, request_headers={
            "traceparent": f"00-{'b' * 32}-{'c' * 16}-01",
            "X-Transaction-Token": "txn",
        }))
        self.assertFalse(from_envelope(env).should_summarize)

    def test_http_no_reva_without_session_skips(self):
        env = parse_event(_http_response(
            {"message": "nested"},
            request_headers={"traceparent": f"00-{'b' * 32}-{'c' * 16}-01"}))
        self.assertFalse(from_envelope(env).should_summarize)

    def test_mcp_headers_entry(self):
        tp = f"00-{'c' * 32}-{'d' * 16}-01"
        env = parse_event(_mcp_response(
            {"traceparent": tp, "X-Reva-Thread-Id": "chat-9"},
            {"result": {"content": [{"type": "text", "text": "tool ok"}]}}))
        hint = from_envelope(env)
        self.assertTrue(hint.should_summarize)
        self.assertEqual(hint.trace_id, "c" * 32)
        self.assertEqual(hint.thread_id, "chat-9")
        self.assertEqual(hint.output, "tool ok")

    def test_mcp_without_session_skips(self):
        """Nested MCP RESPONSE: no session/thread key → not end of UI turn."""
        tp = f"00-{'e' * 32}-{'f' * 16}-01"
        env = parse_event(_mcp_response(
            {"traceparent": tp, "X-Transaction-Token": "txn.jwt"},
            {"result": {"content": [{"type": "text", "text": "x"}]}}))
        self.assertFalse(from_envelope(env).should_summarize)

    def test_mcp_session_id_alone_does_not_mark_the_entry_hop(self):
        """The agents send Mcp-Session-Id on their nested tool calls too: that hop's RESPONSE
        must not be summarised with the tool result as the turn's answer."""
        tp = f"00-{'a' * 32}-{'b' * 16}-01"
        env = parse_event(_mcp_response(
            {"traceparent": tp, "Mcp-Session-Id": "chat-9"},
            {"result": {"content": [{"type": "text", "text": "tool ok"}]}}))
        self.assertFalse(from_envelope(env).should_summarize)

    def test_session_not_txn_decides_summarize(self):
        """Txn may be present on the entry RESPONSE; session key still means summarize."""
        tp = f"00-{'a' * 32}-{'b' * 16}-01"
        env = parse_event(_mcp_response(
            {"traceparent": tp, "X-Reva-Session-Id": "ui-chat",
             "X-Transaction-Token": "minted.txn"},
            {"result": {"content": [{"type": "text", "text": "done"}]}}))
        hint = from_envelope(env)
        self.assertTrue(hint.should_summarize)
        self.assertEqual(hint.thread_id, "ui-chat")


class AssistantText(unittest.TestCase):
    """The answer posted to /trace/summarize, from each response shape (the Kong plugin's cases)."""

    def text(self, payload):
        return assistant_text(json.dumps(payload))

    def test_openai_chat_completions(self):
        self.assertEqual(self.text({"choices": [{"message": {
            "role": "assistant", "content": "Lab results: WBC normal."}}]}),
            "Lab results: WBC normal.")

    def test_openai_content_as_parts_and_the_legacy_text_field(self):
        self.assertEqual(self.text({"choices": [{"message": {"content": [
            {"type": "text", "text": "one"}, {"type": "text", "text": "two"}]}}]}), "one\ntwo")
        self.assertEqual(self.text({"choices": [{"text": "legacy"}]}), "legacy")

    def test_a2a_jsonrpc_message(self):
        self.assertEqual(self.text({"jsonrpc": "2.0", "id": 1, "result": {
            "role": "agent", "parts": [{"kind": "text", "text": "Patient labs look normal."}]}}),
            "Patient labs look normal.")

    def test_a2a_jsonrpc_task_status_message_then_artifacts(self):
        self.assertEqual(self.text({"jsonrpc": "2.0", "id": 1, "result": {
            "id": "task-1", "status": {"state": "completed", "message": {
                "role": "agent", "parts": [{"text": "Hemoglobin 13.2 g/dL."}]}},
            "artifacts": [{"parts": [{"text": "not this"}]}]}}), "Hemoglobin 13.2 g/dL.")
        self.assertEqual(self.text({"jsonrpc": "2.0", "id": 1, "result": {
            "id": "task-1", "artifacts": [{"parts": [{"text": "first"}]},
                                          {"parts": [{"text": "second"}]}]}}),
            "first\nsecond")

    def test_a2a_rest_message_and_task_are_the_body_itself(self):
        self.assertEqual(self.text({"role": "agent", "parts": [
            {"text": "REST answer: creatinine is 0.9."}]}), "REST answer: creatinine is 0.9.")
        self.assertEqual(self.text({"id": "task-2", "artifacts": [
            {"parts": [{"text": "Artifact: all labs within range."}]}]}),
            "Artifact: all labs within range.")

    def test_a_data_part_is_reported_as_json(self):
        self.assertEqual(self.text({"parts": [{"text": "total"}, {"data": {"n": 3}}]}),
                         'total\n{"n":3}')

    def test_mcp_tool_result_text_parts(self):
        self.assertEqual(self.text({"jsonrpc": "2.0", "id": 1, "result": {"content": [
            {"type": "text", "text": "a"}, {"type": "text", "text": "b"}]}}), "a\nb")

    def test_a_jsonrpc_result_with_no_text_is_reported_as_json_and_an_error_by_message(self):
        self.assertEqual(self.text({"jsonrpc": "2.0", "id": 1, "result": {"count": 2}}),
                         '{"count":2}')
        self.assertEqual(self.text({"jsonrpc": "2.0", "id": 1,
                                    "error": {"code": -32000, "message": "boom"}}),
                         "error: boom")

    def test_plain_runtime_agent_fields_including_one_level_down(self):
        self.assertEqual(self.text({"reply": "hi there"}), "hi there")
        self.assertEqual(self.text({"output": {"message": "nested"}}), "nested")
        self.assertEqual(self.text({"output": {"parts": [{"text": "from parts"}]}}),
                         "from parts")

    def test_a_body_that_is_not_json_is_reported_as_it_is(self):
        self.assertEqual(assistant_text("Plain agent reply without JSON."),
                         "Plain agent reply without JSON.")

    def test_an_unrecognised_json_body_is_kept_so_the_turn_still_has_an_answer(self):
        self.assertEqual(self.text({"rows": [1, 2]}), '{"rows": [1, 2]}')
        self.assertEqual(assistant_text("[1, 2]"), "[1, 2]")

    def test_no_body_has_no_answer(self):
        self.assertEqual(assistant_text(""), "")
        self.assertEqual(assistant_text("   "), "")

    def test_an_http_response_that_is_not_json_still_carries_its_text(self):
        body = base64.b64encode(b"Plain agent reply without JSON.").decode()
        env = parse_event({"interceptorInputVersion": "1.0", "http": {
            "gatewayRequest": {"path": "/a/invocations", "httpMethod": "POST", "body": "",
                               "headers": {"X-Reva-Session-Id": "t1",
                                           "traceparent": f"00-{'a' * 32}-{'b' * 16}-01"}},
            "gatewayResponse": {"statusCode": 200, "body": body}}})
        hint = from_envelope(env)
        self.assertTrue(hint.should_summarize)
        self.assertEqual(hint.output, "Plain agent reply without JSON.")

    def test_an_a2a_task_response_reaches_the_summarize_hint(self):
        env = parse_event(_http_response(
            {"jsonrpc": "2.0", "id": 1, "result": {"status": {"message": {
                "parts": [{"text": "All labs in range."}]}}}},
            request_headers={"X-Reva-Session-Id": "t1",
                             "traceparent": f"00-{'a' * 32}-{'b' * 16}-01"}))
        self.assertEqual(from_envelope(env).output, "All labs in range.")


if __name__ == "__main__":
    unittest.main()
