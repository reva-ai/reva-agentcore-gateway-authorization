"""Context variables: name/value pairs from the request body, as the Kong plugin 2.1.0 sends them.

The cases follow the plugin's own offline tests, so a request has the same context here as it
has there.
"""

import json
import unittest

from interceptor.classify import Reject, classify
from interceptor.context import build_context
from interceptor.event import parse_event

from .support import http_event, mcp_event, settings


def context_of(event, **env):
    call = classify(parse_event(event), settings(**env))
    assert not isinstance(call, (Reject,)) and hasattr(call, "context_sources"), call
    return build_context(call.context_sources)[0]


def a2a_event(params, path="/agent-a/invocations"):
    return http_event(path, {"jsonrpc": "2.0", "id": "1", "method": "message/send",
                             "params": params})


def tool_event(params):
    return mcp_event(body={"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params})


def llm_event(body):
    return http_event("/llm/x", body)


class A2a(unittest.TestCase):
    def test_request_message_and_part_metadata_all_become_context(self):
        event = a2a_event({
            "message": {
                "kind": "message", "messageId": "msg-001", "contextId": "ctx-session-123",
                "taskId": "task-abc-789", "role": "user",
                "parts": [{"kind": "text", "text": "Generate the Q3 financial summary report.",
                           "metadata": {"sourceLanguage": "en-US", "priority": "high"}}],
                "metadata": {"clientTimestamp": "2026-11-18T12:30:00Z",
                             "originatingAgent": "orchestrator-v2"}},
            "configuration": {"acceptedOutputModes": ["text/plain"], "historyLength": 5},
            "metadata": {"session_id": "my-session-123", "trace_id": "otel-trace-456",
                         "tenant_id": "org-789"}})
        self.assertEqual(context_of(event), {
            "clientTimestamp": "2026-11-18T12:30:00Z", "originatingAgent": "orchestrator-v2",
            "priority": "high", "sourceLanguage": "en-US", "session_id": "my-session-123",
            "trace_id": "otel-trace-456", "tenant_id": "org-789"})

    def test_only_metadata_is_read(self):
        context = context_of(a2a_event({
            "message": {"contextId": "c", "taskId": "t", "parts": [{"text": "hi"}]},
            "configuration": {"historyLength": 5}}))
        self.assertEqual(context, {})

    def test_a_more_specific_source_wins_and_the_rules_apply(self):
        context = context_of(a2a_event({
            "metadata": {"channel": "web", "riskLevel": "medium"},
            "message": {
                "parts": [{"text": "refund", "metadata": {"priority": "high"}},
                          {"text": "again", "metadata": {"priority": "low"}}],
                "metadata": {
                    "riskLevel": "high", "department": "finance", "amount": 250,
                    "approved": False, "tags": ["refund", "vip"],
                    "customer": {"tier": "gold", "region": "EU"}, "version": "1.2.3",
                    "discount": 0.15, "note": None, "apiKey": "abc123", "x-api-key": "abc",
                    "subject": "s", "history": "h", "on_behalf_of": "u",
                    "jwtish": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2ln",
                    "bearer": "Bearer abc", "dotted": "10.20.30", "big": 123456789012345,
                    "emptyObject": {}, "emptyList": [], "mixed": [1, "a"],
                    "objects": [{"a": 1}], "nested": {"password": "p", "ok": "fine"}}}}))
        self.assertEqual(context, {
            "channel": "web", "riskLevel": "high", "department": "finance", "amount": 250,
            "approved": False, "tags": ["refund", "vip"], "customer.tier": "gold",
            "customer.region": "EU", "priority": "low", "version": "1.2.3",
            "nested.ok": "fine"})

    def test_the_rest_binding_reads_the_same_three_levels(self):
        event = http_event("/a2a/v1/message:send", {
            "metadata": {"r": 3},
            "message": {"parts": [{"text": "hi", "metadata": {"p": 1}}], "metadata": {"m": 2}}})
        self.assertEqual(context_of(event), {"r": 3, "m": 2, "p": 1})


class Mcp(unittest.TestCase):
    def test_arguments_and_meta_are_sent_under_their_own_names(self):
        context = context_of(tool_event({
            "name": "t___open_ticket",
            "arguments": {"title": "VPN down", "priority": "high", "assignee": "bob",
                          "estimate_hours": 4, "filter": {"status": "open"},
                          "progressToken": "from-arguments"},
            "_meta": {"progressToken": "p-1", "trace": "t-9"},
            "task": {"ttl": 60000}}))
        self.assertEqual(context, {
            "title": "VPN down", "priority": "high", "assignee": "bob", "estimate_hours": 4,
            "filter.status": "open", "progressToken": "from-arguments", "trace": "t-9",
            "task.ttl": 60000})            # the arguments win a clash; no tool name, no prefix

    def test_meta_progress_token_is_sent_as_progress_token(self):
        self.assertEqual(
            context_of(tool_event({"name": "t___t", "_meta": {"progressToken": "p-1"}})),
            {"progressToken": "p-1"})


class Model(unittest.TestCase):
    def test_metadata_and_the_call_settings_are_sent(self):
        context = context_of(llm_event({
            "model": "gpt-4o",
            "messages": [{"role": "system", "content": "be brief"},
                         {"role": "user", "content": "Summarise ticket 8841"}],
            "temperature": 0.2, "max_tokens": 500, "stream": False, "user": "alice",
            "tool_choice": "auto", "stop": ["END"], "response_format": {"type": "json_object"},
            "metadata": {"department": "finance", "env": "prod"},
            "tools": [{"type": "function", "function": {"name": "lookup_ticket"}}]}))
        self.assertEqual(context, {
            "department": "finance", "env": "prod", "max_tokens": 500, "stream": False,
            "user": "alice", "tool_choice": "auto", "stop": ["END"],
            "response_format.type": "json_object"})     # no decimals, model, messages or tools

    def test_nothing_but_model_and_messages_sends_no_context(self):
        self.assertEqual(context_of(llm_event({
            "model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]})), {})


class Limits(unittest.TestCase):
    def test_only_the_pairs_that_fit_in_512_bytes_are_kept_first_by_name(self):
        many = {f"k{i:02d}": "v" * 20 for i in range(1, 41)}
        context, left_out = build_context([many])
        self.assertEqual((len(context), max(context)), (17, "k17"))
        self.assertLessEqual(len(json.dumps(context, separators=(",", ":"))), 512)
        self.assertEqual(len(left_out), 21)          # 20 named, then "and 3 more"
        self.assertEqual(left_out[-1], "and 3 more")

    def test_a_pair_that_does_not_fit_is_skipped_and_a_later_smaller_one_kept(self):
        context, _ = build_context([{"a": "x" * 200, "b": "x" * 200, "c": "x" * 200,
                                     "d": "small"}])
        self.assertEqual(sorted(context), ["a", "b", "d"])

    def test_escaped_characters_count_as_they_are_written(self):
        context, _ = build_context([{"quotes": '"' * 300, "plain": "x" * 300}])
        self.assertEqual(sorted(context), ["plain"])

    def test_at_most_64_pairs(self):
        small = {f"{chr(97 + i // 26)}{chr(97 + i % 26)}": 1 for i in range(70)}
        context, _ = build_context([small])
        self.assertEqual(len(context), 64)

    def test_a_non_ascii_name_and_value_are_counted_as_utf8_bytes(self):
        context, _ = build_context([{"café": "é" * 250, "ok": "é" * 250}])
        self.assertEqual(sorted(context), ["café"])

    def test_what_was_left_out_is_named_never_quoted(self):
        _, left_out = build_context([{"password": "hunter2", "ok": 1.5, "fine": "yes"}])
        self.assertEqual(sorted(left_out), ["ok (not a whole number)",
                                            "password (name looks like a credential)"])
        self.assertNotIn("hunter2", " ".join(left_out))

    def test_a_pinned_pair_replaces_a_body_pair_and_is_first_in_line(self):
        many = {f"k{i:02d}": "v" * 20 for i in range(1, 41)}
        context, _ = build_context([many, {"Org_x": "from the body"}],
                                   pinned={"Org_x": "pinned", "zzz": "late but pinned"})
        self.assertEqual((context["Org_x"], context["zzz"]), ("pinned", "late but pinned"))
        self.assertEqual(context["k01"], "v" * 20)

    def test_numbers_and_lists(self):
        context, left_out = build_context([{
            "whole": 3.0, "zero": 0, "neg": -7, "inf": float("inf"), "nan": float("nan"),
            "ints": [1, 2], "strs": ["a"], "flags": [True, False], "mixed": ["a", 1],
            "huge": 10 ** 15}])
        self.assertEqual(context, {"whole": 3, "zero": 0, "neg": -7, "ints": [1, 2],
                                   "strs": ["a"], "flags": [True, False]})
        self.assertEqual(len(left_out), 4)

    def test_a_reserved_name_is_left_out_whatever_its_spelling(self):
        context, _ = build_context([{"Thread-Id": "t", "PROMPT_KEY": "p", "Resource": "r",
                                     "threadid2": "fine"}])
        self.assertEqual(context, {"threadid2": "fine"})


if __name__ == "__main__":
    unittest.main()
